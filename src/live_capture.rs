use crate::ethercat_parser::{FrameHeader, RawEthercatFrame};
use crate::ETHERCAT_ETHERTYPE;
use anyhow::{anyhow, Context, Result};
use pcap::{Active, Capture, Device, Error as PcapError, Packet, PacketHeader, Savefile};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct NetworkInterface {
    pub name: String,
    pub description: Option<String>,
    pub addresses: Vec<String>,
    pub is_up: bool,
    pub is_running: bool,
}

pub struct CaptureOptions {
    pub interface_name: String,
    pub promiscuous: bool,
    pub snaplen: usize,
    pub timeout_ms: i32,
    pub buffer_size: usize,
    pub immediate_mode: bool,
}

impl Default for CaptureOptions {
    fn default() -> Self {
        CaptureOptions {
            interface_name: String::new(),
            promiscuous: true,
            snaplen: 65535,
            timeout_ms: 10,
            buffer_size: 16 * 1024 * 1024,
            immediate_mode: true,
        }
    }
}

pub struct LiveCapture {
    cap: Capture<Active>,
    savefile: Option<Savefile>,
    stop_flag: Arc<AtomicBool>,
    pub stats: LiveStats,
}

#[derive(Debug, Default, Clone)]
pub struct LiveStats {
    pub received: u64,
    pub dropped: u64,
    pub if_dropped: u64,
    pub ethercat_frames: u64,
    pub parse_errors: u64,
    pub filtered_count: u64,
}

#[derive(Debug, Clone)]
pub struct CaptureError {
    pub timestamp: u64,
    pub message: String,
}

pub fn list_interfaces() -> Result<Vec<NetworkInterface>> {
    let devices = Device::list()
        .map_err(|e| anyhow!("Failed to enumerate network interfaces: {}", e))?;
    let mut result = Vec::new();
    for dev in devices {
        let addrs: Vec<String> = dev
            .addresses
            .iter()
            .map(|a| format!("{}", a.addr))
            .collect();
        let is_up = dev.flags.contains(pcap::DeviceFlags::UP);
        let is_running = dev.flags.contains(pcap::DeviceFlags::RUNNING);
        result.push(NetworkInterface {
            name: dev.name,
            description: dev.desc,
            addresses: addrs,
            is_up,
            is_running,
        });
    }
    Ok(result)
}

fn build_bpf_filter() -> String {
    format!("ether proto 0x{:04x}", ETHERCAT_ETHERTYPE)
}

fn system_time_to_nanos(ts: &std::time::SystemTime) -> u64 {
    match ts.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() * 1_000_000_000 + d.subsec_nanos() as u64,
        Err(e) => {
            let neg = e.duration();
            (neg.as_secs() * 1_000_000_000 + neg.subsec_nanos() as u64).wrapping_neg()
        }
    }
}

fn packet_header_to_nanos(header: &PacketHeader) -> u64 {
    let ts = header.ts;
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_usec as u64) * 1_000
}

impl LiveCapture {
    pub fn new(opts: &CaptureOptions) -> Result<Self> {
        let device = Device::from(opts.interface_name.as_str());
        let mut cap_builder = Capture::from_device(device.clone())
            .map_err(|e| anyhow!("Cannot open interface '{}': {}", opts.interface_name, e))?
            .promisc(opts.promiscuous)
            .snaplen(opts.snaplen as i32)
            .timeout(opts.timeout_ms)
            .buffer_size(opts.buffer_size as i32)
            .immediate_mode(opts.immediate_mode);
        let cap = cap_builder
            .open()
            .map_err(|e| anyhow!("Failed to activate capture on '{}': {}", opts.interface_name, e))?;
        let mut active = cap;
        let filter = build_bpf_filter();
        active
            .filter(&filter, true)
            .map_err(|e| anyhow!("Failed to set BPF filter '{}': {}", filter, e))?;
        Ok(LiveCapture {
            cap: active,
            savefile: None,
            stop_flag: Arc::new(AtomicBool::new(false)),
            stats: LiveStats::default(),
        })
    }

    pub fn enable_savefile<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let savefile = self
            .cap
            .savefile(path.as_ref())
            .map_err(|e| anyhow!("Cannot create pcap save file {:?}: {}", path.as_ref(), e))?;
        self.savefile = Some(savefile);
        Ok(())
    }

    pub fn set_stop_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stop_flag)
    }

    pub fn should_stop(&self) -> bool {
        self.stop_flag.load(Ordering::Relaxed)
    }

    pub fn next_frame(&mut self) -> Result<Option<RawEthercatFrame>> {
        loop {
            if self.should_stop() {
                return Ok(None);
            }
            match self.cap.next() {
                Ok(packet) => {
                    self.stats.received += 1;
                    if let Some(ref mut sf) = self.savefile {
                        sf.write(&packet);
                    }
                    let timestamp_ns = packet_header_to_nanos(&packet.header);
                    let data: Vec<u8> = packet.data.to_vec();
                    if data.len() < 14 {
                        self.stats.parse_errors += 1;
                        continue;
                    }
                    let ethertype = u16::from_be_bytes([data[12], data[13]]);
                    if ethertype != ETHERCAT_ETHERTYPE {
                        continue;
                    }
                    self.stats.ethercat_frames += 1;
                    let header = match FrameHeader::parse(&data) {
                        Ok(h) => h,
                        Err(e) => {
                            self.stats.parse_errors += 1;
                            continue;
                        }
                    };
                    return Ok(Some(RawEthercatFrame {
                        timestamp_ns,
                        frame_length: packet.header.caplen as usize,
                        data,
                        header,
                    }));
                }
                Err(PcapError::TimeoutExpired) => {
                    continue;
                }
                Err(PcapError::NoMorePackets) => {
                    return Ok(None);
                }
                Err(e) => {
                    self.stats.parse_errors += 1;
                    return Err(anyhow!("Capture error: {}", e));
                }
            }
        }
    }

    pub fn refresh_stats(&mut self) {
        if let Ok(stats) = self.cap.stats() {
            self.stats.received = stats.received as u64;
            self.stats.dropped = stats.dropped as u64;
            self.stats.if_dropped = stats.if_dropped as u64;
        }
    }
}

pub fn register_stop_signal(flag: Arc<AtomicBool>) {
    let _ = signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&flag));
    let _ = signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&flag));
    #[cfg(unix)]
    {
        let _ = signal_hook::flag::register(signal_hook::consts::SIGQUIT, Arc::clone(&flag));
    }
}

pub enum LoopControl {
    Continue,
    Break,
}

pub fn capture_loop<F>(
    mut capture: LiveCapture,
    mut callback: F,
    stats_interval: Duration,
    mut stats_callback: impl FnMut(&LiveStats),
) -> Result<LiveStats>
where
    F: FnMut(RawEthercatFrame) -> Result<LoopControl>,
{
    let stop_flag = capture.set_stop_flag();
    register_stop_signal(Arc::clone(&stop_flag));
    let mut last_stats = SystemTime::now();
    loop {
        if capture.should_stop() {
            break;
        }
        match capture.next_frame()? {
            Some(frame) => {
                match callback(frame)? {
                    LoopControl::Continue => {}
                    LoopControl::Break => {
                        stop_flag.store(true, Ordering::Relaxed);
                        break;
                    }
                }
            }
            None => {
                break;
            }
        }
        if last_stats.elapsed().unwrap_or_default() >= stats_interval {
            capture.refresh_stats();
            stats_callback(&capture.stats);
            last_stats = SystemTime::now();
        }
    }
    capture.refresh_stats();
    Ok(capture.stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bpf_filter_contains_ethercat_ethertype() {
        let filter = build_bpf_filter();
        assert!(filter.contains("0x88a4") || filter.contains("0x88A4"));
        assert!(filter.contains("ether proto"));
    }

    #[test]
    fn test_capture_options_default() {
        let opts = CaptureOptions::default();
        assert_eq!(opts.promiscuous, true);
        assert_eq!(opts.snaplen, 65535);
        assert_eq!(opts.immediate_mode, true);
    }

    #[test]
    fn test_live_stats_default() {
        let s = LiveStats::default();
        assert_eq!(s.received, 0);
        assert_eq!(s.dropped, 0);
        assert_eq!(s.ethercat_frames, 0);
    }

    #[test]
    fn test_packet_header_to_nanos() {
        let header = PacketHeader {
            ts: libc::timeval {
                tv_sec: 1700000000,
                tv_usec: 123456,
            },
            caplen: 64,
            len: 64,
        };
        let ns = packet_header_to_nanos(&header);
        assert_eq!(ns, 1700000000123456000);
    }

    #[test]
    fn test_system_time_to_nanos() {
        let now = SystemTime::now();
        let ns = system_time_to_nanos(&now);
        assert!(ns > 1700000000000000000);
    }

    #[test]
    fn test_should_stop_flag() {
        let mut opts = CaptureOptions::default();
        opts.interface_name = "lo".to_string();
        let flag = Arc::new(AtomicBool::new(false));
        flag.store(true, Ordering::Relaxed);
        let f = Arc::clone(&flag);
        assert_eq!(f.load(Ordering::Relaxed), true);
    }
}
