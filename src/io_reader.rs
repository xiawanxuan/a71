use crate::ethercat_parser::{FrameHeader, RawEthercatFrame};
use anyhow::{Context, Result};
use byteorder::{LittleEndian, ReadBytesExt};
use std::fs::File;
use std::io::{self, Read, Stdin};
use std::path::Path;

const PCAP_MAGIC: u32 = 0xa1b2c3d4;
const PCAP_MAGIC_NS: u32 = 0xa1b23c4d;
const PCAP_MAGIC_REVERSED: u32 = 0xd4c3b2a1;
const PCAP_MAGIC_REVERSED_NS: u32 = 0x4d3cb2a1;
const DLT_EN10MB: u32 = 1;

pub enum InputSource {
    File(String),
    Stdin,
}

pub trait FrameReader: Send {
    fn read_next_frame(&mut self) -> Result<Option<RawEthercatFrame>>;
}

pub struct PcapFileReader {
    file: File,
    is_nano: bool,
    _link_type: u32,
}

impl PcapFileReader {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut file = File::open(path.as_ref())
            .with_context(|| format!("Failed to open pcap file: {:?}", path.as_ref()))?;
        let magic = file.read_u32::<LittleEndian>()?;
        let is_nano = match magic {
            PCAP_MAGIC => false,
            PCAP_MAGIC_NS => true,
            PCAP_MAGIC_REVERSED | PCAP_MAGIC_REVERSED_NS => {
                return Err(anyhow::anyhow!("Big-endian pcap format not supported"));
            }
            _ => return Err(anyhow::anyhow!("Invalid pcap magic number: 0x{:x}", magic)),
        };
        let _major = file.read_u16::<LittleEndian>()?;
        let _minor = file.read_u16::<LittleEndian>()?;
        let _thiszone = file.read_i32::<LittleEndian>()?;
        let _sigfigs = file.read_u32::<LittleEndian>()?;
        let _snaplen = file.read_u32::<LittleEndian>()?;
        let link_type = file.read_u32::<LittleEndian>()?;
        if link_type != DLT_EN10MB {
            return Err(anyhow::anyhow!(
                "Unsupported link type: {}. Expected Ethernet (DLT_EN10MB=1)",
                link_type
            ));
        }
        Ok(PcapFileReader {
            file,
            is_nano,
            _link_type: link_type,
        })
    }
}

impl FrameReader for PcapFileReader {
    fn read_next_frame(&mut self) -> Result<Option<RawEthercatFrame>> {
        loop {
            let ts_sec = match self.file.read_u32::<LittleEndian>() {
                Ok(v) => v,
                Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
                Err(e) => return Err(e.into()),
            };
            let ts_subsec = self.file.read_u32::<LittleEndian>()?;
            let incl_len = self.file.read_u32::<LittleEndian>()?;
            let _orig_len = self.file.read_u32::<LittleEndian>()?;
            let mut data = vec![0u8; incl_len as usize];
            self.file.read_exact(&mut data)?;
            let timestamp_ns = if self.is_nano {
                (ts_sec as u64) * 1_000_000_000 + (ts_subsec as u64)
            } else {
                (ts_sec as u64) * 1_000_000_000 + (ts_subsec as u64) * 1_000
            };
            if data.len() >= 14 {
                let ethertype = u16::from_be_bytes([data[12], data[13]]);
                if ethertype == crate::ETHERCAT_ETHERTYPE {
                    return Ok(Some(RawEthercatFrame {
                        timestamp_ns,
                        frame_length: incl_len as usize,
                        data,
                        header: FrameHeader::parse(&data)?,
                    }));
                }
            }
        }
    }
}

pub struct RawFileReader {
    file: File,
}

impl RawFileReader {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(path.as_ref())
            .with_context(|| format!("Failed to open raw file: {:?}", path.as_ref()))?;
        Ok(RawFileReader { file })
    }
}

impl FrameReader for RawFileReader {
    fn read_next_frame(&mut self) -> Result<Option<RawEthercatFrame>> {
        let mut size_buf = [0u8; 4];
        match self.file.read_exact(&mut size_buf) {
            Ok(()) => {}
            Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        let frame_size = u32::from_le_bytes(size_buf) as usize;
        let mut ts_buf = [0u8; 8];
        self.file.read_exact(&mut ts_buf)?;
        let timestamp_ns = u64::from_le_bytes(ts_buf);
        let mut data = vec![0u8; frame_size];
        self.file.read_exact(&mut data)?;
        let header = FrameHeader::parse(&data)?;
        Ok(Some(RawEthercatFrame {
            timestamp_ns,
            frame_length: frame_size,
            data,
            header,
        }))
    }
}

pub struct StdinReader {
    stdin: Stdin,
    buffer: Vec<u8>,
}

impl StdinReader {
    pub fn new() -> Self {
        StdinReader {
            stdin: io::stdin(),
            buffer: Vec::with_capacity(65536),
        }
    }

    fn fill_buffer(&mut self, need: usize) -> Result<bool> {
        while self.buffer.len() < need {
            let mut tmp = [0u8; 4096];
            match self.stdin.read(&mut tmp) {
                Ok(0) => {
                    if self.buffer.is_empty() {
                        return Ok(false);
                    }
                    return Err(anyhow::anyhow!(
                        "Unexpected EOF: need {} bytes, have {}",
                        need,
                        self.buffer.len()
                    ));
                }
                Ok(n) => {
                    self.buffer.extend_from_slice(&tmp[..n]);
                }
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(true)
    }
}

impl FrameReader for StdinReader {
    fn read_next_frame(&mut self) -> Result<Option<RawEthercatFrame>> {
        if !self.fill_buffer(12)? {
            return Ok(None);
        }
        let size = u32::from_le_bytes([self.buffer[0], self.buffer[1], self.buffer[2], self.buffer[3]]) as usize;
        let total_need = 12 + size;
        if !self.fill_buffer(total_need)? {
            return Ok(None);
        }
        let timestamp_ns = u64::from_le_bytes([
            self.buffer[4], self.buffer[5], self.buffer[6], self.buffer[7],
            self.buffer[8], self.buffer[9], self.buffer[10], self.buffer[11],
        ]);
        let data: Vec<u8> = self.buffer.drain(12..total_need).collect();
        let header = FrameHeader::parse(&data)?;
        Ok(Some(RawEthercatFrame {
            timestamp_ns,
            frame_length: size,
            data,
            header,
        }))
    }
}

pub fn create_reader(source: &InputSource) -> Result<Box<dyn FrameReader>> {
    match source {
        InputSource::File(path) => {
            let ext = Path::new(path)
                .extension()
                .and_then(|s| s.to_str())
                .map(|s| s.to_lowercase());
            match ext.as_deref() {
                Some("pcap") | Some("cap") => Ok(Box::new(PcapFileReader::open(path)?)),
                _ => Ok(Box::new(RawFileReader::open(path)?)),
            }
        }
        InputSource::Stdin => Ok(Box::new(StdinReader::new())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn make_test_raw_frame() -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0x01, 0x01, 0x05, 0x04, 0x00, 0x00]);
        frame.extend_from_slice(&[0x08, 0x06, 0x07, 0x08, 0x09, 0x0a]);
        frame.extend_from_slice(&0x88A4u16.to_be_bytes());
        let mut ec_header = vec![0x00u8; 4];
        ec_header[0] = 0x0e;
        ec_header[1] = 0x00;
        let payload_len: u16 = 16;
        ec_header[2] = (payload_len & 0x07FF) as u8;
        ec_header[3] = ((payload_len >> 3) & 0xFF) as u8 | 0x10;
        let datagram = vec![
            0x0c, 0x01, 0x00, 0x00, 0x01, 0x00, 0x10, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut result = frame;
        result.extend_from_slice(&ec_header);
        result.extend_from_slice(&datagram);
        result
    }

    #[test]
    fn test_raw_file_reader() {
        let frame_data = make_test_raw_frame();
        let mut tmp = NamedTempFile::new().unwrap();
        let mut buf = Vec::new();
        buf.extend_from_slice(&(frame_data.len() as u32).to_le_bytes());
        buf.extend_from_slice(&123456789u64.to_le_bytes());
        buf.extend_from_slice(&frame_data);
        tmp.write_all(&buf).unwrap();
        tmp.flush().unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        let mut reader = RawFileReader::open(&path).unwrap();
        let frame = reader.read_next_frame().unwrap().unwrap();
        assert_eq!(frame.timestamp_ns, 123456789);
        assert_eq!(frame.frame_length, frame_data.len());
        assert!(reader.read_next_frame().unwrap().is_none());
    }
}
