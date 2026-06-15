use crate::*;
use chrono::{DateTime, NaiveDateTime, Utc};
use colored::*;
use std::collections::BTreeMap;
use std::io::{self, Write};

pub struct OutputFormatter {
    pub format: cli::OutputFormat,
    pub no_color: bool,
    pub use_stdout: bool,
    pub output_file: Option<std::fs::File>,
}

impl OutputFormatter {
    pub fn new(
        format: cli::OutputFormat,
        no_color: bool,
        output_file: Option<std::path::PathBuf>,
    ) -> anyhow::Result<Self> {
        Ok(OutputFormatter {
            format,
            no_color,
            use_stdout: output_file.is_none(),
            output_file: match output_file {
                Some(p) => Some(
                    std::fs::File::create(&p)
                        .map_err(|e| anyhow::anyhow!("Cannot create output file {:?}: {}", p, e))?,
                ),
                None => None,
            },
        })
    }

    fn write(&mut self, s: &str) -> anyhow::Result<()> {
        if let Some(ref mut f) = self.output_file {
            f.write_all(s.as_bytes())?;
        } else {
            let mut stdout = io::stdout();
            stdout.write_all(s.as_bytes())?;
            stdout.flush()?;
        }
        Ok(())
    }

    fn writeln(&mut self, s: &str) -> anyhow::Result<()> {
        self.write(s)?;
        self.write("\n")?;
        Ok(())
    }

    fn colorize(&self, text: &str, color: Color) -> String {
        if self.no_color {
            text.to_string()
        } else {
            text.color(color).to_string()
        }
    }

    pub fn print_frame(&mut self, frame: &EthercatFrame, converter: &pdo_converter::PdoConverter) -> anyhow::Result<()> {
        match self.format {
            cli::OutputFormat::Json => self.print_frame_json(frame),
            cli::OutputFormat::Table => self.print_frame_table(frame, converter),
            cli::OutputFormat::Csv => self.print_frame_csv(frame, converter),
            cli::OutputFormat::Pretty => self.print_frame_pretty(frame, converter),
            cli::OutputFormat::Summary => Ok(()),
        }
    }

    pub fn print_summary(&mut self, stats: &ParseStats) -> anyhow::Result<()> {
        match self.format {
            cli::OutputFormat::Json => {
                let json = serde_json::to_string_pretty(stats)?;
                self.writeln(&json)?;
            }
            cli::OutputFormat::Summary | cli::OutputFormat::Pretty => {
                self.print_summary_pretty(stats)?;
            }
            _ => {
                self.print_summary_table(stats)?;
            }
        }
        Ok(())
    }

    fn print_frame_json(&mut self, frame: &EthercatFrame) -> anyhow::Result<()> {
        let json = serde_json::to_string(frame)?;
        self.writeln(&json)?;
        Ok(())
    }

    fn print_frame_table(&mut self, frame: &EthercatFrame, converter: &pdo_converter::PdoConverter) -> anyhow::Result<()> {
        for dg in &frame.datagrams {
            let ts = format_ts(frame.timestamp_ns);
            let slave = format_slave(dg.header.slave_address, converter);
            let cmd = dg.header.command.to_str();
            let reg = format!("0x{:04x}", dg.header.register_offset);
            let len = dg.header.data_length;
            let wc = dg.header.working_counter;
            let state = format_mailbox_state(dg);
            let fault = if dg.is_fault {
                dg.fault_code
                    .map(|c| format!("0x{:04x}", c))
                    .unwrap_or_default()
            } else {
                "".to_string()
            };
            self.writeln(&format!(
                "{:<26} {:<20} {:<6} {:<8} {:<6} {:<4} {:<6} {:<6}",
                ts, slave, cmd, reg, len, wc, state, fault
            ))?;
        }
        Ok(())
    }

    fn print_frame_csv(&mut self, frame: &EthercatFrame, converter: &pdo_converter::PdoConverter) -> anyhow::Result<()> {
        for dg in &frame.datagrams {
            let ts_ns = frame.timestamp_ns;
            let slave_id = dg.header.slave_address;
            let slave_name = converter.get_slave_device_name(slave_id).unwrap_or("");
            let cmd = dg.header.command.to_str();
            let reg = dg.header.register_offset;
            let len = dg.header.data_length;
            let wc = dg.header.working_counter;
            let mbox_type = dg
                .mailbox
                .as_ref()
                .map(|m| m.msg_type.to_str())
                .unwrap_or("");
            let pdo_values = dg
                .pdo
                .as_ref()
                .map(|p| {
                    p.entries
                        .values()
                        .map(|r| {
                            format!(
                                "{}={}",
                                r.name.as_deref().unwrap_or(&format!("0x{:04x}:{}", r.index, r.subindex)),
                                pdo_converter::PdoConverter::format_value(&r.value)
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(";")
                })
                .unwrap_or_default();
            let fault_flag = dg.is_fault;
            let fault_code = dg.fault_code.unwrap_or(0);
            let fault_desc = dg.fault_description.as_deref().unwrap_or("");
            self.writeln(&format!(
                "{},{},{},{},{},{},{},{},{},{},{},{}",
                ts_ns,
                slave_id,
                slave_name,
                cmd,
                reg,
                len,
                wc,
                mbox_type,
                csv_escape(&pdo_values),
                fault_flag,
                fault_code,
                csv_escape(fault_desc)
            ))?;
        }
        Ok(())
    }

    pub fn print_csv_header(&mut self) -> anyhow::Result<()> {
        if matches!(self.format, cli::OutputFormat::Csv) {
            self.writeln(
                "timestamp_ns,slave_id,slave_name,command,register_offset,data_length,working_counter,mailbox_type,pdo_values,fault_flag,fault_code,fault_description"
            )?;
        }
        Ok(())
    }

    fn print_frame_pretty(&mut self, frame: &EthercatFrame, converter: &pdo_converter::PdoConverter) -> anyhow::Result<()> {
        let ts = self.colorize(&format_ts(frame.timestamp_ns), Color::BrightBlue);
        self.writeln(&format!("═══ Frame @ {} ═══════════════════════════════", ts))?;
        self.writeln(&format!(
            "  Eth: {} → {}  Ethertype: 0x{:04x}  Len: {}B",
            self.colorize(&format_mac(&frame.ethernet_src), Color::Cyan),
            self.colorize(&format_mac(&frame.ethernet_dest), Color::Cyan),
            frame.ethertype,
            frame.frame_length
        ))?;
        for (i, dg) in frame.datagrams.iter().enumerate() {
            let idx = self.colorize(&format!("[{}]", i), Color::BrightBlack);
            let cmd = self.colorize(&format!("{:<4}", dg.header.command.to_str()), Color::Yellow);
            let slave_id = dg.header.slave_address;
            let slave_str = if let Some(name) = converter.get_slave_device_name(slave_id) {
                format!("Slave#{} ({})", slave_id, self.colorize(name, Color::Green))
            } else {
                format!("Slave#{}", self.colorize(&slave_id.to_string(), Color::Green))
            };
            let reg = format!("Reg:0x{:04x}", dg.header.register_offset);
            let wc = format!("WC:{}", dg.header.working_counter);
            self.writeln(&format!("  {} {} {:<20} {:<12} {:<8}", idx, cmd, slave_str, reg, wc))?;
            if dg.is_fault {
                let fault = self.colorize(
                    &format!(
                        "  ⚠ FAULT: {} (0x{:04x})",
                        dg.fault_description.as_deref().unwrap_or("Unknown fault"),
                        dg.fault_code.unwrap_or(0)
                    ),
                    Color::BrightRed,
                );
                self.writeln(&fault)?;
            }
            if let Some(mbox) = &dg.mailbox {
                let mtype = self.colorize(&format!("{}", mbox.msg_type.to_str()), Color::BrightMagenta);
                self.writeln(&format!("     └ Mailbox [{}] Ch:{} Pri:{} Cnt:{}", mtype, mbox.channel, mbox.priority, mbox.counter))?;
                if let Some(sdo) = &mbox.sdo {
                    let dir = if sdo.request { "REQ" } else { "RES" };
                    let sdo_str = format!(
                        "       SDO[{}] 0x{:04x}:{} data={} err={:?}",
                        dir,
                        sdo.index,
                        sdo.subindex,
                        hex::encode(&sdo.data),
                        sdo.error_code
                    );
                    self.writeln(&sdo_str)?;
                }
            }
            if let Some(pdo) = &dg.pdo {
                if !pdo.entries.is_empty() {
                    self.writeln("     └ PDO entries:")?;
                    let mut sorted_entries: Vec<_> = pdo.entries.values().collect();
                    sorted_entries.sort_by(|a, b| (a.index, a.subindex).cmp(&(b.index, b.subindex)));
                    for r in sorted_entries {
                        let name = r
                            .name
                            .as_deref()
                            .unwrap_or(&format!("0x{:04x}:{}", r.index, r.subindex));
                        let val = pdo_converter::PdoConverter::format_value(&r.value);
                        let val_str = self.colorize(&val, Color::BrightCyan);
                        let unit = r.unit.as_deref().unwrap_or("");
                        let comment = r
                            .business_comment
                            .as_deref()
                            .map(|c| format!(" // {}", self.colorize(c, Color::BrightBlack)))
                            .unwrap_or_default();
                        self.writeln(&format!(
                            "        · {} = {} {} {}",
                            name, val_str, unit, comment
                        ))?;
                    }
                }
            }
        }
        Ok(())
    }

    fn print_summary_pretty(&mut self, stats: &ParseStats) -> anyhow::Result<()> {
        let title = self.colorize("═══════════ Parsing Summary ═══════════", Color::BrightYellow);
        self.writeln("")?;
        self.writeln(&title)?;
        let kv = |k: &str, v: &str| -> String {
            format!(
                "  {:<28} {}",
                self.colorize(k, Color::Blue),
                self.colorize(v, Color::BrightWhite)
            )
        };
        self.writeln(&kv("Total frames:", &stats.total_frames.to_string()))?;
        self.writeln(&kv("Total datagrams:", &stats.total_datagrams.to_string()))?;
        self.writeln(&kv("CoE messages:", &stats.coe_messages.to_string()))?;
        self.writeln(&kv("FoE messages:", &stats.foe_messages.to_string()))?;
        self.writeln(&kv("EoE messages:", &stats.eoe_messages.to_string()))?;
        self.writeln(&kv("PDO updates:", &stats.pdo_updates.to_string()))?;
        let fault_str = if stats.fault_count > 0 {
            self.colorize(&stats.fault_count.to_string(), Color::BrightRed)
        } else {
            self.colorize(&stats.fault_count.to_string(), Color::Green)
        };
        self.writeln(&format!(
            "  {:<28} {}",
            self.colorize("Faults detected:", Color::Blue),
            fault_str
        ))?;
        if !stats.slave_counts.is_empty() {
            self.writeln("")?;
            self.writeln(&self.colorize("  Slave communication counts:", Color::BrightCyan))?;
            let mut slaves: BTreeMap<_, _> = stats.slave_counts.iter().collect();
            for (id, cnt) in slaves {
                self.writeln(&format!("    Slave#{:<6} {}", id, cnt))?;
            }
        }
        self.writeln(&self.colorize("═════════════════════════════════════════", Color::BrightYellow))?;
        Ok(())
    }

    fn print_summary_table(&mut self, stats: &ParseStats) -> anyhow::Result<()> {
        self.writeln(&format!(
            "{},{},{},{},{},{},{}",
            stats.total_frames,
            stats.total_datagrams,
            stats.coe_messages,
            stats.foe_messages,
            stats.eoe_messages,
            stats.pdo_updates,
            stats.fault_count
        ))?;
        Ok(())
    }

    pub fn print_json_array(&mut self, frames: &[EthercatFrame]) -> anyhow::Result<()> {
        let json = serde_json::to_string_pretty(frames)?;
        self.writeln(&json)?;
        Ok(())
    }

    pub fn print_template_preview(&mut self, template: &ParseTemplate) -> anyhow::Result<()> {
        self.writeln(&self.colorize(
            &format!(
                "Template loaded: {} (v{}) - {}",
                template.production_line, template.version, template.description
            ),
            Color::Magenta,
        ))?;
        for slave in &template.slaves {
            self.writeln(&format!(
                "  Slave#{}: {} [vendor=0x{:08x}, product=0x{:08x}] - {} registers",
                slave.slave_id,
                self.colorize(&slave.device_name, Color::Green),
                slave.vendor_id,
                slave.product_code,
                slave.registers.len()
            ))?;
        }
        Ok(())
    }
}

fn format_ts(ns: u64) -> String {
    let secs = ns / 1_000_000_000;
    let nanos = (ns % 1_000_000_000) as u32;
    if let Some(dt) = NaiveDateTime::from_timestamp_opt(secs as i64, nanos) {
        let utc = DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc);
        utc.format("%Y-%m-%dT%H:%M:%S%.9fZ").to_string()
    } else {
        format!("{}ns", ns)
    }
}

fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn format_slave(id: u16, converter: &pdo_converter::PdoConverter) -> String {
    if let Some(name) = converter.get_slave_device_name(id) {
        format!("{} ({})", id, name)
    } else {
        id.to_string()
    }
}

fn format_mailbox_state(dg: &ParsedDatagram) -> String {
    if let Some(mbox) = &dg.mailbox {
        format!("{}", mbox.msg_type.to_str())
    } else if dg.pdo.is_some() {
        "PDO".to_string()
    } else {
        "—".to_string()
    }
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_ts() {
        let s = format_ts(1_700_000_000_123_456_789);
        assert!(s.contains("2023-11"));
    }

    #[test]
    fn test_format_mac() {
        let m = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        assert_eq!(format_mac(&m), "00:11:22:33:44:55");
    }

    #[test]
    fn test_csv_escape() {
        assert_eq!(csv_escape("abc"), "abc");
        assert_eq!(csv_escape("a,b"), "\"a,b\"");
        assert_eq!(csv_escape("a\"b"), "\"a\"\"b\"");
    }
}
