use crate::*;
use anyhow::{Context, Result};
use byteorder::{LittleEndian, ReadBytesExt};
use std::collections::HashMap;
use std::io::Cursor;

#[derive(Debug, Clone)]
pub struct FrameHeader {
    pub ethernet_dest: [u8; 6],
    pub ethernet_src: [u8; 6],
    pub ethertype: u16,
    pub ec_header: EthercatHeader,
}

#[derive(Debug, Clone)]
pub struct EthercatHeader {
    pub length: u16,
    pub reserved: u8,
    pub num_datagrams: u8,
}

#[derive(Debug, Clone)]
pub struct RawEthercatFrame {
    pub timestamp_ns: u64,
    pub frame_length: usize,
    pub data: Vec<u8>,
    pub header: FrameHeader,
}

impl FrameHeader {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 14 {
            return Err(anyhow::anyhow!("Packet too short for Ethernet header: {} bytes", data.len()));
        }
        let mut dest = [0u8; 6];
        dest.copy_from_slice(&data[0..6]);
        let mut src = [0u8; 6];
        src.copy_from_slice(&data[6..12]);
        let ethertype = u16::from_be_bytes([data[12], data[13]]);
        if ethertype != crate::ETHERCAT_ETHERTYPE {
            return Err(anyhow::anyhow!(
                "Not an EtherCAT frame. Ethertype: 0x{:04x}, expected: 0x{:04x}",
                ethertype,
                crate::ETHERCAT_ETHERTYPE
            ));
        }
        if data.len() < 18 {
            return Err(anyhow::anyhow!("Packet too short for EtherCAT header"));
        }
        let ec_bytes = &data[14..18];
        let len_raw = u16::from_le_bytes([ec_bytes[0], ec_bytes[1] & 0x07]);
        let ec_length = (ec_bytes[0] as u16) | (((ec_bytes[1] & 0x07) as u16) << 8);
        let _ = len_raw;
        let ec_reserved = (ec_bytes[2] & 0xF0) >> 4;
        let ec_num_dgrams = ec_bytes[3] & 0x7F;
        let _ = ec_length;
        Ok(FrameHeader {
            ethernet_dest: dest,
            ethernet_src: src,
            ethertype,
            ec_header: EthercatHeader {
                length: u16::from_le_bytes([ec_bytes[0], ec_bytes[1] & 0x07]),
                reserved: ec_reserved,
                num_datagrams: ec_num_dgrams,
            },
        })
    }
}

pub fn parse_ethercat_frame(raw: &RawEthercatFrame) -> Result<EthercatFrame> {
    let header = &raw.header;
    let mut offset = 18usize;
    let payload_end = offset + header.ec_header.length as usize;
    let payload_end = payload_end.min(raw.data.len());
    let mut datagrams = Vec::new();
    while offset + 10 < payload_end {
        let (dg, consumed) = parse_datagram(&raw.data[offset..payload_end])?;
        datagrams.push(dg);
        offset += consumed;
        if consumed < 12 {
            break;
        }
    }
    Ok(EthercatFrame {
        timestamp_ns: raw.timestamp_ns,
        frame_length: raw.frame_length,
        ethernet_dest: header.ethernet_dest,
        ethernet_src: header.ethernet_src,
        ethertype: header.ethertype,
        datagrams,
    })
}

fn parse_datagram(data: &[u8]) -> Result<(ParsedDatagram, usize)> {
    if data.len() < 10 {
        return Err(anyhow::anyhow!("Datagram too short: {} bytes", data.len()));
    }
    let cmd_raw = data[0];
    let idx = data[1];
    let addr = u16::from_le_bytes([data[2], data[3]]);
    let regoff = u16::from_le_bytes([data[4], data[5]]);
    let len_flags = u16::from_le_bytes([data[6], data[7]]);
    let data_len = len_flags & 0x07FF;
    let circulating = (len_flags & 0x4000) != 0;
    let next = (len_flags & 0x8000) != 0;
    let irq = u16::from_le_bytes([data[8], data[9]]);
    let header_size = 10usize;
    let total_size = header_size + data_len as usize + 2;
    if data.len() < total_size {
        return Err(anyhow::anyhow!(
            "Datagram truncated: need {} bytes, have {}",
            total_size,
            data.len()
        ));
    }
    let payload: Vec<u8> = data[header_size..header_size + data_len as usize].to_vec();
    let wc_offset = header_size + data_len as usize;
    let working_counter = u16::from_le_bytes([data[wc_offset], data[wc_offset + 1]]);
    let command = EthercatCommand::from_u8(cmd_raw);
    let header = DatagramHeader {
        command,
        index: idx,
        slave_address: addr,
        register_offset: regoff,
        data_length: data_len,
        circulating,
        next,
        irq,
        working_counter,
    };
    let mut mailbox = None;
    let mut pdo = None;
    let mut is_fault = false;
    let mut fault_code: Option<u32> = None;
    let mut fault_description: Option<String> = None;
    if (command == EthercatCommand::LRW || command == EthercatCommand::APWR || command == EthercatCommand::FPRW) && data_len >= 6 {
        if let Ok(mbox) = try_parse_mailbox(&payload, addr) {
            mailbox = Some(mbox);
        }
    }
    if matches!(command, EthercatCommand::LRW | EthercatCommand::BRD | EthercatCommand::BWR | EthercatCommand::BRW) && data_len >= 2 && mailbox.is_none() {
        pdo = Some(PdoData {
            slave_id: addr,
            pdo_index: 0x1600,
            entries: HashMap::new(),
        });
    }
    if regoff == crate::AL_ERROR_CODE_REG && data_len >= 4 {
        is_fault = true;
        fault_code = Some(u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]));
        fault_description = Some(describe_al_error(fault_code.unwrap()));
    }
    Ok((
        ParsedDatagram {
            header,
            data: payload,
            mailbox,
            pdo,
            is_fault,
            fault_code,
            fault_description,
        },
        total_size,
    ))
}

fn try_parse_mailbox(data: &[u8], station: u16) -> Result<MailboxMessage> {
    if data.len() < 6 {
        return Err(anyhow::anyhow!("Mailbox data too short"));
    }
    let mbox_len = u16::from_le_bytes([data[0], data[1] & 0x07]) as usize;
    if mbox_len == 0 || data.len() < 6 {
        return Err(anyhow::anyhow!("Invalid mailbox length"));
    }
    let addr = u16::from_le_bytes([data[2], data[3]]);
    let chn_prio = data[4];
    let channel = chn_prio & 0x0F;
    let priority = (chn_prio >> 4) & 0x07;
    let typ_cnt = data[5];
    let msg_type = MailboxType::from_u8(typ_cnt & 0x0F);
    let counter = (typ_cnt >> 4) & 0x07;
    let payload: Vec<u8> = if data.len() > 6 {
        data[6..].to_vec()
    } else {
        Vec::new()
    };
    let sdo = if msg_type == MailboxType::CoE && payload.len() >= 10 {
        try_parse_sdo(&payload).ok()
    } else {
        None
    };
    let _ = station;
    Ok(MailboxMessage {
        station_address: addr,
        channel,
        priority,
        msg_type,
        counter,
        payload,
        sdo,
    })
}

fn try_parse_sdo(data: &[u8]) -> Result<SdoAccess> {
    if data.len() < 2 {
        return Err(anyhow::anyhow!("SDO data too short"));
    }
    let service = data[0] & 0x0F;
    let request = (service == crate::COE_SDO_REQUEST);
    if data.len() < 10 {
        return Ok(SdoAccess {
            index: 0,
            subindex: 0,
            request,
            data: data.to_vec(),
            completed: false,
            error_code: None,
        });
    }
    let index = u16::from_le_bytes([data[2], data[3]]);
    let subindex = data[4];
    let cs = (data[1] >> 5) & 0x03;
    let completed = cs == 0x00 || cs == 0x01;
    let expedited = (data[1] & 0x02) != 0;
    let size_indicated = (data[1] & 0x01) != 0;
    let error = (data[0] & 0x80) != 0;
    let mut payload = Vec::new();
    if expedited && size_indicated {
        let n = 4 - ((data[1] >> 2) & 0x03);
        let end = (8 + n as usize).min(data.len());
        payload = data[8..end].to_vec();
    } else if data.len() > 8 {
        payload = data[8..].to_vec();
    }
    let error_code = if error && data.len() >= 8 {
        Some(u32::from_le_bytes([data[4], data[5], data[6], data[7]]))
    } else {
        None
    };
    Ok(SdoAccess {
        index,
        subindex,
        request,
        data: payload,
        completed,
        error_code,
    })
}

fn describe_al_error(code: u32) -> String {
    match code {
        0x0000 => "No error".to_string(),
        0x0001 => "Unspecified error".to_string(),
        0x0002 => "No memory".to_string(),
        0x0011 => "Invalid requested state change".to_string(),
        0x0012 => "Unknown requested state".to_string(),
        0x0013 => "Bootstrap not supported".to_string(),
        0x0014 => "No valid firmware".to_string(),
        0x0015 => "Invalid mailbox configuration".to_string(),
        0x0016 => "Invalid mailbox configuration (sync channels)".to_string(),
        0x0017 => "Invalid sync manager configuration".to_string(),
        0x0018 => "No valid inputs available".to_string(),
        0x0019 => "No valid outputs available".to_string(),
        0x001A => "Synchronization error".to_string(),
        0x001B => "Sync manager watchdog".to_string(),
        0x001C => "Invalid Sync Manager Types".to_string(),
        0x001D => "Invalid output configuration".to_string(),
        0x001E => "Invalid input configuration".to_string(),
        0x001F => "Invalid watchdog configuration".to_string(),
        0x0020 => "Slave needs cold start".to_string(),
        0x0021 => "Slave needs INIT".to_string(),
        0x0022 => "Slave needs PREOP".to_string(),
        0x0023 => "Cold start prevented".to_string(),
        0x0024 => "INIT command prevented".to_string(),
        0x0025 => "PREOP command prevented".to_string(),
        0x0026 => "SAFEOP command prevented".to_string(),
        0x0027 => "Invalid input mapping".to_string(),
        0x0028 => "Invalid output mapping".to_string(),
        0x0029 => "Inconsistent settings".to_string(),
        0x002A => "FreeRun not supported".to_string(),
        0x002B => "SyncMode not supported".to_string(),
        0x002C => "FreeRun needs Buffer".to_string(),
        0x0030 => "Invalid DC SYNC configuration".to_string(),
        0x0031 => "Invalid DC latch configuration".to_string(),
        0x0032 => "PLL error".to_string(),
        0x0033 => "DC sync IO error".to_string(),
        0x0034 => "DC sync timeout".to_string(),
        0x0035 => "DC invalid sync cycle time".to_string(),
        0x0036 => "DC sync 0 cycle time".to_string(),
        0x0037 => "DC sync 1 cycle time".to_string(),
        0x0041 => "MBX_AOE".to_string(),
        0x0042 => "MBX_EOE".to_string(),
        0x0043 => "MBX_CoE".to_string(),
        0x0044 => "MBX_FOE".to_string(),
        0x0045 => "MBX_SoE".to_string(),
        0x0046 => "MBX_VoE".to_string(),
        0x0047 => "MBX_Doe".to_string(),
        0x0048 => "MBX_BRW".to_string(),
        0x0049 => "MBX_Generic".to_string(),
        0x0050 => "Lost samples".to_string(),
        0x0051 => "Invalid DC SYNC output data".to_string(),
        0x0060 => "Access Layer".to_string(),
        0x0070 => "SII / EEPROM".to_string(),
        0x0080 => "Application Controller available".to_string(),
        0x00F0 => "Vendor specific error ID".to_string(),
        0x0100 => "PCI vendor ID error".to_string(),
        0x0200 => "Invalid firmware".to_string(),
        0xFFFF => "General error".to_string(),
        other => format!("Unknown AL error code: 0x{:08x}", other),
    }
}

pub fn update_stats(stats: &mut ParseStats, frame: &EthercatFrame) {
    stats.total_frames += 1;
    for dg in &frame.datagrams {
        stats.total_datagrams += 1;
        *stats.slave_counts.entry(dg.header.slave_address).or_insert(0) += 1;
        if let Some(mbox) = &dg.mailbox {
            match mbox.msg_type {
                MailboxType::CoE => stats.coe_messages += 1,
                MailboxType::FoE => stats.foe_messages += 1,
                MailboxType::EoE => stats.eoe_messages += 1,
                _ => {}
            }
        }
        if dg.pdo.is_some() {
            stats.pdo_updates += 1;
        }
        if dg.is_fault {
            stats.fault_count += 1;
        }
    }
}

pub struct FilterOptions {
    pub slave_ids: Vec<u16>,
    pub msg_types: Vec<MailboxType>,
    pub fault_codes: Vec<u32>,
    pub commands: Vec<EthercatCommand>,
}

impl FilterOptions {
    pub fn new() -> Self {
        FilterOptions {
            slave_ids: Vec::new(),
            msg_types: Vec::new(),
            fault_codes: Vec::new(),
            commands: Vec::new(),
        }
    }

    pub fn has_any_filter(&self) -> bool {
        !self.slave_ids.is_empty()
            || !self.msg_types.is_empty()
            || !self.fault_codes.is_empty()
            || !self.commands.is_empty()
    }

    pub fn matches_frame(&self, frame: &EthercatFrame) -> bool {
        if !self.has_any_filter() {
            return true;
        }
        frame.datagrams.iter().any(|dg| self.matches_datagram(dg))
    }

    pub fn matches_datagram(&self, dg: &ParsedDatagram) -> bool {
        // ─── 第 1 层：主维度过滤（AND 关系，必须全部满足）───────────────
        // slave_ids / commands 属于基础选择维度
        if !self.slave_ids.is_empty() && !self.slave_ids.contains(&dg.header.slave_address) {
            return false;
        }
        if !self.commands.is_empty() && !self.commands.contains(&dg.header.command) {
            return false;
        }

        // ─── 第 2 层：附加筛选层（OR 关系，满足任意一个即可）─────────────
        // fault_codes / msg_types 属于"用户想额外看什么"的维度
        // 规则：
        //   - 两组都空 → 无需附加筛选，直接通过
        //   - 只有一组非空 → 必须匹配该组
        //   - 两组都非空 → (匹配 fault) OR (匹配 msg_type)
        let has_fault_filter = !self.fault_codes.is_empty();
        let has_msg_filter = !self.msg_types.is_empty();

        if !has_fault_filter && !has_msg_filter {
            return true;
        }

        let fault_match = if has_fault_filter {
            dg.is_fault && dg.fault_code.map_or(false, |c| self.fault_codes.contains(&c))
        } else {
            false
        };

        let msg_match = if has_msg_filter {
            dg.mailbox
                .as_ref()
                .map(|m| self.msg_types.contains(&m.msg_type))
                .unwrap_or(false)
        } else {
            false
        };

        match (has_fault_filter, has_msg_filter) {
            (true, true) => fault_match || msg_match,
            (true, false) => fault_match,
            (false, true) => msg_match,
            (false, false) => true,
        }
    }

    pub fn filter_frame(&self, frame: EthercatFrame) -> Option<EthercatFrame> {
        if self.matches_frame(&frame) {
            let filtered_dg: Vec<ParsedDatagram> = frame
                .datagrams
                .into_iter()
                .filter(|dg| self.matches_datagram(dg))
                .collect();
            if filtered_dg.is_empty() {
                None
            } else {
                Some(EthercatFrame {
                    datagrams: filtered_dg,
                    ..frame
                })
            }
        } else {
            None
        }
    }
}

impl Default for FilterOptions {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_frame_raw() -> RawEthercatFrame {
        let mut data = Vec::new();
        data.extend_from_slice(&[0x01, 0x01, 0x05, 0x04, 0x00, 0x00]);
        data.extend_from_slice(&[0x08, 0x06, 0x07, 0x08, 0x09, 0x0a]);
        data.extend_from_slice(&0x88A4u16.to_be_bytes());
        let mut ec = [0u8; 4];
        let dg_len: u16 = 28;
        ec[0] = (dg_len & 0xFF) as u8;
        ec[1] = ((dg_len >> 8) & 0x07) as u8;
        ec[2] = 0;
        ec[3] = 1;
        data.extend_from_slice(&ec);
        let mut dg = vec![0u8; 28];
        dg[0] = 0x0c;
        dg[1] = 0x01;
        dg[2] = 0x02;
        dg[3] = 0x00;
        dg[4] = 0x10;
        dg[5] = 0x00;
        let len_flags: u16 = 12 | (1u16 << 15);
        dg[6] = (len_flags & 0xFF) as u8;
        dg[7] = ((len_flags >> 8) & 0xFF) as u8;
        dg[8] = 0x00;
        dg[9] = 0x00;
        dg[10] = 0x00;
        dg[11] = 0x01;
        dg[12] = 0x02;
        dg[13] = 0x03;
        dg[14] = 0x04;
        dg[15] = 0x05;
        dg[16] = 0x06;
        dg[17] = 0x07;
        dg[18] = 0x08;
        dg[19] = 0x09;
        dg[20] = 0x0a;
        dg[21] = 0x0b;
        dg[22] = 0x01;
        dg[23] = 0x00;
        data.extend_from_slice(&dg);
        let header = FrameHeader::parse(&data).unwrap();
        RawEthercatFrame {
            timestamp_ns: 123456789,
            frame_length: data.len(),
            data,
            header,
        }
    }

    #[test]
    fn test_parse_frame_header() {
        let raw = make_test_frame_raw();
        assert_eq!(raw.header.ethertype, 0x88A4);
        assert_eq!(raw.header.ec_header.num_datagrams, 1);
    }

    #[test]
    fn test_parse_full_frame() {
        let raw = make_test_frame_raw();
        let frame = parse_ethercat_frame(&raw).unwrap();
        assert_eq!(frame.timestamp_ns, 123456789);
        assert_eq!(frame.datagrams.len(), 1);
        let dg = &frame.datagrams[0];
        assert_eq!(dg.header.slave_address, 2);
        assert_eq!(dg.header.command, EthercatCommand::LRW);
        assert_eq!(dg.header.register_offset, 0x0010);
    }

    #[test]
    fn test_filter() {
        let raw = make_test_frame_raw();
        let frame = parse_ethercat_frame(&raw).unwrap();
        let mut f = FilterOptions::new();
        assert!(f.matches_frame(&frame));
        f.slave_ids = vec![100];
        assert!(!f.matches_frame(&frame));
        let mut f2 = FilterOptions::new();
        f2.slave_ids = vec![2];
        assert!(f2.matches_frame(&frame));
    }

    fn make_mock_datagram(
        slave: u16,
        cmd: EthercatCommand,
        is_fault: bool,
        fault_code: Option<u32>,
        mbox_type: Option<MailboxType>,
    ) -> ParsedDatagram {
        ParsedDatagram {
            header: DatagramHeader {
                command: cmd,
                index: 0,
                slave_address: slave,
                register_offset: 0,
                data_length: 4,
                circulating: false,
                next: false,
                irq: 0,
                working_counter: 1,
            },
            data: vec![0u8; 4],
            mailbox: mbox_type.map(|mt| MailboxMessage {
                station_address: slave,
                channel: 0,
                priority: 0,
                msg_type: mt,
                counter: 0,
                payload: Vec::new(),
                sdo: None,
            }),
            pdo: None,
            is_fault,
            fault_code,
            fault_description: fault_code.map(describe_al_error),
        }
    }

    fn make_mock_frame(dgs: Vec<ParsedDatagram>) -> EthercatFrame {
        EthercatFrame {
            timestamp_ns: 123,
            frame_length: 64,
            ethernet_dest: [0u8; 6],
            ethernet_src: [0u8; 6],
            ethertype: 0x88A4,
            datagrams: dgs,
        }
    }

    #[test]
    fn test_filter_multi_slave_and_command_and_pass() {
        // --slave-id 1,3 --command LRW → 应该同时保留 slave1 和 slave3 的 LRW 报文
        let dgs = vec![
            make_mock_datagram(1, EthercatCommand::LRW, false, None, None),
            make_mock_datagram(2, EthercatCommand::LRW, false, None, None),
            make_mock_datagram(3, EthercatCommand::LRW, false, None, None),
            make_mock_datagram(1, EthercatCommand::APRD, false, None, None),
        ];
        let frame = make_mock_frame(dgs);
        let mut f = FilterOptions::new();
        f.slave_ids = vec![1, 3];
        f.commands = vec![EthercatCommand::LRW];
        let filtered = f.filter_frame(frame).unwrap();
        assert_eq!(filtered.datagrams.len(), 2);
        assert_eq!(filtered.datagrams[0].header.slave_address, 1);
        assert_eq!(filtered.datagrams[1].header.slave_address, 3);
    }

    #[test]
    fn test_filter_slave_plus_fault_or_pass() {
        // --slave-id 1 --fault-code 0x0011 → 关键修复: 保留 slave1 的正常 PDO + slave1 的故障报文
        // 旧逻辑会把 slave1 的正常报文因不匹配 fault_code 全过滤掉
        let dgs = vec![
            make_mock_datagram(1, EthercatCommand::LRW, false, None, None),
            make_mock_datagram(1, EthercatCommand::LRW, true, Some(0x0011), None),
            make_mock_datagram(5, EthercatCommand::LRW, true, Some(0x0011), None),
        ];
        let frame = make_mock_frame(dgs);
        let mut f = FilterOptions::new();
        f.slave_ids = vec![1];
        f.fault_codes = vec![0x0011];
        let filtered = f.filter_frame(frame).unwrap();
        assert_eq!(
            filtered.datagrams.len(),
            2,
            "slave1 的正常PDO和slave1的故障报文都应保留"
        );
        assert!(!filtered.datagrams[0].is_fault);
        assert!(filtered.datagrams[1].is_fault);
    }

    #[test]
    fn test_filter_slave_plus_msg_type_or_pass() {
        // --slave-id 2 --msg-type CoE → 保留 slave2 的 PDO + slave2 的 CoE
        // 旧逻辑会把 slave2 的 PDO（无 mailbox）全过滤掉
        let dgs = vec![
            make_mock_datagram(2, EthercatCommand::LRW, false, None, None),
            make_mock_datagram(2, EthercatCommand::LRW, false, None, Some(MailboxType::CoE)),
            make_mock_datagram(2, EthercatCommand::LRW, false, None, Some(MailboxType::FoE)),
            make_mock_datagram(9, EthercatCommand::LRW, false, None, Some(MailboxType::CoE)),
        ];
        let frame = make_mock_frame(dgs);
        let mut f = FilterOptions::new();
        f.slave_ids = vec![2];
        f.msg_types = vec![MailboxType::CoE];
        let filtered = f.filter_frame(frame).unwrap();
        assert_eq!(
            filtered.datagrams.len(),
            2,
            "slave2 的PDO + slave2的CoE 应保留, slave2的FoE和slave9的CoE应排除"
        );
        assert!(filtered.datagrams[0].mailbox.is_none());
        assert_eq!(
            filtered.datagrams[1].mailbox.as_ref().unwrap().msg_type,
            MailboxType::CoE
        );
    }

    #[test]
    fn test_filter_fault_plus_msg_type_or_pass() {
        // --fault-code 0x001A --msg-type FoE → (故障) OR (FoE) 的并集
        let dgs = vec![
            make_mock_datagram(1, EthercatCommand::LRW, false, None, None),
            make_mock_datagram(2, EthercatCommand::LRW, true, Some(0x001A), None),
            make_mock_datagram(3, EthercatCommand::LRW, false, None, Some(MailboxType::FoE)),
            make_mock_datagram(4, EthercatCommand::LRW, true, Some(0x001A), Some(MailboxType::FoE)),
            make_mock_datagram(5, EthercatCommand::LRW, false, None, Some(MailboxType::CoE)),
        ];
        let frame = make_mock_frame(dgs);
        let mut f = FilterOptions::new();
        f.fault_codes = vec![0x001A];
        f.msg_types = vec![MailboxType::FoE];
        let filtered = f.filter_frame(frame).unwrap();
        assert_eq!(
            filtered.datagrams.len(),
            3,
            "slave2(故障) + slave3(FoE) + slave4(双匹配) 应保留"
        );
        assert_eq!(filtered.datagrams[0].header.slave_address, 2);
        assert_eq!(filtered.datagrams[1].header.slave_address, 3);
        assert_eq!(filtered.datagrams[2].header.slave_address, 4);
    }

    #[test]
    fn test_filter_quad_combination() {
        // --slave-id 1,2,5 --command LRW,APRD --fault-code 0x0011 --msg-type EoE
        // = (slave ∈ {1,2,5}) AND (cmd ∈ {LRW,APRD}) AND ( fault=0x0011 OR EoE OR 无附加条件=放行 )
        let dgs = vec![
            make_mock_datagram(1, EthercatCommand::LRW, false, None, None),
            make_mock_datagram(1, EthercatCommand::FPRD, false, None, None),
            make_mock_datagram(2, EthercatCommand::APRD, true, Some(0x0011), None),
            make_mock_datagram(3, EthercatCommand::LRW, true, Some(0x0011), None),
            make_mock_datagram(5, EthercatCommand::LRW, false, None, Some(MailboxType::EoE)),
            make_mock_datagram(5, EthercatCommand::LRW, false, None, Some(MailboxType::CoE)),
            make_mock_datagram(2, EthercatCommand::LRW, false, None, Some(MailboxType::EoE)),
        ];
        let frame = make_mock_frame(dgs);
        let mut f = FilterOptions::new();
        f.slave_ids = vec![1, 2, 5];
        f.commands = vec![EthercatCommand::LRW, EthercatCommand::APRD];
        f.fault_codes = vec![0x0011];
        f.msg_types = vec![MailboxType::EoE];
        let filtered = f.filter_frame(frame).unwrap();
        let slaves: Vec<u16> = filtered.datagrams.iter().map(|d| d.header.slave_address).collect();
        // slave1(LRW,PDO) → 主维度通过，附加层 fault+msg 虽都不匹配但 ... 等等，按新逻辑两者都启用时是 OR
        // 不: --fault-code 和 --msg-type 都传入 → (fault匹配) OR (msg匹配)
        // slave1 无故障 非 EoE → 附加层不通过 → 被排除
        // slave1 FPRD → 主维度命令不匹配 → 排除
        // slave2 APRD 故障0x0011 → 主维度通过 + 附加fault通过 → 保留 ✓
        // slave3 → slave不匹配 → 排除
        // slave5 LRW EoE → 主维度通过 + 附加msg通过 → 保留 ✓
        // slave5 LRW CoE → 附加层不匹配(fault也不匹配) → 排除
        // slave2 LRW EoE → 主维度通过 + 附加msg通过 → 保留 ✓
        assert_eq!(
            filtered.datagrams.len(),
            3,
            "应保留 slave2(fault)+slave5(EoE)+slave2(EoE)"
        );
        assert_eq!(slaves, vec![2, 5, 2]);
    }

    #[test]
    fn test_filter_fault_only_does_not_exclude_normal_when_not_requested() {
        // 仅 slave_id 过滤时，不带 fault 条件 → 正常报文必须通过
        // (这是一个回归测试，防止以后重构时引入 AND 回归)
        let dgs = vec![
            make_mock_datagram(3, EthercatCommand::LRW, false, None, None),
            make_mock_datagram(3, EthercatCommand::LRW, false, None, None),
        ];
        let frame = make_mock_frame(dgs);
        let mut f = FilterOptions::new();
        f.slave_ids = vec![3];
        let filtered = f.filter_frame(frame).unwrap();
        assert_eq!(filtered.datagrams.len(), 2);
    }

    #[test]
    fn test_filter_has_any_flag() {
        let f = FilterOptions::new();
        assert!(!f.has_any_filter());
        let mut f2 = FilterOptions::new();
        f2.slave_ids = vec![1];
        assert!(f2.has_any_filter());
        let mut f3 = FilterOptions::new();
        f3.msg_types = vec![MailboxType::CoE];
        assert!(f3.has_any_filter());
        let mut f4 = FilterOptions::new();
        f4.fault_codes = vec![0x0011];
        assert!(f4.has_any_filter());
        let mut f5 = FilterOptions::new();
        f5.commands = vec![EthercatCommand::LRW];
        assert!(f5.has_any_filter());
    }

    #[test]
    fn test_al_error_codes() {
        assert!(describe_al_error(0x0011).contains("state change"));
        assert!(describe_al_error(0xFFFF).contains("General"));
    }
}
