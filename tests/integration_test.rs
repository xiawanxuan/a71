use ethercat_parser::*;
use std::fs::File;
use std::io::{BufWriter, Write};
use tempfile::NamedTempFile;

fn build_test_frame(slave_count: u16, include_fault: bool, fault_code: u32) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&[0x01u8, 0x01, 0x05, 0x04, 0x00, 0x00]);
    data.extend_from_slice(&[0x08u8, 0x06, 0x07, 0x08, 0x09, 0x0a]);
    data.extend_from_slice(&ETHERCAT_ETHERTYPE.to_be_bytes());
    let mut datagrams: Vec<Vec<u8>> = Vec::new();
    for i in 0..slave_count {
        let is_last = i + 1 == slave_count;
        let sid = i + 1;
        let mut dg = Vec::new();
        dg.push(0x0C);
        dg.push(i as u8);
        dg.extend_from_slice(&sid.to_le_bytes());
        let inject = include_fault && sid == slave_count;
        let reg: u16 = if inject { AL_ERROR_CODE_REG } else { 0x0010 };
        dg.extend_from_slice(&reg.to_le_bytes());
        let plen: u16 = if inject { 4 } else { 12 };
        let nflag: u16 = if is_last { 0 } else { 1u16 << 15 };
        let lf: u16 = plen | nflag;
        dg.extend_from_slice(&lf.to_le_bytes());
        dg.extend_from_slice(&0u16.to_le_bytes());
        if inject {
            dg.extend_from_slice(&fault_code.to_le_bytes());
        } else {
            let pos: i32 = (i as i32) * 1000 + 500;
            dg.extend_from_slice(&pos.to_le_bytes());
            let vel: i16 = (i as i16) * 100 + 200;
            dg.extend_from_slice(&vel.to_le_bytes());
            let io: u16 = 0xFF00 | (i as u16);
            dg.extend_from_slice(&io.to_le_bytes());
        }
        let wc: u16 = 1;
        dg.extend_from_slice(&wc.to_le_bytes());
        datagrams.push(dg);
    }
    let total: usize = datagrams.iter().map(|d| d.len()).sum();
    let mut ec = [0u8; 4];
    let ecls = (total as u16) & 0x07FF;
    ec[0] = (ecls & 0xFF) as u8;
    ec[1] = ((ecls >> 8) & 0x07) as u8;
    ec[2] = 0;
    ec[3] = slave_count as u8;
    data.extend_from_slice(&ec);
    for dg in datagrams {
        data.extend(dg);
    }
    data
}

fn wrap_as_raw_capture(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut ts: u64 = 1_700_000_000_000_000_000;
    for f in frames {
        buf.extend_from_slice(&(f.len() as u32).to_le_bytes());
        buf.extend_from_slice(&ts.to_le_bytes());
        buf.extend_from_slice(f);
        ts += 1_000_000;
    }
    buf
}

#[test]
fn integration_pipeline_read_parse_filter_enhance() {
    let frame1 = build_test_frame(5, false, 0);
    let frame2 = build_test_frame(5, true, 0x0011);
    let capture = wrap_as_raw_capture(&[frame1, frame2]);
    let mut tmp = NamedTempFile::new().unwrap();
    tmp.write_all(&capture).unwrap();
    let path = tmp.path().to_str().unwrap().to_string();
    let mut reader = io_reader::RawFileReader::open(&path).unwrap();
    let mut stats = ParseStats::default();
    let total_frames;
    let mut conv = pdo_converter::PdoConverter::new();
    let tpl_json = include_str!("../templates/registers.json");
    conv.load_template_from_str(tpl_json).unwrap();
    let mut parsed_frames = Vec::new();
    loop {
        let rf = reader.read_next_frame().unwrap();
        match rf {
            Some(raw) => {
                let mut pf = ethercat_parser::parse_ethercat_frame(&raw).unwrap();
                for dg in pf.datagrams.iter_mut() {
                    conv.enhance_datagram(dg);
                }
                update_stats(&mut stats, &pf);
                parsed_frames.push(pf);
            }
            None => break,
        }
    }
    total_frames = parsed_frames.len();
    assert_eq!(total_frames, 2);
    assert_eq!(stats.total_frames, 2);
    assert_eq!(stats.total_datagrams, 10);
    assert_eq!(stats.fault_count, 1);
    assert_eq!(*stats.slave_counts.get(&1).unwrap(), 2);
    assert_eq!(*stats.slave_counts.get(&5).unwrap(), 2);
    let pf = &parsed_frames[0];
    assert_eq!(pf.ethertype, ETHERCAT_ETHERTYPE);
    assert_eq!(pf.datagrams.len(), 5);
    let dg0 = &pf.datagrams[0];
    assert_eq!(dg0.header.command, EthercatCommand::LRW);
    assert_eq!(dg0.header.slave_address, 1);
    assert_eq!(dg0.header.register_offset, 0x0010);
    let pf2 = &parsed_frames[1];
    let last_dg = &pf2.datagrams[4];
    assert_eq!(last_dg.header.slave_address, 5);
    assert_eq!(last_dg.is_fault, true);
    assert_eq!(last_dg.fault_code, Some(0x0011));
    assert!(last_dg.fault_description.as_ref().unwrap().contains("state change"));
    let dev_name = conv.get_slave_device_name(1);
    assert_eq!(dev_name, Some("X-Axis-Servo-Drive"));
    let dev_name3 = conv.get_slave_device_name(3);
    assert_eq!(dev_name3, Some("IO-Module-Conveyor"));
}

#[test]
fn integration_filter_slave_id() {
    let frame1 = build_test_frame(5, false, 0);
    let capture = wrap_as_raw_capture(&[frame1]);
    let mut tmp = NamedTempFile::new().unwrap();
    tmp.write_all(&capture).unwrap();
    let path = tmp.path().to_str().unwrap().to_string();
    let mut reader = io_reader::RawFileReader::open(&path).unwrap();
    let raw = reader.read_next_frame().unwrap().unwrap();
    let pf = ethercat_parser::parse_ethercat_frame(&raw).unwrap();
    let mut filter = ethercat_parser::FilterOptions::new();
    filter.slave_ids = vec![3];
    assert!(filter.matches_frame(&pf));
    let filtered = filter.filter_frame(pf).unwrap();
    assert_eq!(filtered.datagrams.len(), 1);
    assert_eq!(filtered.datagrams[0].header.slave_address, 3);
}

#[test]
fn integration_filter_fault_code() {
    let frame1 = build_test_frame(5, true, 0x001A);
    let capture = wrap_as_raw_capture(&[frame1]);
    let mut tmp = NamedTempFile::new().unwrap();
    tmp.write_all(&capture).unwrap();
    let path = tmp.path().to_str().unwrap().to_string();
    let mut reader = io_reader::RawFileReader::open(&path).unwrap();
    let raw = reader.read_next_frame().unwrap().unwrap();
    let pf = ethercat_parser::parse_ethercat_frame(&raw).unwrap();
    let mut filter = ethercat_parser::FilterOptions::new();
    filter.fault_codes = vec![0x0011];
    assert!(!filter.matches_frame(&pf));
    filter.fault_codes = vec![0x001A];
    assert!(filter.matches_frame(&pf));
    let filtered = filter.filter_frame(pf).unwrap();
    assert_eq!(filtered.datagrams.len(), 1);
    assert_eq!(filtered.datagrams[0].fault_code, Some(0x001A));
}

#[test]
fn integration_filter_msg_type() {
    let frame1 = build_test_frame(3, false, 0);
    let capture = wrap_as_raw_capture(&[frame1]);
    let mut tmp = NamedTempFile::new().unwrap();
    tmp.write_all(&capture).unwrap();
    let path = tmp.path().to_str().unwrap().to_string();
    let mut reader = io_reader::RawFileReader::open(&path).unwrap();
    let raw = reader.read_next_frame().unwrap().unwrap();
    let pf = ethercat_parser::parse_ethercat_frame(&raw).unwrap();
    let mut filter = ethercat_parser::FilterOptions::new();
    filter.msg_types = vec![MailboxType::CoE];
    assert!(!filter.matches_frame(&pf));
}

#[test]
fn integration_pdo_conversion_with_template() {
    let frame1 = build_test_frame(5, false, 0);
    let capture = wrap_as_raw_capture(&[frame1]);
    let mut tmp = NamedTempFile::new().unwrap();
    tmp.write_all(&capture).unwrap();
    let path = tmp.path().to_str().unwrap().to_string();
    let mut reader = io_reader::RawFileReader::open(&path).unwrap();
    let raw = reader.read_next_frame().unwrap().unwrap();
    let mut pf = ethercat_parser::parse_ethercat_frame(&raw).unwrap();
    let mut conv = pdo_converter::PdoConverter::new();
    let tpl_json = include_str!("../templates/registers.json");
    conv.load_template_from_str(tpl_json).unwrap();
    for dg in pf.datagrams.iter_mut() {
        conv.enhance_datagram(dg);
    }
    let dg_x = &pf.datagrams[0];
    if let Some(ref pdo) = dg_x.pdo {
        assert_eq!(pdo.slave_id, 1);
        if let Some(entry) = pdo.entries.values().next() {
            let val_str = pdo_converter::PdoConverter::format_value(&entry.value);
            assert!(!val_str.is_empty());
        }
    }
}

#[test]
fn integration_template_generation_roundtrip() {
    let tpl_json = include_str!("../templates/registers.json");
    let mut conv = pdo_converter::PdoConverter::new();
    conv.load_template_from_str(tpl_json).unwrap();
    let tpl = conv.get_template().unwrap();
    assert_eq!(tpl.version, "1.0");
    assert_eq!(tpl.production_line, "Assembly-Line-A");
    assert_eq!(tpl.slaves.len(), 5);
    for s in &tpl.slaves {
        assert!(!s.registers.is_empty());
        for r in &s.registers {
            assert!(!r.name.is_empty());
            assert!(!r.data_type.is_empty());
        }
    }
    assert_eq!(conv.get_slave_device_name(4), Some("Temperature-Controller"));
    assert_eq!(conv.get_slave_device_name(5), Some("Vision-Inspector"));
    assert_eq!(conv.get_slave_device_name(99), None);
}

#[test]
fn integration_stats_update() {
    let frame1 = build_test_frame(3, false, 0);
    let frame2 = build_test_frame(3, true, 0x0030);
    let capture = wrap_as_raw_capture(&[frame1, frame2]);
    let mut tmp = NamedTempFile::new().unwrap();
    tmp.write_all(&capture).unwrap();
    let path = tmp.path().to_str().unwrap().to_string();
    let mut reader = io_reader::RawFileReader::open(&path).unwrap();
    let mut stats = ParseStats::default();
    while let Some(raw) = reader.read_next_frame().unwrap() {
        let pf = ethercat_parser::parse_ethercat_frame(&raw).unwrap();
        update_stats(&mut stats, &pf);
    }
    assert_eq!(stats.total_frames, 2);
    assert_eq!(stats.total_datagrams, 6);
    assert_eq!(stats.coe_messages, 0);
    assert_eq!(stats.fault_count, 1);
    assert_eq!(*stats.slave_counts.get(&2).unwrap(), 2);
}

#[test]
fn integration_multiple_datagrams_one_frame() {
    let frame1 = build_test_frame(8, false, 0);
    let capture = wrap_as_raw_capture(&[frame1]);
    let mut tmp = NamedTempFile::new().unwrap();
    tmp.write_all(&capture).unwrap();
    let path = tmp.path().to_str().unwrap().to_string();
    let mut reader = io_reader::RawFileReader::open(&path).unwrap();
    let raw = reader.read_next_frame().unwrap().unwrap();
    let pf = ethercat_parser::parse_ethercat_frame(&raw).unwrap();
    assert_eq!(pf.datagrams.len(), 8);
    for i in 0..8 {
        assert_eq!(pf.datagrams[i].header.slave_address, (i as u16) + 1);
    }
}
