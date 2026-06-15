use crate::*;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

pub struct PdoConverter {
    template: Option<ParseTemplate>,
    slave_register_map: HashMap<(u16, u16, u8), TemplateRegister>,
    slave_device_map: HashMap<u16, TemplateSlave>,
}

impl PdoConverter {
    pub fn new() -> Self {
        PdoConverter {
            template: None,
            slave_register_map: HashMap::new(),
            slave_device_map: HashMap::new(),
        }
    }

    pub fn load_template<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let file = File::open(path.as_ref())
            .with_context(|| format!("Failed to open template file: {:?}", path.as_ref()))?;
        let reader = BufReader::new(file);
        let template: ParseTemplate = serde_json::from_reader(reader)
            .with_context(|| "Failed to parse template JSON")?;
        self.build_indexes(&template);
        self.template = Some(template);
        Ok(())
    }

    pub fn load_template_from_str(&mut self, json: &str) -> Result<()> {
        let template: ParseTemplate = serde_json::from_str(json)
            .with_context(|| "Failed to parse template JSON")?;
        self.build_indexes(&template);
        self.template = Some(template);
        Ok(())
    }

    fn build_indexes(&mut self, template: &ParseTemplate) {
        self.slave_register_map.clear();
        self.slave_device_map.clear();
        for slave in &template.slaves {
            self.slave_device_map.insert(slave.slave_id, slave.clone());
            for reg in &slave.registers {
                self.slave_register_map.insert(
                    (slave.slave_id, reg.index, reg.subindex),
                    reg.clone(),
                );
            }
        }
    }

    pub fn get_template(&self) -> Option<&ParseTemplate> {
        self.template.as_ref()
    }

    pub fn get_slave_device_name(&self, slave_id: u16) -> Option<&str> {
        self.slave_device_map.get(&slave_id).map(|s| s.device_name.as_str())
    }

    pub fn convert_pdo_data(
        &self,
        slave_id: u16,
        pdo_index: u16,
        raw_data: &[u8],
    ) -> PdoData {
        let mut entries = HashMap::new();
        let mut bit_offset: usize = 0;
        let mut last_reg_index: u16 = 0;
        for sub_idx in 1u8..=255u8 {
            if bit_offset / 8 >= raw_data.len() {
                break;
            }
            let (value, consumed_bits, reg_index, template) =
                self.extract_value_at(slave_id, pdo_index, sub_idx, raw_data, bit_offset);
            let key = ((reg_index as u32) << 8) | (sub_idx as u32);
            if consumed_bits == 0 {
                if sub_idx > 32 {
                    break;
                }
                continue;
            }
            let reg_template = self.slave_register_map.get(&(slave_id, reg_index, sub_idx));
            let name = reg_template.as_ref().map(|r| r.name.clone());
            let description = reg_template.as_ref().map(|r| r.description.clone());
            let unit = reg_template.as_ref().and_then(|r| r.unit.clone());
            let business_comment = reg_template.as_ref().and_then(|r| r.business_comment.clone());
            let raw_bytes = self.extract_raw_bytes(raw_data, bit_offset, consumed_bits);
            entries.insert(
                key as u16,
                RegisterValue {
                    index: reg_index,
                    subindex: sub_idx,
                    name,
                    description,
                    unit,
                    raw_bytes,
                    value,
                    business_comment,
                },
            );
            bit_offset += consumed_bits;
            last_reg_index = reg_index;
            let _ = template;
        }
        let _ = last_reg_index;
        PdoData {
            slave_id,
            pdo_index,
            entries,
        }
    }

    fn extract_value_at(
        &self,
        slave_id: u16,
        pdo_index: u16,
        subindex: u8,
        raw_data: &[u8],
        bit_offset: usize,
    ) -> (PdoValueType, usize, u16, Option<TemplateRegister>) {
        let reg_index = 0x7000 + (pdo_index.saturating_sub(0x1600));
        if let Some(template) = self.slave_register_map.get(&(slave_id, reg_index, subindex)) {
            let (val, bits) = self.convert_with_template(template, raw_data, bit_offset);
            return (val, bits, reg_index, Some(template.clone()));
        }
        if bit_offset / 8 >= raw_data.len() {
            return (PdoValueType::Bytes(Vec::new()), 0, reg_index, None);
        }
        let remaining = raw_data.len() * 8 - bit_offset;
        if remaining >= 16 && bit_offset % 8 == 0 {
            let byte_idx = bit_offset / 8;
            if byte_idx + 2 <= raw_data.len() {
                let v = u16::from_le_bytes([raw_data[byte_idx], raw_data[byte_idx + 1]]);
                return (PdoValueType::Uint16(v), 16, reg_index, None);
            }
        }
        if remaining >= 8 && bit_offset % 8 == 0 {
            let byte_idx = bit_offset / 8;
            return (PdoValueType::Uint8(raw_data[byte_idx]), 8, reg_index, None);
        }
        (PdoValueType::Bytes(Vec::new()), 0, reg_index, None)
    }

    fn convert_with_template(
        &self,
        reg: &TemplateRegister,
        raw_data: &[u8],
        bit_offset: usize,
    ) -> (PdoValueType, usize) {
        let byte_idx = bit_offset / 8;
        let bit_remain = bit_offset % 8;
        match reg.data_type.as_str() {
            "bool" | "BOOL" | "BOOLEAN" => {
                if byte_idx >= raw_data.len() {
                    return (PdoValueType::Bool(false), 0);
                }
                let val = (raw_data[byte_idx] >> bit_remain) & 0x01 == 1;
                (PdoValueType::Bool(val), 1)
            }
            "int8" | "INT8" | "SINT" => {
                if byte_idx >= raw_data.len() {
                    return (PdoValueType::Int8(0), 0);
                }
                (PdoValueType::Int8(raw_data[byte_idx] as i8), 8)
            }
            "uint8" | "UINT8" | "USINT" | "BYTE" => {
                if byte_idx >= raw_data.len() {
                    return (PdoValueType::Uint8(0), 0);
                }
                (PdoValueType::Uint8(raw_data[byte_idx]), 8)
            }
            "int16" | "INT16" | "INT" => {
                if byte_idx + 1 >= raw_data.len() {
                    return (PdoValueType::Int16(0), 0);
                }
                let v = i16::from_le_bytes([raw_data[byte_idx], raw_data[byte_idx + 1]]);
                (PdoValueType::Int16(v), 16)
            }
            "uint16" | "UINT16" | "UINT" | "WORD" => {
                if byte_idx + 1 >= raw_data.len() {
                    return (PdoValueType::Uint16(0), 0);
                }
                let v = u16::from_le_bytes([raw_data[byte_idx], raw_data[byte_idx + 1]]);
                (PdoValueType::Uint16(v), 16)
            }
            "int32" | "INT32" | "DINT" => {
                if byte_idx + 3 >= raw_data.len() {
                    return (PdoValueType::Int32(0), 0);
                }
                let v = i32::from_le_bytes([
                    raw_data[byte_idx],
                    raw_data[byte_idx + 1],
                    raw_data[byte_idx + 2],
                    raw_data[byte_idx + 3],
                ]);
                (PdoValueType::Int32(v), 32)
            }
            "uint32" | "UINT32" | "UDINT" | "DWORD" => {
                if byte_idx + 3 >= raw_data.len() {
                    return (PdoValueType::Uint32(0), 0);
                }
                let v = u32::from_le_bytes([
                    raw_data[byte_idx],
                    raw_data[byte_idx + 1],
                    raw_data[byte_idx + 2],
                    raw_data[byte_idx + 3],
                ]);
                (PdoValueType::Uint32(v), 32)
            }
            "int64" | "INT64" | "LINT" => {
                if byte_idx + 7 >= raw_data.len() {
                    return (PdoValueType::Int64(0), 0);
                }
                let mut b = [0u8; 8];
                b.copy_from_slice(&raw_data[byte_idx..byte_idx + 8]);
                (PdoValueType::Int64(i64::from_le_bytes(b)), 64)
            }
            "uint64" | "UINT64" | "ULINT" | "LWORD" => {
                if byte_idx + 7 >= raw_data.len() {
                    return (PdoValueType::Uint64(0), 0);
                }
                let mut b = [0u8; 8];
                b.copy_from_slice(&raw_data[byte_idx..byte_idx + 8]);
                (PdoValueType::Uint64(u64::from_le_bytes(b)), 64)
            }
            "float" | "FLOAT" | "REAL" => {
                if byte_idx + 3 >= raw_data.len() {
                    return (PdoValueType::Float(0.0), 0);
                }
                let mut b = [0u8; 4];
                b.copy_from_slice(&raw_data[byte_idx..byte_idx + 4]);
                (PdoValueType::Float(f32::from_le_bytes(b)), 32)
            }
            "double" | "DOUBLE" | "LREAL" => {
                if byte_idx + 7 >= raw_data.len() {
                    return (PdoValueType::Double(0.0), 0);
                }
                let mut b = [0u8; 8];
                b.copy_from_slice(&raw_data[byte_idx..byte_idx + 8]);
                (PdoValueType::Double(f64::from_le_bytes(b)), 64)
            }
            "state" | "STATE" | "AL_STATE" => {
                if byte_idx >= raw_data.len() {
                    return (PdoValueType::State(StateMachineState::Unknown(0)), 0);
                }
                (
                    PdoValueType::State(StateMachineState::from_u8(raw_data[byte_idx])),
                    8,
                )
            }
            "string" | "STRING" | "VISIBLE_STRING" => {
                let start = byte_idx;
                let mut end = start;
                while end < raw_data.len() && raw_data[end] != 0 {
                    end += 1;
                }
                let s = String::from_utf8_lossy(&raw_data[start..end]).to_string();
                let consumed = ((end - start) + 1) * 8;
                (PdoValueType::String(s), consumed.max(8))
            }
            _ => {
                let end = (byte_idx + 4).min(raw_data.len());
                let b = raw_data[byte_idx..end].to_vec();
                let bits = b.len() * 8;
                (PdoValueType::Bytes(b), if bits == 0 { 8 } else { bits })
            }
        }
    }

    fn extract_raw_bytes(&self, raw_data: &[u8], bit_offset: usize, consumed_bits: usize) -> Vec<u8> {
        if consumed_bits == 0 {
            return Vec::new();
        }
        let start_byte = bit_offset / 8;
        let total_bytes = (consumed_bits + 7) / 8;
        let end_byte = (start_byte + total_bytes).min(raw_data.len());
        if start_byte >= raw_data.len() {
            return Vec::new();
        }
        raw_data[start_byte..end_byte].to_vec()
    }

    pub fn format_value(value: &PdoValueType) -> String {
        match value {
            PdoValueType::Bool(v) => if *v { "true" } else { "false" }.to_string(),
            PdoValueType::Int8(v) => format!("{}", v),
            PdoValueType::Int16(v) => format!("{}", v),
            PdoValueType::Int32(v) => format!("{}", v),
            PdoValueType::Int64(v) => format!("{}", v),
            PdoValueType::Uint8(v) => format!("{}", v),
            PdoValueType::Uint16(v) => format!("{}", v),
            PdoValueType::Uint32(v) => format!("{}", v),
            PdoValueType::Uint64(v) => format!("{}", v),
            PdoValueType::Float(v) => format!("{:.6}", v),
            PdoValueType::Double(v) => format!("{:.10}", v),
            PdoValueType::Bytes(b) => hex::encode(b),
            PdoValueType::String(s) => s.clone(),
            PdoValueType::State(s) => s.to_str().to_string(),
        }
    }

    pub fn enhance_datagram(&self, dg: &mut ParsedDatagram) {
        if let Some(pdo) = dg.pdo.take() {
            let converted = self.convert_pdo_data(pdo.slave_id, pdo.pdo_index, &dg.data);
            dg.pdo = Some(converted);
        }
        if dg.header.register_offset == crate::AL_STATUS_REG && dg.data.len() >= 2 {
            let state = StateMachineState::from_u8(dg.data[0]);
            if dg.pdo.is_none() {
                dg.pdo = Some(PdoData {
                    slave_id: dg.header.slave_address,
                    pdo_index: crate::AL_STATUS_REG,
                    entries: HashMap::new(),
                });
            }
            if let Some(ref mut pdo) = dg.pdo {
                let reg = RegisterValue {
                    index: crate::AL_STATUS_REG,
                    subindex: 0,
                    name: Some("AL Status".to_string()),
                    description: Some("Application Layer State Machine Status".to_string()),
                    unit: None,
                    raw_bytes: dg.data[..2.min(dg.data.len())].to_vec(),
                    value: PdoValueType::State(state),
                    business_comment: None,
                };
                pdo.entries.insert(crate::AL_STATUS_REG, reg);
            }
        }
    }
}

impl Default for PdoConverter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_template_json() -> &'static str {
        r#"
{
  "version": "1.0",
  "production_line": "Line-A",
  "description": "Assembly Line A register mapping",
  "slaves": [
    {
      "slave_id": 1,
      "device_name": "Servo-Drive-X1",
      "vendor_id": 42,
      "product_code": 1001,
      "registers": [
        {
          "index": 28672,
          "subindex": 1,
          "name": "Target_Position",
          "description": "Motor target position in counts",
          "data_type": "int32",
          "unit": "count",
          "business_comment": "X-axis servo position command"
        },
        {
          "index": 28672,
          "subindex": 2,
          "name": "Actual_Velocity",
          "description": "Actual motor velocity",
          "data_type": "int16",
          "unit": "rpm",
          "business_comment": "X-axis current velocity"
        }
      ]
    }
  ]
}
"#
    }

    #[test]
    fn test_load_template() {
        let mut conv = PdoConverter::new();
        conv.load_template_from_str(sample_template_json()).unwrap();
        assert_eq!(conv.get_template().unwrap().production_line, "Line-A");
        assert_eq!(conv.get_slave_device_name(1), Some("Servo-Drive-X1"));
    }

    #[test]
    fn test_convert_pdo_with_template() {
        let mut conv = PdoConverter::new();
        conv.load_template_from_str(sample_template_json()).unwrap();
        let mut raw = vec![0u8; 6];
        raw[0] = 0x78;
        raw[1] = 0x56;
        raw[2] = 0x34;
        raw[3] = 0x12;
        raw[4] = 0x20;
        raw[5] = 0x4e;
        let pdo = conv.convert_pdo_data(1, 0x1600, &raw);
        assert_eq!(pdo.slave_id, 1);
        assert!(pdo.entries.len() >= 2);
        let key1 = ((0x7000u32) << 8) | 1;
        if let Some(entry) = pdo.entries.get(&(key1 as u16)) {
            assert_eq!(entry.name.as_deref(), Some("Target_Position"));
            if let PdoValueType::Int32(v) = entry.value {
                assert_eq!(v, 0x12345678);
            } else {
                panic!("Expected Int32");
            }
        }
    }

    #[test]
    fn test_value_formatting() {
        assert_eq!(PdoConverter::format_value(&PdoValueType::Bool(true)), "true");
        assert_eq!(PdoConverter::format_value(&PdoValueType::Int32(42)), "42");
        assert_eq!(PdoConverter::format_value(&PdoValueType::State(StateMachineState::Op)), "OP");
    }
}
