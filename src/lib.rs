pub mod io_reader;
pub mod ethercat_parser;
pub mod pdo_converter;
pub mod cli;
pub mod output;
pub mod live_capture;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EthercatCommand {
    NoOp,
    APRD,
    APWR,
    APRW,
    FPRD,
    FPWR,
    FPRW,
    BRD,
    BWR,
    BRW,
    LRD,
    LWR,
    LRW,
    ARMW,
    Unknown(u8),
}

impl EthercatCommand {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0x00 => EthercatCommand::NoOp,
            0x01 => EthercatCommand::APRD,
            0x02 => EthercatCommand::APWR,
            0x03 => EthercatCommand::APRW,
            0x04 => EthercatCommand::FPRD,
            0x05 => EthercatCommand::FPWR,
            0x06 => EthercatCommand::FPRW,
            0x07 => EthercatCommand::BRD,
            0x08 => EthercatCommand::BWR,
            0x09 => EthercatCommand::BRW,
            0x0A => EthercatCommand::LRD,
            0x0B => EthercatCommand::LWR,
            0x0C => EthercatCommand::LRW,
            0x0D => EthercatCommand::ARMW,
            other => EthercatCommand::Unknown(other),
        }
    }

    pub fn to_str(&self) -> &'static str {
        match self {
            EthercatCommand::NoOp => "NoOp",
            EthercatCommand::APRD => "APRD",
            EthercatCommand::APWR => "APWR",
            EthercatCommand::APRW => "APRW",
            EthercatCommand::FPRD => "FPRD",
            EthercatCommand::FPWR => "FPWR",
            EthercatCommand::FPRW => "FPRW",
            EthercatCommand::BRD => "BRD",
            EthercatCommand::BWR => "BWR",
            EthercatCommand::BRW => "BRW",
            EthercatCommand::LRD => "LRD",
            EthercatCommand::LWR => "LWR",
            EthercatCommand::LRW => "LRW",
            EthercatCommand::ARMW => "ARMW",
            EthercatCommand::Unknown(_) => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MailboxType {
    CoE,
    FoE,
    EoE,
    SoE,
    AoE,
    VOE,
    Unknown(u8),
}

impl MailboxType {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0x03 => MailboxType::CoE,
            0x05 => MailboxType::FoE,
            0x02 => MailboxType::EoE,
            0x04 => MailboxType::SoE,
            0x06 => MailboxType::AoE,
            0x07 => MailboxType::VOE,
            other => MailboxType::Unknown(other),
        }
    }

    pub fn to_str(&self) -> &'static str {
        match self {
            MailboxType::CoE => "CoE",
            MailboxType::FoE => "FoE",
            MailboxType::EoE => "EoE",
            MailboxType::SoE => "SoE",
            MailboxType::AoE => "AoE",
            MailboxType::VOE => "VoE",
            MailboxType::Unknown(_) => "Unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StateMachineState {
    Init,
    PreOp,
    SafeOp,
    Op,
    Unknown(u8),
}

impl StateMachineState {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0x01 => StateMachineState::Init,
            0x02 => StateMachineState::PreOp,
            0x04 => StateMachineState::SafeOp,
            0x08 => StateMachineState::Op,
            other => StateMachineState::Unknown(other),
        }
    }

    pub fn to_str(&self) -> &'static str {
        match self {
            StateMachineState::Init => "INIT",
            StateMachineState::PreOp => "PRE-OP",
            StateMachineState::SafeOp => "SAFE-OP",
            StateMachineState::Op => "OP",
            StateMachineState::Unknown(_) => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatagramHeader {
    pub command: EthercatCommand,
    pub index: u8,
    pub slave_address: u16,
    pub register_offset: u16,
    pub data_length: u16,
    pub circulating: bool,
    pub next: bool,
    pub irq: u16,
    pub working_counter: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdoAccess {
    pub index: u16,
    pub subindex: u8,
    pub request: bool,
    pub data: Vec<u8>,
    pub completed: bool,
    pub error_code: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailboxMessage {
    pub station_address: u16,
    pub channel: u8,
    pub priority: u8,
    pub msg_type: MailboxType,
    pub counter: u8,
    pub payload: Vec<u8>,
    pub sdo: Option<SdoAccess>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdoData {
    pub slave_id: u16,
    pub pdo_index: u16,
    pub entries: HashMap<u16, RegisterValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterValue {
    pub index: u16,
    pub subindex: u8,
    pub name: Option<String>,
    pub description: Option<String>,
    pub unit: Option<String>,
    pub raw_bytes: Vec<u8>,
    pub value: PdoValueType,
    pub business_comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PdoValueType {
    Bool(bool),
    Int8(i8),
    Int16(i16),
    Int32(i32),
    Int64(i64),
    Uint8(u8),
    Uint16(u16),
    Uint32(u32),
    Uint64(u64),
    Float(f32),
    Double(f64),
    Bytes(Vec<u8>),
    String(String),
    State(StateMachineState),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedDatagram {
    pub header: DatagramHeader,
    pub data: Vec<u8>,
    pub mailbox: Option<MailboxMessage>,
    pub pdo: Option<PdoData>,
    pub is_fault: bool,
    pub fault_code: Option<u32>,
    pub fault_description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthercatFrame {
    pub timestamp_ns: u64,
    pub frame_length: usize,
    pub ethernet_dest: [u8; 6],
    pub ethernet_src: [u8; 6],
    pub ethertype: u16,
    pub datagrams: Vec<ParsedDatagram>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateRegister {
    pub index: u16,
    pub subindex: u8,
    pub name: String,
    pub description: String,
    pub data_type: String,
    pub unit: Option<String>,
    pub business_comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateSlave {
    pub slave_id: u16,
    pub device_name: String,
    pub vendor_id: u32,
    pub product_code: u32,
    pub registers: Vec<TemplateRegister>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParseTemplate {
    pub version: String,
    pub production_line: String,
    pub description: String,
    pub slaves: Vec<TemplateSlave>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParseStats {
    pub total_frames: u64,
    pub total_datagrams: u64,
    pub coe_messages: u64,
    pub foe_messages: u64,
    pub eoe_messages: u64,
    pub pdo_updates: u64,
    pub fault_count: u64,
    pub slave_counts: HashMap<u16, u64>,
}

impl Default for ParseStats {
    fn default() -> Self {
        ParseStats {
            total_frames: 0,
            total_datagrams: 0,
            coe_messages: 0,
            foe_messages: 0,
            eoe_messages: 0,
            pdo_updates: 0,
            fault_count: 0,
            slave_counts: HashMap::new(),
        }
    }
}

pub const ETHERCAT_ETHERTYPE: u16 = 0x88A4;
pub const COE_SDO_REQUEST: u8 = 0x01;
pub const COE_SDO_RESPONSE: u8 = 0x02;
pub const AL_STATUS_REG: u16 = 0x0130;
pub const AL_CONTROL_REG: u16 = 0x0120;
pub const AL_ERROR_CODE_REG: u16 = 0x0134;
