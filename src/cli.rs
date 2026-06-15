use crate::*;
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Json,
    Table,
    Csv,
    Summary,
    Pretty,
}

#[derive(Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum MailboxTypeArg {
    CoE,
    FoE,
    EoE,
    SoE,
    AoE,
    VoE,
}

impl MailboxTypeArg {
    pub fn to_mailbox_type(&self) -> MailboxType {
        match self {
            MailboxTypeArg::CoE => MailboxType::CoE,
            MailboxTypeArg::FoE => MailboxType::FoE,
            MailboxTypeArg::EoE => MailboxType::EoE,
            MailboxTypeArg::SoE => MailboxType::SoE,
            MailboxTypeArg::AoE => MailboxType::AoE,
            MailboxTypeArg::VoE => MailboxType::VOE,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum CommandTypeArg {
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
}

impl CommandTypeArg {
    pub fn to_ethercat_command(&self) -> EthercatCommand {
        match self {
            CommandTypeArg::APRD => EthercatCommand::APRD,
            CommandTypeArg::APWR => EthercatCommand::APWR,
            CommandTypeArg::APRW => EthercatCommand::APRW,
            CommandTypeArg::FPRD => EthercatCommand::FPRD,
            CommandTypeArg::FPWR => EthercatCommand::FPWR,
            CommandTypeArg::FPRW => EthercatCommand::FPRW,
            CommandTypeArg::BRD => EthercatCommand::BRD,
            CommandTypeArg::BWR => EthercatCommand::BWR,
            CommandTypeArg::BRW => EthercatCommand::BRW,
            CommandTypeArg::LRD => EthercatCommand::LRD,
            CommandTypeArg::LWR => EthercatCommand::LWR,
            CommandTypeArg::LRW => EthercatCommand::LRW,
            CommandTypeArg::ARMW => EthercatCommand::ARMW,
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "ethercat-parser",
    version = "1.0.0",
    about = "EtherCAT packet parser for industrial automation production line maintenance",
    long_about = "Parses EtherCAT binary capture logs, extracts slave addresses, register R/W, state machine transitions, and fault codes.\nSupports CoE/FoE/EoE mailbox sub-frames, PDO mapping with custom business templates, and CLI filtering."
)]
pub struct CliArgs {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    #[command(about = "Parse a capture file or stdin stream")]
    Parse(ParseArgs),
    #[command(about = "Generate an empty register template JSON file")]
    Template(TemplateArgs),
    #[command(about = "Generate a sample binary capture file for testing")]
    Generate(GenerateArgs),
}

#[derive(Parser, Debug)]
pub struct ParseArgs {
    #[arg(
        short,
        long,
        value_name = "FILE",
        help = "Input capture file (.pcap, .cap, or raw binary). Use '-' for stdin piping."
    )]
    pub input: Option<PathBuf>,

    #[arg(
        short = 't',
        long,
        value_name = "TEMPLATE",
        help = "Register mapping template JSON file (binds registers to business semantics)"
    )]
    pub template: Option<PathBuf>,

    #[arg(
        short = 'o',
        long,
        value_name = "FORMAT",
        default_value_t = OutputFormat::Pretty,
        help = "Output format: json, table, csv, summary, pretty"
    )]
    pub format: OutputFormat,

    #[arg(
        short = 'f',
        long,
        value_name = "OUTPUT_FILE",
        help = "Write output to file instead of stdout"
    )]
    pub output_file: Option<PathBuf>,

    #[arg(
        long = "slave-id",
        value_name = "ID",
        value_delimiter = ',',
        help = "Filter by slave address(es), comma-separated"
    )]
    pub slave_ids: Vec<u16>,

    #[arg(
        long = "msg-type",
        value_name = "TYPE",
        value_delimiter = ',',
        help = "Filter by mailbox message type: CoE,FoE,EoE,SoE,AoE,VoE"
    )]
    pub msg_types: Vec<MailboxTypeArg>,

    #[arg(
        long = "fault-code",
        value_name = "HEX",
        value_delimiter = ',',
        help = "Filter by AL fault code (hex, e.g. 0x0011,0x001A), comma-separated"
    )]
    pub fault_codes: Vec<String>,

    #[arg(
        long = "command",
        value_name = "CMD",
        value_delimiter = ',',
        help = "Filter by EtherCAT command type: LRW,APRD,FPRD,..."
    )]
    pub commands: Vec<CommandTypeArg>,

    #[arg(
        short = 'e',
        long = "errors-only",
        help = "Show only frames/datagrams containing faults or errors"
    )]
    pub errors_only: bool,

    #[arg(
        long = "no-color",
        help = "Disable ANSI color codes in output (for non-TTY environments)"
    )]
    pub no_color: bool,

    #[arg(
        long = "limit",
        value_name = "N",
        help = "Stop parsing after N frames (0 = unlimited)"
    )]
    pub limit: Option<u64>,

    #[arg(
        short = 'v',
        long = "verbose",
        action = clap::ArgAction::Count,
        help = "Increase verbosity (-v, -vv, -vvv)"
    )]
    pub verbose: u8,
}

#[derive(Parser, Debug)]
pub struct TemplateArgs {
    #[arg(
        short = 'o',
        long,
        value_name = "FILE",
        help = "Output template JSON file path"
    )]
    pub output: PathBuf,

    #[arg(
        short = 's',
        long = "slaves",
        default_value_t = 4,
        help = "Number of example slave entries to include"
    )]
    pub slave_count: u32,
}

#[derive(Parser, Debug)]
pub struct GenerateArgs {
    #[arg(
        short = 'o',
        long,
        value_name = "FILE",
        help = "Output sample binary capture file (raw format)"
    )]
    pub output: PathBuf,

    #[arg(
        short = 'n',
        long,
        default_value_t = 100,
        help = "Number of frames to generate"
    )]
    pub frames: u32,

    #[arg(
        long = "slaves",
        default_value_t = 5,
        help = "Number of simulated slave stations"
    )]
    pub slaves: u16,

    #[arg(
        long = "include-faults",
        help = "Inject simulated AL error frames"
    )]
    pub include_faults: bool,
}

pub fn parse_fault_codes(hex_strings: &[String]) -> Vec<u32> {
    hex_strings
        .iter()
        .filter_map(|s| {
            let s = s.trim().trim_start_matches("0x").trim_start_matches("0X");
            u32::from_str_radix(s, 16).ok()
        })
        .collect()
}

pub fn build_filter_options(args: &ParseArgs) -> ethercat_parser::FilterOptions {
    let mut opts = ethercat_parser::FilterOptions::new();
    opts.slave_ids = args.slave_ids.clone();
    opts.msg_types = args
        .msg_types
        .iter()
        .map(|t| t.to_mailbox_type())
        .collect();
    opts.fault_codes = parse_fault_codes(&args.fault_codes);
    opts.commands = args
        .commands
        .iter()
        .map(|c| c.to_ethercat_command())
        .collect();
    opts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_fault_codes() {
        let inputs = vec![
            "0x0011".to_string(),
            "0X001A".to_string(),
            "0xFFFF".to_string(),
        ];
        let result = parse_fault_codes(&inputs);
        assert_eq!(result, vec![0x0011, 0x001A, 0xFFFF]);
    }

    #[test]
    fn test_mailbox_type_arg() {
        assert_eq!(MailboxTypeArg::CoE.to_mailbox_type(), MailboxType::CoE);
        assert_eq!(MailboxTypeArg::FoE.to_mailbox_type(), MailboxType::FoE);
        assert_eq!(MailboxTypeArg::EoE.to_mailbox_type(), MailboxType::EoE);
    }

    #[test]
    fn test_command_type_arg() {
        assert_eq!(CommandTypeArg::LRW.to_ethercat_command(), EthercatCommand::LRW);
        assert_eq!(CommandTypeArg::APRD.to_ethercat_command(), EthercatCommand::APRD);
    }
}
