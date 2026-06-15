use clap::Parser;
use ethercat_parser::*;
use std::io::Write;
use std::process::ExitCode;
use std::sync::Arc;

mod lib;
use lib::*;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {:#}", e);
            ExitCode::FAILURE
        }
    }
}

fn run() -> anyhow::Result<()> {
    let args = cli::CliArgs::parse();
    match args.command {
        cli::Commands::Parse(parse_args) => cmd_parse(parse_args),
        cli::Commands::Template(tpl_args) => cmd_template(tpl_args),
        cli::Commands::Generate(gen_args) => cmd_generate(gen_args),
        cli::Commands::Live(live_args) => cmd_live(live_args),
    }
}

fn cmd_live(args: cli::LiveArgs) -> anyhow::Result<()> {
    match args.action {
        cli::LiveAction::List => cmd_live_list(),
        cli::LiveAction::Capture(cap_args) => cmd_live_capture(cap_args),
    }
}

fn cmd_live_list() -> anyhow::Result<()> {
    let interfaces = live_capture::list_interfaces()?;
    if interfaces.is_empty() {
        println!("No network interfaces found. Ensure you have sufficient privileges (root/Administrator) and libpcap/WinPcap/Npcap is installed.");
        return Ok(());
    }
    println!("Available network interfaces:\n");
    for (i, iface) in interfaces.iter().enumerate() {
        let status = if iface.is_up && iface.is_running {
            "\x1b[32m[UP]\x1b[0m".to_string()
        } else if iface.is_up {
            "\x1b[33m[UP-not-running]\x1b[0m".to_string()
        } else {
            "\x1b[31m[DOWN]\x1b[0m".to_string()
        };
        println!("  [{}] {}  {}", i, status, iface.name);
        if let Some(desc) = &iface.description {
            println!("      Description: {}", desc);
        }
        for addr in &iface.addresses {
            println!("      Address:     {}", addr);
        }
        println!();
    }
    println!("Usage: ethercat-parser live capture -i <interface_name> [options]");
    Ok(())
}

fn cmd_live_capture(args: cli::LiveCaptureArgs) -> anyhow::Result<()> {
    use colored::*;
    use live_capture::LoopControl;
    use std::cell::RefCell;
    use std::time::Duration;

    let mut converter = pdo_converter::PdoConverter::new();
    if let Some(tpl_path) = &args.template {
        converter.load_template(tpl_path)?;
        if args.verbose >= 1 {
            if let Some(tpl) = converter.get_template() {
                let mut tmp = output::OutputFormatter::new(
                    cli::OutputFormat::Pretty,
                    args.no_color,
                    None,
                )?;
                tmp.print_template_preview(tpl)?;
            }
        }
    }

    let filter = cli::build_live_filter_options(&args);
    let errors_only = args.errors_only;
    let mut formatter =
        output::OutputFormatter::new(args.format, args.no_color, args.output_file.clone())?;
    formatter.print_csv_header()?;
    let stats = RefCell::new(ParseStats::default());
    let frames_parsed = RefCell::new(0u64);
    let limit = args.limit.unwrap_or(0);
    let collected_frames = RefCell::new(Vec::<EthercatFrame>::new());

    let cap_opts = cli::live_capture_to_capture_opts(&args);
    let mut capture = live_capture::LiveCapture::new(&cap_opts)?;
    if let Some(pcap_path) = &args.save_pcap {
        capture.enable_savefile(pcap_path)?;
        println!(
            "{} {}",
            if args.no_color { "[INFO]".to_string() } else { "[INFO]".cyan().to_string() },
            format!("Saving raw packets to: {}", pcap_path.display())
        );
    }

    let stop_flag = capture.set_stop_flag();
    live_capture::register_stop_signal(Arc::clone(&stop_flag));

    let stats_interval = if args.stats_interval_ms > 0 {
        Duration::from_millis(args.stats_interval_ms)
    } else {
        Duration::from_secs(u64::MAX)
    };

    let no_color = args.no_color;
    let verbose = args.verbose;
    let json_output_file = matches!(args.format, cli::OutputFormat::Json) && args.output_file.is_some();

    println!(
        "{}",
        if no_color {
            format!("Starting live capture on '{}'... Press Ctrl+C to stop.", args.interface)
        } else {
            format!("{} '{}'... Press Ctrl+C to stop.",
                "🔴 Capturing on".green().bold(),
                args.interface.bold()
            )
        }
    );

    let result = live_capture::capture_loop(
        capture,
        |raw| {
            let mut parsed = match ethercat_parser::parse_ethercat_frame(&raw) {
                Ok(f) => f,
                Err(e) => {
                    if verbose >= 2 {
                        eprintln!("Warning: skipping malformed frame: {}", e);
                    }
                    return Ok(LoopControl::Continue);
                }
            };

            for dg in parsed.datagrams.iter_mut() {
                converter.enhance_datagram(dg);
            }

            let mut stats_ref = stats.borrow_mut();
            update_stats(&mut stats_ref, &parsed);
            drop(stats_ref);

            let filtered = if errors_only {
                let has_error = parsed
                    .datagrams
                    .iter()
                    .any(|d| d.is_fault || d.mailbox.as_ref().and_then(|m| m.sdo.as_ref()).map(|s| s.error_code.is_some()).unwrap_or(false));
                if !has_error {
                    None
                } else {
                    filter.filter_frame(parsed)
                }
            } else {
                filter.filter_frame(parsed)
            };

            if let Some(frame) = filtered {
                if json_output_file {
                    collected_frames.borrow_mut().push(frame);
                } else {
                    formatter.print_frame(&frame, &converter)?;
                }
                let mut fp = frames_parsed.borrow_mut();
                *fp += 1;
                if limit > 0 && *fp >= limit {
                    stop_flag.store(true, Ordering::Relaxed);
                    return Ok(LoopControl::Break);
                }
            }
            Ok(LoopControl::Continue)
        },
        stats_interval,
        |s: &live_capture::LiveStats| {
            if verbose >= 1 {
                eprintln!(
                    "{}  rx={}  ec={}  filtered={}  dropped={}  parse_errors={}",
                    if no_color { "[STATS]".to_string() } else { "[STATS]".cyan().bold().to_string() },
                    s.received,
                    s.ethercat_frames,
                    s.filtered_count,
                    s.dropped,
                    s.parse_errors
                );
            }
        },
    );

    match result {
        Ok(final_stats) => {
            let collected = collected_frames.into_inner();
            if !collected.is_empty() {
                formatter.print_json_array(&collected)?;
            }
            if matches!(args.format, cli::OutputFormat::Summary | cli::OutputFormat::Pretty) || verbose >= 1 {
                let final_parse_stats = stats.into_inner();
                formatter.print_summary(&final_parse_stats)?;
                println!(
                    "\n{}  received={}  ethercat_frames={}  dropped={}  if_dropped={}  parse_errors={}",
                    if no_color { "Capture stopped.".to_string() } else { "🛑 Capture stopped.".yellow().bold().to_string() },
                    final_stats.received,
                    final_stats.ethercat_frames,
                    final_stats.dropped,
                    final_stats.if_dropped,
                    final_stats.parse_errors
                );
            }
            Ok(())
        }
        Err(e) => Err(e),
    }
}

fn cmd_parse(args: cli::ParseArgs) -> anyhow::Result<()> {
    let source = match &args.input {
        Some(p) if p.to_string_lossy() == "-" => io_reader::InputSource::Stdin,
        Some(p) => io_reader::InputSource::File(p.to_string_lossy().to_string()),
        None => io_reader::InputSource::Stdin,
    };
    let mut reader = io_reader::create_reader(&source)?;
    let mut converter = pdo_converter::PdoConverter::new();
    if let Some(tpl_path) = &args.template {
        converter.load_template(tpl_path)?;
        if args.verbose >= 1 {
            if let Some(tpl) = converter.get_template() {
                let mut tmp = output::OutputFormatter::new(
                    cli::OutputFormat::Pretty,
                    args.no_color,
                    None,
                )?;
                tmp.print_template_preview(tpl)?;
            }
        }
    }
    let filter = cli::build_filter_options(&args);
    let errors_only = args.errors_only;
    let mut formatter =
        output::OutputFormatter::new(args.format, args.no_color, args.output_file.clone())?;
    formatter.print_csv_header()?;
    let mut stats = ParseStats::default();
    let mut frames_parsed: u64 = 0;
    let limit = args.limit.unwrap_or(0);
    let mut collected_frames: Vec<EthercatFrame> = if matches!(args.format, cli::OutputFormat::Json) && args.output_file.is_some() {
        Vec::new()
    } else {
        Vec::new()
    };
    while let Some(raw_frame) = reader.read_next_frame()? {
        let mut parsed = match ethercat_parser::parse_ethercat_frame(&raw_frame) {
            Ok(f) => f,
            Err(e) => {
                if args.verbose >= 2 {
                    eprintln!("Warning: skipping malformed frame: {}", e);
                }
                continue;
            }
        };
        for dg in parsed.datagrams.iter_mut() {
            converter.enhance_datagram(dg);
        }
        update_stats(&mut stats, &parsed);
        let filtered = if errors_only {
            let has_error = parsed
                .datagrams
                .iter()
                .any(|d| d.is_fault || d.mailbox.as_ref().and_then(|m| m.sdo.as_ref()).map(|s| s.error_code.is_some()).unwrap_or(false));
            if !has_error {
                None
            } else {
                filter.filter_frame(parsed)
            }
        } else {
            filter.filter_frame(parsed)
        };
        if let Some(frame) = filtered {
            if matches!(args.format, cli::OutputFormat::Json) && args.output_file.is_some() {
                collected_frames.push(frame);
            } else {
                formatter.print_frame(&frame, &converter)?;
            }
            frames_parsed += 1;
            if limit > 0 && frames_parsed >= limit {
                break;
            }
        }
    }
    if !collected_frames.is_empty() {
        formatter.print_json_array(&collected_frames)?;
    }
    if matches!(args.format, cli::OutputFormat::Summary | cli::OutputFormat::Pretty) || args.verbose >= 1 {
        formatter.print_summary(&stats)?;
    }
    Ok(())
}

fn cmd_template(args: cli::TemplateArgs) -> anyhow::Result<()> {
    let slaves: Vec<TemplateSlave> = (1..=args.slave_count)
        .map(|id| TemplateSlave {
            slave_id: id as u16,
            device_name: format!("Slave-Device-{}", id),
            vendor_id: 0x00000002 + (id as u32),
            product_code: 0x1000 + (id as u32),
            registers: vec![
                TemplateRegister {
                    index: 0x7000,
                    subindex: 1,
                    name: format!("Control_Word_S{}", id),
                    description: "DS402 control word".to_string(),
                    data_type: "uint16".to_string(),
                    unit: None,
                    business_comment: Some(format!("Motion controller control word for station {}", id)),
                },
                TemplateRegister {
                    index: 0x7000,
                    subindex: 2,
                    name: format!("Target_Position_S{}", id),
                    description: "Target position in encoder counts".to_string(),
                    data_type: "int32".to_string(),
                    unit: Some("count".to_string()),
                    business_comment: Some(format!("Axis {} position command, negative = reverse direction", id)),
                },
                TemplateRegister {
                    index: 0x7000,
                    subindex: 3,
                    name: format!("Target_Velocity_S{}", id),
                    description: "Target velocity".to_string(),
                    data_type: "int32".to_string(),
                    unit: Some("rpm".to_string()),
                    business_comment: None,
                },
                TemplateRegister {
                    index: 0x7010,
                    subindex: 1,
                    name: format!("Status_Word_S{}", id),
                    description: "DS402 status word".to_string(),
                    data_type: "uint16".to_string(),
                    unit: None,
                    business_comment: Some(format!("Axis {} status, bit 0 = Ready to switch on", id)),
                },
                TemplateRegister {
                    index: 0x7010,
                    subindex: 2,
                    name: format!("Actual_Position_S{}", id),
                    description: "Actual encoder position".to_string(),
                    data_type: "int32".to_string(),
                    unit: Some("count".to_string()),
                    business_comment: None,
                },
                TemplateRegister {
                    index: 0x7010,
                    subindex: 3,
                    name: format!("Actual_Velocity_S{}", id),
                    description: "Actual motor velocity".to_string(),
                    data_type: "int32".to_string(),
                    unit: Some("rpm".to_string()),
                    business_comment: None,
                },
                TemplateRegister {
                    index: 0x7020,
                    subindex: 1,
                    name: format!("Digital_Inputs_S{}", id),
                    description: "DI bitmask".to_string(),
                    data_type: "uint32".to_string(),
                    unit: None,
                    business_comment: Some("Conveyor sensors, emergency stop, door interlocks"),
                },
                TemplateRegister {
                    index: 0x7020,
                    subindex: 2,
                    name: format!("Digital_Outputs_S{}", id),
                    description: "DO bitmask".to_string(),
                    data_type: "uint32".to_string(),
                    unit: None,
                    business_comment: Some("Conveyor motors, valves, warning lights"),
                },
                TemplateRegister {
                    index: 0x7030,
                    subindex: 1,
                    name: format!("Analog_Input_1_S{}", id),
                    description: "Temperature sensor".to_string(),
                    data_type: "uint16".to_string(),
                    unit: Some("0.1°C".to_string()),
                    business_comment: Some("Motor winding temperature sensor, warn > 120°C"),
                },
                TemplateRegister {
                    index: 0x7030,
                    subindex: 2,
                    name: format!("Analog_Input_2_S{}", id),
                    description: "Pressure sensor".to_string(),
                    data_type: "uint16".to_string(),
                    unit: Some("kPa".to_string()),
                    business_comment: Some("Pneumatic system pressure, normal 500-700 kPa"),
                },
            ],
        })
        .collect();
    let tpl = ParseTemplate {
        version: "1.0".to_string(),
        production_line: "Production-Line-A".to_string(),
        description: "Auto-generated template for EtherCAT register-to-business mapping".to_string(),
        slaves,
    };
    let json = serde_json::to_string_pretty(&tpl)?;
    let mut file = std::fs::File::create(&args.output)
        .map_err(|e| anyhow::anyhow!("Cannot create template file {:?}: {}", args.output, e))?;
    file.write_all(json.as_bytes())?;
    println!(
        "Template generated: {} with {} slave entries",
        args.output.display(),
        args.slave_count
    );
    Ok(())
}

fn cmd_generate(args: cli::GenerateArgs) -> anyhow::Result<()> {
    use std::fs::File;
    use std::io::BufWriter;
    let mut writer = BufWriter::new(File::create(&args.output)?);
    let mut rng = rand::rng();
    let mut base_ts = 1_700_000_000_000_000_000u64;
    let fault_codes: Vec<u32> = vec![0x0011, 0x001A, 0x0027, 0x0030];
    for frame_idx in 0..args.frames {
        let mut frame = build_ethercat_frame(&mut rng, args.slaves, frame_idx, args.include_faults, &fault_codes);
        let frame_size = frame.len() as u32;
        writer.write_all(&frame_size.to_le_bytes())?;
        writer.write_all(&base_ts.to_le_bytes())?;
        writer.write_all(&frame)?;
        base_ts = base_ts.saturating_add(1_000_000);
    }
    writer.flush()?;
    println!(
        "Generated {} frames for {} slaves → {}",
        args.frames,
        args.slaves,
        args.output.display()
    );
    Ok(())
}

fn build_ethercat_frame<R: rand::Rng>(
    rng: &mut R,
    slaves: u16,
    frame_idx: u32,
    include_faults: bool,
    fault_codes: &[u32],
) -> Vec<u8> {
    let mut data = Vec::new();
    let mut eth_dest = [0u8; 6];
    let mut eth_src = [0u8; 6];
    rng.fill(&mut eth_dest[..]);
    rng.fill(&mut eth_src[..]);
    eth_dest[0] = 0x01;
    data.extend_from_slice(&eth_dest);
    data.extend_from_slice(&eth_src);
    data.extend_from_slice(&crate::ETHERCAT_ETHERTYPE.to_be_bytes());
    let mut datagrams: Vec<Vec<u8>> = Vec::new();
    let slave_range = 1u16..=slaves;
    let slave_list: Vec<u16> = slave_range.collect();
    let num_dg = slave_list.len();
    for (d_idx, &sid) in slave_list.iter().enumerate() {
        let is_last = d_idx + 1 == num_dg;
        let inject_fault = include_faults && frame_idx % 37 == 23 && sid == ((frame_idx % slaves as u32) as u16 + 1);
        datagrams.push(build_logical_read_write(
            rng,
            sid,
            frame_idx,
            d_idx as u8,
            inject_fault,
            fault_codes,
            is_last,
        ));
    }
    let total_payload: usize = datagrams.iter().map(|d| d.len()).sum();
    let mut ec = [0u8; 4];
    let ec_len = total_payload.min(0x07FF) as u16;
    ec[0] = (ec_len & 0xFF) as u8;
    ec[1] = ((ec_len >> 8) & 0x07) as u8;
    ec[2] = 0;
    ec[3] = (num_dg as u8) & 0x7F;
    data.extend_from_slice(&ec);
    for dg in datagrams {
        data.extend(dg);
    }
    data
}

fn build_logical_read_write<R: rand::Rng>(
    rng: &mut R,
    slave_id: u16,
    frame_idx: u32,
    dg_idx: u8,
    inject_fault: bool,
    fault_codes: &[u32],
    is_last: bool,
) -> Vec<u8> {
    let mut dg = Vec::new();
    dg.push(0x0C);
    dg.push(dg_idx);
    dg.extend_from_slice(&slave_id.to_le_bytes());
    let reg_offset: u16 = if inject_fault { crate::AL_ERROR_CODE_REG } else { 0x0010 };
    dg.extend_from_slice(&reg_offset.to_le_bytes());
    let payload_len: u16 = if inject_fault { 4 } else { 12 };
    let next_flag: u16 = if is_last { 0 } else { 1 << 15 };
    let len_flags: u16 = payload_len | next_flag;
    dg.extend_from_slice(&len_flags.to_le_bytes());
    let irq: u16 = if is_last { 0x0001 } else { 0x0000 };
    dg.extend_from_slice(&irq.to_le_bytes());
    if inject_fault {
        let code = fault_codes[(frame_idx as usize) % fault_codes.len()];
        dg.extend_from_slice(&code.to_le_bytes());
    } else {
        let pos = (frame_idx as i32) * 100 + (slave_id as i32) * 50;
        dg.extend_from_slice(&pos.to_le_bytes());
        let vel: i16 = ((frame_idx as i16) % 1000) + (slave_id as i16) * 10;
        dg.extend_from_slice(&vel.to_le_bytes());
        let di: u16 = 0xFF00 | (slave_id as u16);
        dg.extend_from_slice(&di.to_le_bytes());
    }
    let wc: u16 = rng.random_range(1u16..=8u16);
    dg.extend_from_slice(&wc.to_le_bytes());
    dg
}
