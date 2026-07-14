#![forbid(unsafe_code)]

use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use xbedump::{DumpOptions, KeyKind, RepairOptions, ValidationReport, Xbe};

const USAGE: &str = "\
Usage: xbe [xbefile] [options]

  -da          Dumps the complete XBE Header Structure
  -dh          Dumps the Header info
  -dc          Dumps the Certificate
  -ds          Dumps the Sections
  -dl          Dumps the Library Sections

  -vh          Verifies the .xbe Header
  -wb          Writes back the update to file out.xbe

  -sm          Uses Microsoft Signature (default mode)
               (Note: Signing not possible, as we do not have the private key)
  -shabibi     Uses the Habibi Signature Keys
  -st          Uses the historical test keys and leaves the XOR unchanged

  -d1          Debug output for option -vh

  ---- Special Options -----

  -habibi      Signs with the Habibi key and sets all media flags
  -sign        Signs with the historical test key and patches the XOR keys
  -xbgs        Dumps xbgs output
  ?            Display Help

XBE Dumper 0.5, rewritten in safe Rust.
";

#[derive(Default)]
struct Cli {
    file: PathBuf,
    dump: DumpOptions,
    validate: bool,
    write_back: bool,
    debug: bool,
    patch_xor_keys: bool,
    allow_all_media_and_regions: bool,
    generate_signature: bool,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("xbe: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    if args.len() == 1 && args[0] == "--test" {
        return Ok(());
    }
    if args.len() < 2 || args.iter().any(|arg| arg == "?") {
        print!("{USAGE}");
        return Ok(());
    }

    let mut cli = Cli {
        file: PathBuf::from(&args[0]),
        ..Cli::default()
    };
    for argument in &args[1..] {
        let argument = argument.to_string_lossy();
        match argument.as_ref() {
            "-da" => {
                cli.dump.header = true;
                cli.dump.certificate = true;
                cli.dump.sections = true;
                cli.dump.libraries = true;
            }
            "-dh" => cli.dump.header = true,
            "-dc" => cli.dump.certificate = true,
            "-ds" => cli.dump.sections = true,
            "-dl" => cli.dump.libraries = true,
            "-xbgs" => cli.dump.xbgs = true,
            "-sm" => cli.dump.key = KeyKind::Microsoft,
            "-st" => cli.dump.key = KeyKind::Test,
            "-shabibi" => cli.dump.key = KeyKind::Habibi,
            "-vh" => cli.validate = true,
            "-wb" => {
                cli.validate = true;
                cli.write_back = true;
            }
            "-d1" => cli.debug = true,
            "-sign" => {
                cli.dump.header = false;
                cli.dump.certificate = false;
                cli.dump.sections = false;
                cli.dump.libraries = false;
                cli.dump.xbgs = false;
                cli.validate = true;
                cli.write_back = true;
                cli.patch_xor_keys = true;
                cli.generate_signature = true;
                cli.dump.key = KeyKind::Test;
            }
            "-habibi" => {
                cli.dump.header = false;
                cli.dump.certificate = false;
                cli.dump.sections = false;
                cli.dump.libraries = false;
                cli.dump.xbgs = false;
                cli.validate = true;
                cli.write_back = true;
                cli.patch_xor_keys = true;
                cli.allow_all_media_and_regions = true;
                cli.generate_signature = true;
                cli.dump.key = KeyKind::Habibi;
            }
            unknown => return Err(format!("unknown option {unknown:?}\n\n{USAGE}").into()),
        }
    }

    let bytes = fs::read(&cli.file)?;
    let mut xbe = Xbe::parse(bytes)?;
    if !cli.dump.xbgs {
        println!("XBE Dumper 0.5-BETA Release");
        match cli.dump.key {
            KeyKind::Microsoft => {}
            KeyKind::Test => println!("Using Linux Test Keys"),
            KeyKind::Habibi => println!("Using Habibi Keys"),
        }
    }

    if cli.dump.header
        || cli.dump.certificate
        || cli.dump.sections
        || cli.dump.libraries
        || cli.dump.xbgs
    {
        print!("{}", xbe.dump(&cli.dump)?);
    }

    if cli.validate {
        let report = if cli.write_back {
            let report = xbe.repair(RepairOptions {
                key: cli.dump.key,
                patch_xor_keys: cli.patch_xor_keys,
                allow_all_media_and_regions: cli.allow_all_media_and_regions,
                generate_signature: cli.generate_signature,
            })?;
            fs::write("out.xbe", xbe.as_bytes())?;
            println!("\nFile out.xbe created, verifying it ...\n");
            report
        } else {
            xbe.validate(cli.dump.key)?
        };
        print_report(&report, cli.debug);
    }
    Ok(())
}

fn print_report(report: &ValidationReport, debug: bool) {
    for check in &report.checks {
        println!(
            "{:<24}{}",
            format!("{}:", check.name),
            if check.passed { "pass" } else { "fail" }
        );
        if debug && !check.passed {
            if let Some(actual) = &check.actual {
                println!("             in File -> {actual}");
            }
            if let Some(expected) = &check.expected {
                println!("           should be -> {expected}");
            }
        }
    }
    println!(
        "\nXBE file integrity:    {}",
        if report.is_valid() {
            "OK"
        } else {
            "FALSE !!!!!!! FALSE !!!!!"
        }
    );
}
