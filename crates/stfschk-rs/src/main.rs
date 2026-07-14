use std::{
    env, fs,
    io::{self, IsTerminal as _},
    path::{Path, PathBuf},
    process::ExitCode,
};

use stfschk::{Error, StfsPackage, VERSION, is_package};

fn main() -> ExitCode {
    println!("STFS filesystem checker/verifier {VERSION}, by emoose");
    println!();

    let mut include_headers = false;
    let mut path = None;
    for argument in env::args_os().skip(1) {
        if argument == "-h" {
            include_headers = true;
        } else {
            path = Some(PathBuf::from(argument));
        }
    }

    let Some(path) = path else {
        print_usage();
        return ExitCode::SUCCESS;
    };
    if !path.exists() {
        println!("Invalid path {}!", path.display());
        return ExitCode::FAILURE;
    }

    if path.is_dir() {
        match process_directory(&path, include_headers) {
            Ok(all_valid) if all_valid => ExitCode::SUCCESS,
            Ok(_) | Err(_) => ExitCode::FAILURE,
        }
    } else {
        let valid = match process_file(&path, include_headers) {
            Ok(Some((package, report))) => {
                print!("{}", package.render_report(&report, include_headers));
                println!();
                if report.valid {
                    println!("No major errors detected.");
                } else {
                    println!("Errors found, file may be invalid!");
                }
                report.valid
            }
            Ok(None) => {
                println!("Errors found, file may be invalid!");
                false
            }
            Err(error) => {
                println!("{error}");
                println!();
                println!("Errors found, file may be invalid!");
                false
            }
        };
        println!();
        println!("Press any key to exit...");
        if io::stdin().is_terminal() {
            let mut line = String::new();
            let _ = io::stdin().read_line(&mut line);
        }
        if valid {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        }
    }
}

fn print_usage() {
    println!("Usage:");
    println!("  stfschk.exe [-h] <path\\to\\package.file>");
    println!("-h flag will include STFS headers in summary");
    println!();
    println!("Batch mode:");
    println!("  stfschk.exe [-h] <path\\to\\folder>");
    println!();
    println!(
        "Batch mode checks all packages in a folder, creating a <filename>.bad file for packages detected as bad"
    );
    println!("The .bad file contains info about why the file was marked as bad");
    println!(
        "Only files with valid XContent magic signature CON/LIVE/PIRS are checked when using batch mode"
    );
}

fn process_directory(path: &Path, include_headers: bool) -> Result<bool, Error> {
    let mut entries = fs::read_dir(path)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.path());
    let mut all_valid = true;
    for entry in entries {
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            all_valid &= process_directory(&entry.path(), include_headers)?;
        } else if file_type.is_file() {
            let file_path = entry.path();
            match process_file(&file_path, include_headers) {
                Ok(Some((package, report))) if !report.valid => {
                    fs::write(
                        bad_path(&file_path),
                        package.render_report(&report, include_headers),
                    )?;
                    all_valid = false;
                }
                Ok(_) => {}
                Err(error) => {
                    fs::write(bad_path(&file_path), format!("{error}\n"))?;
                    all_valid = false;
                }
            }
        }
    }
    Ok(all_valid)
}

fn process_file(
    path: &Path,
    _include_headers: bool,
) -> Result<Option<(StfsPackage, stfschk::VerificationReport)>, Error> {
    let data = fs::read(path)?;
    if !is_package(&data) {
        return Ok(None);
    }
    println!("Checking file {}", path.display());
    println!();
    let package = StfsPackage::parse(data)?;
    let report = package.verify()?;
    Ok(Some((package, report)))
}

fn bad_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(".bad");
    PathBuf::from(value)
}
