// SPDX-FileCopyrightText: Copyright 2026 Aspenini (orbis-unpkg)
// SPDX-License-Identifier: GPL-2.0-or-later

//! Small, dependency-free command-line front-end for `orbis_unpkg`.

use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use orbis_unpkg::{FileType, Pkg, PkgCategory, Psf, detect_file_type};

#[derive(Debug)]
enum Action {
    Extract {
        file: PathBuf,
        output: Option<PathBuf>,
        quiet: bool,
        wait: bool,
    },
    Info {
        file: PathBuf,
    },
    CheckType {
        file: PathBuf,
        quiet: bool,
    },
    Install {
        source: PathBuf,
        games_dir: PathBuf,
        addons_dir: PathBuf,
        quiet: bool,
    },
}

enum Parsed {
    Run(Action),
    Help(Option<&'static str>),
    Version,
}

fn main() -> ExitCode {
    let args = env::args_os().skip(1).collect::<Vec<_>>();
    match parse_args(&args) {
        Ok(Parsed::Run(action)) => {
            let wait = matches!(&action, Action::Extract { wait: true, .. });
            let code = dispatch(action);
            if wait && std::io::stdin().is_terminal() {
                eprint!("\nPress Enter to exit...");
                let _ = std::io::stderr().flush();
                let mut buffer = String::new();
                let _ = std::io::stdin().read_line(&mut buffer);
            }
            code
        }
        Ok(Parsed::Help(command)) => {
            print_help(command);
            ExitCode::SUCCESS
        }
        Ok(Parsed::Version) => {
            println!("orbis-unpkg {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("error: {message}\n\nRun 'orbis-unpkg --help' for usage.");
            ExitCode::from(2)
        }
    }
}

fn parse_args(args: &[OsString]) -> Result<Parsed, String> {
    if args.is_empty() {
        return Ok(Parsed::Help(None));
    }
    match option(args[0].as_os_str()) {
        Some("-h" | "--help") => return Ok(Parsed::Help(None)),
        Some("-V" | "--version") => return Ok(Parsed::Version),
        _ => {}
    }

    match args[0].to_str() {
        Some("help") => parse_help(&args[1..]),
        Some("extract") => command_or_help("extract", &args[1..], parse_extract),
        Some("info") => command_or_help("info", &args[1..], parse_info),
        Some("check-type" | "type") => command_or_help("check-type", &args[1..], parse_check_type),
        Some("install") => command_or_help("install", &args[1..], parse_install),
        _ => parse_legacy(args).map(Parsed::Run),
    }
}

fn command_or_help(
    name: &'static str,
    args: &[OsString],
    parse: fn(&[OsString]) -> Result<Action, String>,
) -> Result<Parsed, String> {
    if args
        .iter()
        .take_while(|arg| arg.as_os_str() != "--")
        .any(|arg| matches!(option(arg), Some("-h" | "--help")))
    {
        Ok(Parsed::Help(Some(name)))
    } else {
        parse(args).map(Parsed::Run)
    }
}

fn parse_help(args: &[OsString]) -> Result<Parsed, String> {
    match args {
        [] => Ok(Parsed::Help(None)),
        [command] => match command.to_str() {
            Some("extract") => Ok(Parsed::Help(Some("extract"))),
            Some("info") => Ok(Parsed::Help(Some("info"))),
            Some("check-type" | "type") => Ok(Parsed::Help(Some("check-type"))),
            Some("install") => Ok(Parsed::Help(Some("install"))),
            Some(other) => Err(format!("unknown command '{other}'")),
            None => Err("command names must be valid UTF-8".into()),
        },
        _ => Err("help accepts at most one command name".into()),
    }
}

fn parse_extract(args: &[OsString]) -> Result<Action, String> {
    let mut output = None;
    let mut quiet = false;
    let mut positional = Vec::new();
    let mut options = true;
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_os_str();
        if options && arg == "--" {
            options = false;
        } else if options {
            match option(arg) {
                Some("-q" | "--quiet") => quiet = true,
                Some("-o" | "--output") => {
                    output = Some(PathBuf::from(option_value(args, &mut index, "--output")?));
                }
                Some(value) if value.starts_with("--output=") => {
                    output = Some(PathBuf::from(long_value(value, "--output")?));
                }
                Some(value) if value.starts_with('-') => {
                    return Err(format!("unknown extract option '{value}'"));
                }
                _ => positional.push(args[index].clone()),
            }
        } else {
            positional.push(args[index].clone());
        }
        index += 1;
    }
    let file = one_positional(positional, "extract requires one FILE")?;
    Ok(Action::Extract {
        file: PathBuf::from(file),
        output,
        quiet,
        wait: false,
    })
}

fn parse_info(args: &[OsString]) -> Result<Action, String> {
    let mut values = Vec::new();
    let mut options = true;
    for arg in args {
        if options && arg == "--" {
            options = false;
        } else if options && option(arg).is_some_and(|value| value.starts_with('-')) {
            return Err(format!("unknown info option '{}'", arg.to_string_lossy()));
        } else {
            values.push(arg.clone());
        }
    }
    let file = one_positional(values, "info requires one FILE")?;
    Ok(Action::Info {
        file: PathBuf::from(file),
    })
}

fn parse_check_type(args: &[OsString]) -> Result<Action, String> {
    let mut quiet = false;
    let mut positional = Vec::new();
    let mut options = true;
    for arg in args {
        if options && arg == "--" {
            options = false;
            continue;
        }
        if !options {
            positional.push(arg.clone());
            continue;
        }
        match option(arg) {
            Some("-q" | "--quiet") => quiet = true,
            Some(value) if value.starts_with('-') => {
                return Err(format!("unknown check-type option '{value}'"));
            }
            _ => positional.push(arg.clone()),
        }
    }
    let file = one_positional(positional, "check-type requires one FILE")?;
    Ok(Action::CheckType {
        file: PathBuf::from(file),
        quiet,
    })
}

fn parse_install(args: &[OsString]) -> Result<Action, String> {
    let mut games_dir = None;
    let mut addons_dir = None;
    let mut quiet = false;
    let mut positional = Vec::new();
    let mut options = true;
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_os_str();
        if options && arg == "--" {
            options = false;
        } else if options {
            match option(arg) {
                Some("-q" | "--quiet") => quiet = true,
                Some("--games-dir") => {
                    games_dir = Some(PathBuf::from(option_value(
                        args,
                        &mut index,
                        "--games-dir",
                    )?));
                }
                Some(value) if value.starts_with("--games-dir=") => {
                    games_dir = Some(PathBuf::from(long_value(value, "--games-dir")?));
                }
                Some("--addons-dir") => {
                    addons_dir = Some(PathBuf::from(option_value(
                        args,
                        &mut index,
                        "--addons-dir",
                    )?));
                }
                Some(value) if value.starts_with("--addons-dir=") => {
                    addons_dir = Some(PathBuf::from(long_value(value, "--addons-dir")?));
                }
                Some(value) if value.starts_with('-') => {
                    return Err(format!("unknown install option '{value}'"));
                }
                _ => positional.push(args[index].clone()),
            }
        } else {
            positional.push(args[index].clone());
        }
        index += 1;
    }

    let source = one_positional(positional, "install requires one FILE_OR_DIR")?;
    let games_dir = games_dir
        .or_else(|| env::var_os("ORBIS_UNPKG_GAMES_DIR").map(PathBuf::from))
        .ok_or("install requires --games-dir or ORBIS_UNPKG_GAMES_DIR")?;
    let addons_dir = addons_dir
        .or_else(|| env::var_os("ORBIS_UNPKG_ADDONS_DIR").map(PathBuf::from))
        .ok_or("install requires --addons-dir or ORBIS_UNPKG_ADDONS_DIR")?;
    Ok(Action::Install {
        source: PathBuf::from(source),
        games_dir,
        addons_dir,
        quiet,
    })
}

fn parse_legacy(args: &[OsString]) -> Result<Action, String> {
    let mut check_type = false;
    let mut info = false;
    let mut quiet = false;
    let mut no_wait = false;
    let mut positional = Vec::new();
    let mut options = true;
    for arg in args {
        if options && arg == "--" {
            options = false;
            continue;
        }
        if options {
            match option(arg) {
                Some("--check-type") => check_type = true,
                Some("--info") => info = true,
                Some("-q" | "--quiet") => quiet = true,
                Some("-y" | "--no-wait") => no_wait = true,
                Some(value) if value.starts_with('-') => {
                    return Err(format!("unknown option '{value}'"));
                }
                _ => positional.push(arg.clone()),
            }
        } else {
            positional.push(arg.clone());
        }
    }

    if check_type && info {
        return Err("--check-type and --info cannot be used together".into());
    }
    if positional.is_empty() || positional.len() > 2 {
        return Err("legacy extraction requires FILE and an optional OUTPUT".into());
    }
    let file = PathBuf::from(positional.remove(0));
    if check_type {
        if !positional.is_empty() {
            return Err("--check-type does not accept OUTPUT".into());
        }
        Ok(Action::CheckType { file, quiet })
    } else if info {
        if !positional.is_empty() {
            return Err("--info does not accept OUTPUT".into());
        }
        Ok(Action::Info { file })
    } else {
        let output = positional.pop().map(PathBuf::from);
        let wait = output.is_none() && !no_wait;
        Ok(Action::Extract {
            file,
            output,
            quiet,
            wait,
        })
    }
}

fn option(arg: &OsStr) -> Option<&str> {
    arg.to_str()
}

fn option_value(args: &[OsString], index: &mut usize, name: &str) -> Result<OsString, String> {
    *index += 1;
    args.get(*index)
        .cloned()
        .ok_or_else(|| format!("{name} requires a value"))
}

fn long_value<'a>(value: &'a str, name: &str) -> Result<&'a str, String> {
    value
        .strip_prefix(name)
        .and_then(|value| value.strip_prefix('='))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{name} requires a value"))
}

fn one_positional(mut values: Vec<OsString>, message: &str) -> Result<OsString, String> {
    if values.len() == 1 {
        Ok(values.remove(0))
    } else {
        Err(message.into())
    }
}

fn print_help(command: Option<&str>) {
    match command {
        Some("extract") => println!(
            "Extract a PKG file\n\nUsage: orbis-unpkg extract [OPTIONS] <FILE>\n\nOptions:\n  -o, --output <DIR>  Base output directory\n  -q, --quiet         Suppress summaries and progress\n  -h, --help          Print help"
        ),
        Some("info") => {
            println!("Display PKG metadata without extracting it\n\nUsage: orbis-unpkg info <FILE>")
        }
        Some("check-type") => println!(
            "Detect whether a PKG is a base game, update, or DLC\n\nUsage: orbis-unpkg check-type [OPTIONS] <FILE>\n\nOptions:\n  -q, --quiet  Print only through the process exit code\n  -h, --help   Print help"
        ),
        Some("install") => println!(
            "Install one PKG, or every PKG directly inside a directory\n\nUsage: orbis-unpkg install [OPTIONS] --games-dir <DIR> --addons-dir <DIR> <FILE_OR_DIR>\n\nOptions:\n      --games-dir <DIR>   Game directory [env: ORBIS_UNPKG_GAMES_DIR]\n      --addons-dir <DIR>  Add-on directory [env: ORBIS_UNPKG_ADDONS_DIR]\n  -q, --quiet             Suppress summaries and progress\n  -h, --help              Print help"
        ),
        _ => println!(
            "Inspect, extract, and install PlayStation 4 PKG files\n\nUsage:\n  orbis-unpkg <COMMAND> [OPTIONS]\n  orbis-unpkg [OPTIONS] <FILE> [OUTPUT]\n\nCommands:\n  extract     Extract a PKG file\n  info        Display PKG metadata\n  check-type  Detect the PKG category [alias: type]\n  install     Install one PKG or a directory of PKGs\n  help        Print command help\n\nOptions:\n      --check-type  Legacy category check\n      --info        Legacy metadata display\n  -q, --quiet       Suppress summaries and progress\n  -y, --no-wait     Do not pause after drag-and-drop extraction\n  -h, --help        Print help\n  -V, --version     Print version"
        ),
    }
}

fn dispatch(action: Action) -> ExitCode {
    match action {
        Action::Extract {
            file,
            output,
            quiet,
            ..
        } => result_code(extract_pkg(&file, output.as_deref(), quiet)),
        Action::Info { file } => result_code(show_info(&file)),
        Action::CheckType { file, quiet } => check_type(&file, quiet),
        Action::Install {
            source,
            games_dir,
            addons_dir,
            quiet,
        } => result_code(install(&source, &games_dir, &addons_dir, quiet)),
    }
}

fn result_code(result: Result<(), String>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn check_type(file: &Path, quiet: bool) -> ExitCode {
    match inspect(file) {
        Ok((pkg, _, category)) => {
            if !quiet {
                println!("detected: {} ({})", category.label(), pkg.title_id());
            }
            ExitCode::from(category.exit_code())
        }
        Err(_) => ExitCode::from(0),
    }
}

fn show_info(file: &Path) -> Result<(), String> {
    let (pkg, _, category) = inspect(file)?;
    print_summary(file, &pkg, category);
    Ok(())
}

fn extract_pkg(file: &Path, base_output: Option<&Path>, quiet: bool) -> Result<(), String> {
    let (pkg, psf, category) = inspect(file)?;
    let base = base_output
        .map(Path::to_path_buf)
        .unwrap_or_else(|| sibling_directory(file));
    extract_open_pkg(file, pkg, &psf, category, &base, quiet)
}

fn install(source: &Path, games_dir: &Path, addons_dir: &Path, quiet: bool) -> Result<(), String> {
    let files = install_sources(source)?;
    let total = files.len();
    let mut failures = 0usize;
    for (index, file) in files.iter().enumerate() {
        if !quiet && total > 1 {
            println!("\nInstalling {}/{}: {}", index + 1, total, file.display());
        }
        let result = inspect(file).and_then(|(pkg, psf, category)| {
            let base = install_base(category, games_dir, addons_dir);
            if !quiet {
                println!("Destination: {}", base.display());
            }
            extract_open_pkg(file, pkg, &psf, category, base, quiet)
        });
        if let Err(message) = result {
            eprintln!("failed: {}: {message}", file.display());
            failures += 1;
        }
    }
    if failures == 0 {
        if !quiet && total > 1 {
            println!("\nInstalled {total} PKG files");
        }
        Ok(())
    } else {
        Err(format!("{failures} of {total} PKG files failed to install"))
    }
}

fn install_sources(source: &Path) -> Result<Vec<PathBuf>, String> {
    if source.is_file() {
        if is_pkg_path(source) {
            return Ok(vec![source.to_path_buf()]);
        }
        return Err(format!("{} is not a .pkg file", source.display()));
    }
    if !source.is_dir() {
        return Err(format!("{} does not exist", source.display()));
    }
    let entries = fs::read_dir(source)
        .map_err(|error| format!("cannot read {}: {error}", source.display()))?;
    let mut files = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_file() && is_pkg_path(path))
        .collect::<Vec<_>>();
    files.sort();
    if files.is_empty() {
        Err(format!("{} contains no .pkg files", source.display()))
    } else {
        Ok(files)
    }
}

fn is_pkg_path(path: &Path) -> bool {
    path.extension()
        .and_then(OsStr::to_str)
        .is_some_and(|extension| extension.eq_ignore_ascii_case("pkg"))
}

fn install_base<'a>(category: PkgCategory, games_dir: &'a Path, addons_dir: &'a Path) -> &'a Path {
    match category {
        PkgCategory::Dlc => addons_dir,
        PkgCategory::Base | PkgCategory::Patch => games_dir,
    }
}

fn inspect(file: &Path) -> Result<(Pkg, Psf, PkgCategory), String> {
    match detect_file_type(file) {
        Ok(FileType::Pkg) => {}
        Ok(_) => return Err(format!("{} is not a valid PKG file", file.display())),
        Err(error) => return Err(error.to_string()),
    }
    let pkg = Pkg::open(file).map_err(|error| format!("cannot open PKG: {error}"))?;
    let psf =
        Psf::parse(pkg.param_sfo()).map_err(|error| format!("cannot read param.sfo: {error}"))?;
    let category = PkgCategory::classify(pkg.flags(), psf.get_string("CATEGORY"));
    Ok((pkg, psf, category))
}

fn extract_open_pkg(
    file: &Path,
    mut pkg: Pkg,
    psf: &Psf,
    category: PkgCategory,
    base_output: &Path,
    quiet: bool,
) -> Result<(), String> {
    let output = resolve_output(base_output, &pkg, psf, category);
    if !quiet {
        print_summary(file, &pkg, category);
        println!("\nExtracting to {}", output.display());
    }
    pkg.extract(&output)
        .map_err(|error| format!("extraction failed: {error}"))?;

    let total = pkg.num_files();
    let interactive = !quiet && std::io::stderr().is_terminal();
    let mut warnings = 0usize;
    for index in 0..total {
        let name = pkg.file_name(index).unwrap_or_default().to_string();
        if !quiet && !interactive {
            eprintln!("  [{}/{}] {name}", index + 1, total);
        }
        let mut last_percent = u64::MAX;
        let result = pkg.extract_file_with_progress(index, |done, blocks| {
            if interactive && blocks > 0 {
                let percent = done * 100 / blocks;
                if percent != last_percent {
                    eprint!("\r  [{}/{}] {:>3}% {}", index + 1, total, percent, name);
                    let _ = std::io::stderr().flush();
                    last_percent = percent;
                }
            }
        });
        if interactive {
            eprintln!();
        }
        if let Err(error) = result {
            warnings += 1;
            eprintln!("warning: {name}: {error}");
        }
    }
    if warnings > 0 {
        return Err(format!("failed to extract {warnings} of {total} entries"));
    }
    if !quiet {
        println!("Extracted {total} entries to {}", output.display());
    }
    Ok(())
}

fn sibling_directory(file: &Path) -> PathBuf {
    match file.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

fn resolve_output(base: &Path, pkg: &Pkg, psf: &Psf, category: PkgCategory) -> PathBuf {
    let mut output = base.join(pkg.title_id());
    match category {
        PkgCategory::Patch => {
            let mut name = output.into_os_string();
            name.push("-patch");
            output = PathBuf::from(name);
        }
        PkgCategory::Dlc => {
            if let Some(content_id) = psf.get_string("CONTENT_ID") {
                if let Some(label) = content_id.split('-').nth(2) {
                    output.push(label);
                }
            }
        }
        PkgCategory::Base => {}
    }
    output
}

fn print_summary(file: &Path, pkg: &Pkg, category: PkgCategory) {
    let size = fs::metadata(file)
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    let flags = if pkg.flags().is_empty() {
        "(none)"
    } else {
        pkg.flags()
    };
    println!("orbis-unpkg");
    println!("  {:<9}  {}", "File", file.display());
    println!("  {:<9}  {}", "Title ID", pkg.title_id());
    println!("  {:<9}  {}", "Type", category.label());
    println!("  {:<9}  {flags}", "Flags");
    println!("  {:<9}  {}", "Size", human_size(size));
}

fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.2} {}", UNITS[unit])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn parses_command_style_extract() {
        let parsed = parse_args(&args(&["extract", "game.pkg", "--output", "out"])).unwrap();
        assert!(matches!(
            parsed,
            Parsed::Run(Action::Extract { file, output: Some(output), wait: false, .. })
                if file == Path::new("game.pkg") && output == Path::new("out")
        ));
    }

    #[test]
    fn parses_legacy_extract() {
        let parsed = parse_args(&args(&["game.pkg", "out", "--quiet"])).unwrap();
        assert!(matches!(
            parsed,
            Parsed::Run(Action::Extract { file, output: Some(output), quiet: true, .. })
                if file == Path::new("game.pkg") && output == Path::new("out")
        ));
    }

    #[test]
    fn parses_install_directories() {
        let parsed = parse_args(&args(&[
            "install",
            "packages",
            "--games-dir",
            "games",
            "--addons-dir",
            "addons",
        ]))
        .unwrap();
        assert!(matches!(
            parsed,
            Parsed::Run(Action::Install { games_dir, addons_dir, .. })
                if games_dir == Path::new("games") && addons_dir == Path::new("addons")
        ));
    }

    #[test]
    fn rejects_missing_option_values() {
        assert!(parse_args(&args(&["extract", "game.pkg", "--output"])).is_err());
    }

    #[test]
    fn parses_equals_options_and_escaped_paths() {
        let parsed = parse_args(&args(&["extract", "--output=out", "--", "-game.pkg"])).unwrap();
        assert!(matches!(
            parsed,
            Parsed::Run(Action::Extract { file, output: Some(output), .. })
                if file == Path::new("-game.pkg") && output == Path::new("out")
        ));
    }

    #[test]
    fn pkg_extension_is_case_insensitive() {
        assert!(is_pkg_path(Path::new("game.pkg")));
        assert!(is_pkg_path(Path::new("GAME.PKG")));
        assert!(!is_pkg_path(Path::new("game.zip")));
    }

    #[test]
    fn dlc_uses_addons_directory() {
        let games = Path::new("games");
        let addons = Path::new("addons");
        assert_eq!(install_base(PkgCategory::Base, games, addons), games);
        assert_eq!(install_base(PkgCategory::Patch, games, addons), games);
        assert_eq!(install_base(PkgCategory::Dlc, games, addons), addons);
    }

    #[test]
    fn human_sizes_are_readable() {
        assert_eq!(human_size(1), "1 B");
        assert_eq!(human_size(1024), "1.00 KiB");
        assert_eq!(human_size(1_572_864), "1.50 MiB");
    }
}
