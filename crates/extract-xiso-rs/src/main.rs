//! extract-xiso — command-line frontend for the extract_xiso library.
//!
//! The CLI matches the classic `extract-xiso` tool (originally written in
//! C by in <in@fishtank.com>, 2003) flag-for-flag and message-for-message;
//! all format logic lives in the library crate.

mod logging;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use extract_xiso::{
    CreateOptions, Error, Event, ExtractOptions, SYSTEM_UPDATE, Warning, XisoImage, create_image,
    format, is_image_optimized,
};
use logging::{exiso_log, flush, log_err};

const PATH_CHAR: char = std::path::MAIN_SEPARATOR;

fn banner() -> String {
    format!(
        "extract-xiso v{} for {}\n",
        format::VERSION,
        std::env::consts::OS
    )
}

fn usage(prog: &str) {
    eprint!(
        "{}\n\
  Usage:\n\
\n\
    {prog} [options] [-[lrx]] <file1.xiso> [file2.xiso] ...\n\
    {prog} [options] -c <dir> [name] [-c <dir> [name]] ...\n\
\n\
  Mutually exclusive modes:\n\
\n\
    -c <dir> [name]     Create xiso from file(s) starting in <dir>.  If the\n\
                          [name] parameter is specified, the xiso will be\n\
                          created with the (path and) name given, otherwise\n\
                          the xiso will be created in the current directory\n\
                          with the name <dir>.iso.  The -c option may be\n\
                          specified multiple times to create multiple xiso\n\
                          images.\n\
    -l                  List files in xiso(s).\n\
    -r                  Rewrite xiso(s) as optimized xiso(s).\n\
    -x                  Extract xiso(s) (the default mode if none is given).\n\
                          If no directory is specified with -d, a directory\n\
                          with the name of the xiso (minus the .iso portion)\n\
                          will be created in the current directory and the\n\
                          xiso will be expanded there.\n\
\n\
  Options:\n\
\n\
    -d <directory>      In extract mode, expand xiso in <directory>.\n\
                        In rewrite mode, rewrite xiso in <directory>.\n\
    -D                  In rewrite mode, delete old xiso after processing.\n\
    -h                  Print this help text and exit.\n\
    -m                  In create or rewrite mode, disable automatic .xbe\n\
                          media enable patching (not recommended).\n\
    -q                  Run quiet (suppress all non-error output).\n\
    -Q                  Run silent (suppress all output).\n\
    -s                  Skip $SystemUpdate folder.\n\
    -v                  Print version information and exit.\n",
        banner()
    );
}

struct Cli {
    create: Vec<(String, Option<String>)>,
    dest: Option<String>,
    delete_old: bool,
    media_enable: bool,
    skip_systemupdate: bool,
    /// false when -l was given.
    extract: bool,
    rewrite: bool,
    files: Vec<String>,
}

fn usage_exit(prog: &str) -> ! {
    usage(prog);
    std::process::exit(1);
}

fn parse_args(args: &[String]) -> Cli {
    let prog = &args[0];
    if args.len() < 2 {
        usage_exit(prog);
    }

    let mut cli = Cli {
        create: Vec::new(),
        dest: None,
        delete_old: false,
        media_enable: true,
        skip_systemupdate: false,
        extract: true,
        rewrite: false,
        files: Vec::new(),
    };
    let mut x_seen = false;
    let mut end_of_opts = false;

    let mut i = 1;
    while i < args.len() {
        let arg = &args[i];
        if end_of_opts || !arg.starts_with('-') || arg.len() < 2 {
            cli.files.push(arg.clone());
            i += 1;
            continue;
        }
        if arg == "--" {
            end_of_opts = true;
            i += 1;
            continue;
        }

        let opts: Vec<char> = arg[1..].chars().collect();
        let mut j = 0;
        while j < opts.len() {
            match opts[j] {
                c @ ('c' | 'd') => {
                    // Option takes a value: the rest of this token, or the
                    // next argument.
                    let value: String = if j + 1 < opts.len() {
                        opts[j + 1..].iter().collect()
                    } else {
                        i += 1;
                        if i >= args.len() {
                            usage_exit(prog);
                        }
                        args[i].clone()
                    };
                    if c == 'c' {
                        if x_seen || cli.rewrite || !cli.extract {
                            usage_exit(prog);
                        }
                        // Optional [name]: the following argument, if it
                        // exists and is not an option.
                        let name = if i + 1 < args.len()
                            && !args[i + 1].is_empty()
                            && !args[i + 1].starts_with('-')
                        {
                            i += 1;
                            Some(args[i].clone())
                        } else {
                            None
                        };
                        cli.create.push((value, name));
                    } else {
                        cli.dest = Some(value);
                    }
                    j = opts.len();
                    continue;
                }
                'D' => cli.delete_old = true,
                'h' => {
                    usage(prog);
                    std::process::exit(0);
                }
                'l' => {
                    if x_seen || cli.rewrite || !cli.create.is_empty() {
                        usage_exit(prog);
                    }
                    cli.extract = false;
                }
                'm' => {
                    if x_seen || !cli.extract {
                        usage_exit(prog);
                    }
                    cli.media_enable = false;
                }
                'q' => logging::set_quiet(),
                'Q' => logging::set_real_quiet(),
                'r' => {
                    if x_seen || !cli.extract || !cli.create.is_empty() {
                        usage_exit(prog);
                    }
                    cli.rewrite = true;
                }
                's' => cli.skip_systemupdate = true,
                'v' => {
                    print!("{}", banner());
                    std::process::exit(0);
                }
                'x' => {
                    if !cli.extract || cli.rewrite || !cli.create.is_empty() {
                        usage_exit(prog);
                    }
                    x_seen = true;
                }
                _ => usage_exit(prog),
            }
            j += 1;
        }
        i += 1;
    }

    // Create mode takes no trailing image operands; the other modes need
    // at least one.
    if cli.create.is_empty() == cli.files.is_empty() {
        usage_exit(prog);
    }

    cli
}

fn basename(path: &str) -> &str {
    let idx = if cfg!(windows) {
        path.rfind(['/', '\\'])
    } else {
        path.rfind('/')
    };
    match idx {
        Some(i) => &path[i + 1..],
        None => path,
    }
}

fn trim_trailing_sep(s: &str) -> &str {
    let trimmed = s.trim_end_matches(['/', '\\']);
    if trimmed.is_empty() { s } else { trimmed }
}

/// Split an output name into its directory part and base name.
fn split_output_name(name: &str) -> (Option<String>, String) {
    let idx = if cfg!(windows) {
        name.rfind(['/', '\\'])
    } else {
        name.rfind('/')
    };
    match idx {
        Some(i) => (Some(name[..=i].to_string()), name[i + 1..].to_string()),
        None => (None, name.to_string()),
    }
}

/// Print a library progress event exactly the way the original tool did.
/// `root_prefix` is prepended to extraction paths ("halo\", "dest\", "\").
fn print_event(event: &Event<'_>, root_prefix: &str) {
    match event {
        Event::ScanBegin => {
            exiso_log!("generating avl tree from filesystem: ");
            flush!();
        }
        Event::ScanEnd { ok } => {
            exiso_log!("{}\n\n", if *ok { "[OK]" } else { "failed!" });
        }
        Event::AddingDirectory { path } => {
            exiso_log!("adding {path} (0 bytes) [OK]\n");
        }
        Event::AddingFileBegin { dir, name, size } => {
            exiso_log!("adding {dir}{name} ({size} bytes) ");
            flush!();
        }
        Event::AddingFileEnd { ok } => {
            exiso_log!("{}", if *ok { "[OK]\n" } else { "failed\n" });
        }
        Event::CreatingDirectory { path } => {
            exiso_log!("creating {root_prefix}{path} (0 bytes) [OK]\n");
        }
        Event::ExtractProgress {
            dir,
            name,
            size,
            done,
        } => {
            let percent = if *size == 0 {
                100
            } else {
                done * 100 / u64::from(*size)
            };
            exiso_log!("extracting {root_prefix}{dir}{name} ({size} bytes) [{percent}%]\r");
            flush!();
        }
        Event::ExtractFileEnd => exiso_log!("\n"),
        Event::Warning(w) => print_warning(w),
        _ => {}
    }
}

fn print_warning(warning: &Warning<'_>) {
    logging::warn_issued();
    match warning {
        Warning::ImageFileTruncated {
            name,
            expected,
            actual,
        } => {
            exiso_log!(
                "\nWARNING: File {name} is truncated. Reported size: {expected} bytes, read size: {actual} bytes!"
            );
            log_err!("file {name} in the image is truncated ({actual} of {expected} bytes)");
        }
        Warning::SourceFileTruncated {
            name,
            expected,
            actual,
        } => {
            exiso_log!(
                "WARNING: File {name} is truncated. Reported size: {expected} bytes, wrote size: {actual} bytes!\n"
            );
            log_err!("file {name} is truncated ({actual} of {expected} bytes)");
        }
        Warning::FileTooLarge { path } => {
            log_err!("file {} is too large for xiso, skipping...", path.display());
        }
        Warning::FilenameTooLong { path } => {
            log_err!(
                "filename {} is too long for xiso, skipping...",
                path.display()
            );
        }
        _ => {}
    }
}

/// The image name shown in messages: the file name minus any ".iso".
fn iso_display_names(file_path: &str) -> (String, String) {
    let name = basename(file_path).to_string();
    let short = if name.len() > 4 && name[name.len() - 4..].eq_ignore_ascii_case(".iso") {
        name[..name.len() - 4].to_string()
    } else {
        name.clone()
    };
    (name, short)
}

fn output_dir(dest: Option<&str>) -> Result<PathBuf, Error> {
    match dest {
        Some(d) if !d.is_empty() => Ok(PathBuf::from(trim_trailing_sep(d))),
        _ => std::env::current_dir().map_err(|e| Error::Open {
            path: ".".to_string(),
            source: e,
        }),
    }
}

fn run_create(cli: &Cli) -> bool {
    let options = CreateOptions::default()
        .with_media_enable_patching(cli.media_enable)
        .with_skip_system_update(cli.skip_systemupdate);

    for (dir, name) in &cli.create {
        let (out_dir_part, base) = match name {
            Some(n) => {
                let (d, b) = split_output_name(n);
                (d, Some(b))
            }
            None => (None, None),
        };

        // Validate the source directory up front, like the original.
        let source = trim_trailing_sep(dir);
        match fs::metadata(source) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => {
                log_err!("unable to change to directory {source}: not a directory");
                return false;
            }
            Err(e) => {
                log_err!("unable to change to directory {source}: {e}");
                return false;
            }
        }

        let iso_name = match &base {
            Some(b) => b.clone(),
            None => basename(source).to_string(),
        };
        let iso_name = if iso_name.is_empty() {
            "root".to_string()
        } else {
            iso_name
        };
        let ext = if base.is_some() { "" } else { ".iso" };

        let out_dir = match output_dir(out_dir_part.as_deref()) {
            Ok(d) => d,
            Err(e) => {
                log_err!("{e}");
                return false;
            }
        };
        let output = out_dir.join(format!("{iso_name}{ext}"));

        exiso_log!("\ncreating {iso_name}{ext}:\n\n");

        let mut handler = |e: Event<'_>| print_event(&e, "");
        match create_image(Path::new(source), &output, &options, &mut handler) {
            Ok(summary) => {
                exiso_log!(
                    "\nsuccessfully created {iso_name}{ext} ({} files totalling {} bytes added)\n",
                    summary.files,
                    summary.bytes
                );
            }
            Err(e) => {
                log_err!("{e}");
                exiso_log!("\ncould not create {iso_name}{ext}\n");
                return false;
            }
        }
    }
    true
}

/// Per-image totals plus the name they should be reported under.
struct IsoResult {
    files: u32,
    bytes: u64,
    new_iso_path: Option<PathBuf>,
}

/// Inner error type: None means the failure message was already printed.
type IsoError = Option<Error>;

fn rewrite_one(cli: &Cli, old_path: &str, iso_name: &str) -> Result<IsoResult, IsoError> {
    let mut image = XisoImage::open(old_path).map_err(Some)?;
    if image.is_empty() {
        exiso_log!("xbox image {}.iso contains no files.\n", iso_name);
        return Err(None);
    }

    exiso_log!("rewriting {iso_name}.iso:\n\n");

    let out_dir = output_dir(cli.dest.as_deref()).map_err(Some)?;
    let output = out_dir.join(format!("{iso_name}.iso"));
    let options = CreateOptions::default()
        .with_media_enable_patching(cli.media_enable)
        .with_skip_system_update(cli.skip_systemupdate);
    let mut handler = |e: Event<'_>| print_event(&e, "");
    let summary = image
        .rewrite_to(&output, &options, &mut handler)
        .map_err(Some)?;

    Ok(IsoResult {
        files: summary.files,
        bytes: summary.bytes,
        new_iso_path: Some(output),
    })
}

fn extract_or_list_one(cli: &Cli, file_path: &str) -> Result<IsoResult, IsoError> {
    let (name, iso_name) = iso_display_names(file_path);

    // With -d the destination directory is created up front (best effort,
    // like the original).
    if cli.extract
        && let Some(dest) = &cli.dest
    {
        let _ = fs::create_dir_all(dest);
    }

    let mut image = XisoImage::open(file_path).map_err(Some)?;
    if image.is_empty() {
        exiso_log!("xbox image {name} contains no files.\n");
        return Err(None);
    }

    exiso_log!(
        "{} {name}:\n\n",
        if cli.extract { "extracting" } else { "listing" }
    );

    // Prefix used for progress/listing output.
    let root_prefix = match (&cli.dest, cli.extract) {
        (Some(dest), _) => format!("{}{PATH_CHAR}", trim_trailing_sep(dest)),
        (None, true) => format!("{iso_name}{PATH_CHAR}"),
        (None, false) => PATH_CHAR.to_string(),
    };

    if cli.extract {
        let base = match &cli.dest {
            Some(dest) => PathBuf::from(dest),
            None => {
                fs::create_dir(&iso_name).map_err(|e| {
                    Some(Error::CreateDir {
                        path: iso_name.clone(),
                        source: e,
                    })
                })?;
                PathBuf::from(&iso_name)
            }
        };
        let options = ExtractOptions::default().with_skip_system_update(cli.skip_systemupdate);
        let mut handler = |e: Event<'_>| print_event(&e, &root_prefix);
        let summary = image
            .extract_to(&base, &options, &mut handler)
            .map_err(Some)?;
        Ok(IsoResult {
            files: summary.files,
            bytes: summary.bytes,
            new_iso_path: None,
        })
    } else {
        let entries = image.entries().map_err(Some)?;
        let mut files = 0u32;
        let mut bytes = 0u64;
        for entry in &entries {
            if cli.skip_systemupdate
                && (entry
                    .dir_components
                    .iter()
                    .any(|c| c.contains(SYSTEM_UPDATE))
                    || (entry.is_directory && entry.name.contains(SYSTEM_UPDATE)))
            {
                continue;
            }
            let mut path = String::new();
            for c in &entry.dir_components {
                path.push_str(c);
                path.push(PATH_CHAR);
            }
            path.push_str(&entry.name);
            if entry.is_directory {
                exiso_log!("{root_prefix}{path}{PATH_CHAR} (0 bytes)\n");
            } else {
                exiso_log!("{root_prefix}{path} ({} bytes)\n", entry.size);
                files += 1;
                bytes += u64::from(entry.size);
            }
        }
        Ok(IsoResult {
            files,
            bytes,
            new_iso_path: None,
        })
    }
}

fn run_images(cli: &Cli) -> bool {
    let mut isos = 0u32;
    let mut all_files = 0u32;
    let mut all_bytes = 0u64;

    for file_arg in &cli.files {
        isos += 1;
        exiso_log!("\n");

        let optimized = match is_image_optimized(file_arg) {
            Ok(o) => o,
            Err(e) => {
                log_err!("{e}");
                return false;
            }
        };

        let result = if cli.rewrite {
            if optimized {
                exiso_log!("{file_arg} is already optimized, skipping...\n");
                continue;
            }
            let old = format!("{file_arg}.old");
            if fs::metadata(&old).is_ok() {
                log_err!("{old} already exists, cannot rewrite {file_arg}");
                continue;
            }
            if fs::rename(file_arg, &old).is_err() {
                log_err!("cannot rename {file_arg} to {old}");
                continue;
            }
            let (_, iso_name) = iso_display_names(file_arg);
            let result = rewrite_one(cli, &old, &iso_name);
            if let Ok(r) = &result {
                let _ = r;
                if cli.delete_old && fs::remove_file(&old).is_err() {
                    log_err!("unable to delete {old}");
                }
            }
            result
        } else {
            extract_or_list_one(cli, file_arg)
        };

        match result {
            Ok(r) => {
                all_files += r.files;
                all_bytes += r.bytes;
                let shown = r
                    .new_iso_path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| file_arg.clone());
                exiso_log!("\n{} files in {shown} total {} bytes\n", r.files, r.bytes);
                if let Some(new_path) = &r.new_iso_path {
                    exiso_log!(
                        "\n{file_arg} successfully rewritten{}{}\n",
                        if cli.dest.is_some() { " as " } else { "." },
                        if cli.dest.is_some() {
                            new_path.display().to_string()
                        } else {
                            String::new()
                        }
                    );
                }
            }
            Err(e) => {
                if let Some(e) = e {
                    log_err!("{e}");
                }
                let (name, _) = iso_display_names(file_arg);
                let verb = if cli.rewrite {
                    "rewrite"
                } else if cli.extract {
                    "extract"
                } else {
                    "list"
                };
                log_err!("failed to {verb} xbox iso image {name}");
                return false;
            }
        }
    }

    if isos > 1 {
        exiso_log!("\n{all_files} files in {isos} xiso's total {all_bytes} bytes\n");
    }
    true
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let cli = parse_args(&args);

    exiso_log!("{}", banner());

    let ok = if !cli.create.is_empty() {
        run_create(&cli)
    } else {
        run_images(&cli)
    };

    if logging::was_warned() {
        exiso_log!("\nWARNING:  Warning(s) were issued during execution--review stderr!\n");
    }

    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
