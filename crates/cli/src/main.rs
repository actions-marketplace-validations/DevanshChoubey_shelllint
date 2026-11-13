// SPDX-License-Identifier: GPL-3.0-or-later
// Port of ShellCheck shellcheck.hs (e11f964)

mod cache;
mod completions;
mod discover;
mod dump_ast;
mod fix;
mod list_checks;
mod oom;
mod options;
mod rcstrict;
mod run_control;
mod shell_inference;
mod sys;
mod verbose;

use std::io::Write;
use std::process::exit;
use std::sync::atomic::{AtomicBool, Ordering};

use shelllint_checker::{check_script_owned, optional_checks, with_check_stack};
use shelllint_core::data::{SHELLCHECK_VERSION, shell_for_executable};
use shelllint_core::extras::{expand_home, is_external_var_pattern};
use shelllint_core::interface::{CheckSpec, ColorOption, Severity, SystemInterface};
use shelllint_formatter::{Formatter, by_name, tty::WIKI_LINK};

#[global_allocator]
static ALLOC: oom::ExitOnOom = oom::ExitOnOom;

use options::{Flag, Options, default_options, get_opt, get_usage_info, options as option_table};
use sys::io_interface;

/// The project's website, printed by `--version` (upstream prints
/// https://www.shellcheck.net). Comes from the package's `repository` key so
/// a rename only touches Cargo.toml.
pub const PROJECT_WEBSITE: &str = env!("CARGO_PKG_REPOSITORY");

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub(crate) enum Status {
    NoProblems,
    SomeProblems,
    SupportFailure,
    SyntaxFailure,
    RuntimeException,
}

pub(crate) fn print_err(s: &str) {
    eprintln!("{}", s);
}

fn parse_file_list_lines(contents: &str) -> Vec<String> {
    contents
        .lines()
        .map(|l| l.trim_matches(shelllint_core::unicode::is_space))
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect()
}

fn parse_arguments(argv: &[String]) -> Result<(Vec<Flag>, Vec<String>), Status> {
    let (opts, files, errors) = get_opt(&option_table(), argv);
    if errors.is_empty() {
        Ok((opts, files))
    } else {
        print_err(&format!("{}\n{}", errors.concat(), get_usage_info()));
        Err(Status::SyntaxFailure)
    }
}

/// `getOption`: the first flag with that name.
fn get_option<'a>(flags: &'a [Flag], name: &str) -> Option<&'a str> {
    flags.iter().find(|f| f.0 == name).map(|f| f.1.as_str())
}

fn get_options<'a>(flags: &'a [Flag], name: &str) -> Vec<&'a str> {
    flags.iter().filter(|f| f.0 == name).map(|f| f.1.as_str()).collect()
}

/// `split char str`: keeps empty fields, "" gives [""].
fn split(c: char, s: &str) -> Vec<String> {
    s.split(c).map(String::from).collect()
}

fn get_env_args() -> Vec<String> {
    let opts = std::env::var("SHELLCHECK_OPTS").unwrap_or_default();
    opts.split(' ').filter(|s| !s.is_empty()).map(String::from).collect()
}

fn main() {
    // Haskell's `error` (an uncaught ErrorCall) prints `<prog>: <message>`
    // and exits 1. A Rust panic would exit 101 with a backtrace hint, so the
    // hook prints the message the same way and `main` exits 1 once the
    // unwinding (which flushes buffered stdout) reaches it.
    // DIVERGENCE: the message text is the port's own, not GHC's (there is
    // no `CallStack (from HasCallStack)` trailer).
    std::panic::set_hook(Box::new(|info| {
        let payload = info.payload();
        let msg = payload
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "internal error".to_string());
        eprintln!("{}: {}", prog_name(), msg);
    }));
    // Every file is checked on one big-stack thread instead of one each.
    match std::panic::catch_unwind(|| with_check_stack(run_main)) {
        Ok(code) => exit(code),
        Err(_) => {
            let _ = std::io::stdout().flush();
            exit(1)
        }
    }
}

fn run_main() -> i32 {
    // DIVERGENCE: non-UTF-8 arguments are converted lossily (U+FFFD).
    let params: Vec<String> = std::env::args_os().skip(1).map(|a| a.to_string_lossy().into_owned()).collect();
    let mut args = get_env_args();
    args.extend(params);
    let status = match parse_arguments(&args).and_then(|(flags, files)| process(&flags, &files)) {
        Ok(s) | Err(s) => s,
    };
    status_to_code(status)
}

/// The program name, as GHC's `getProgName` gives it (the basename of argv[0]).
fn prog_name() -> String {
    std::env::args_os()
        .next()
        .map(|a| {
            let p = std::path::PathBuf::from(a);
            p.file_name().unwrap_or(p.as_os_str()).to_string_lossy().into_owned()
        })
        .unwrap_or_else(|| "shellcheck".to_string())
}

/// An uncaught Haskell exception: `<prog>: <message>` on stderr, exit 1.
fn die(msg: &str) -> ! {
    let _ = std::io::stdout().flush();
    eprintln!("{}: {}", prog_name(), msg);
    exit(1)
}

fn status_to_code(status: Status) -> i32 {
    match status {
        Status::NoProblems => 0,
        Status::SomeProblems => 1,
        Status::SyntaxFailure => 3,
        Status::SupportFailure => 4,
        Status::RuntimeException => 2,
    }
}

fn process(flags: &[Flag], files: &[String]) -> Result<Status, Status> {
    if let Some(shell) = get_option(flags, "completions") {
        return match completions::generate(shell) {
            Some(script) => {
                print!("{}", script);
                Ok(Status::NoProblems)
            }
            None => {
                print_err(&format!("Unknown shell for --completions: {}", shell));
                print_err(&format!("Supported shells: {}", completions::SHELL_NAMES.join(", ")));
                Err(Status::SyntaxFailure)
            }
        };
    }
    let mut options = default_options();
    for flag in flags {
        parse_option(flag, &mut options)?;
    }

    let files_from = get_options(flags, "files-from");
    let mut all_files: Vec<String> = vec![];
    for path in &files_from {
        all_files.extend(read_files_from(path)?);
    }
    all_files.extend(files.iter().cloned());

    // `-r` and `--exclude-path` (extensions): expand directories, drop excluded paths.
    let recursive = get_option(flags, "recursive").is_some();
    let excludes = get_options(flags, "exclude-path");
    let mut walked_to_nothing = false;
    if recursive || !excludes.is_empty() {
        let had_inputs = !all_files.is_empty();
        all_files = discover::expand_files(&all_files, recursive, &excludes);
        // A walk that finds nothing is not an error.
        walked_to_nothing = recursive && had_inputs && all_files.is_empty();
    }

    // It shouldn't be an error to do --files-from=/dev/null
    if files_from.is_empty() && !walked_to_nothing {
        verify_files(&all_files)?;
    }

    if let Some(name) = &options.stdin_filename {
        if !all_files.iter().any(|f| f == "-") {
            print_err("--stdin-filename can only be used together with '-' (standard input) as a file.\n");
            print_err(&get_usage_info());
            return Err(Status::SyntaxFailure);
        }
        if !options.fix {
            for f in all_files.iter_mut() {
                if *f == "-" {
                    *f = name.clone();
                }
            }
        }
    }

    rcstrict::check_rcfile_readable(&options)?;
    let first = all_files.first().map(String::as_str);
    rcstrict::apply_rc_overrides(
        &mut options,
        get_option(flags, "color").is_some(),
        get_option(flags, "wiki-link-count").is_some(),
        first,
    );

    let format = get_option(flags, "format").unwrap_or("tty");
    let mut formatter = new_formatter(format, &options)?;
    if !options.outputs.is_empty() {
        formatter = tee_outputs(formatter, &options)?;
    }

    if options.dry_run && !options.fix {
        print_err("--dry-run only works together with --fix.");
        return Err(Status::SyntaxFailure);
    }
    if options.dump_ast {
        return Ok(dump_ast::run(&options, &all_files));
    }
    if let Some(rev) = get_option(flags, "changed-since") {
        if all_files.iter().any(|f| f == "-") {
            print_err("--changed-since cannot be used with standard input ('-').");
            return Err(Status::SyntaxFailure);
        }
        match discover::changed_lines(rev, &all_files) {
            Ok(m) => options.changed_lines = Some(m),
            Err(msg) => {
                print_err(&format!("{}: {}", prog_name(), msg));
                return Err(Status::RuntimeException);
            }
        }
    }
    if options.fix {
        return Ok(fix::run_fix(&options, formatter, &all_files));
    }

    let sys = io_interface(&options, &all_files);
    let status = run_formatter(&sys, formatter, &options, &all_files);
    if OUTPUT_FAILED.load(Ordering::SeqCst) {
        return Ok(Status::RuntimeException);
    }
    Ok(status)
}

/// Set when a `--output` file could not be written.
static OUTPUT_FAILED: AtomicBool = AtomicBool::new(false);

fn new_formatter(format: &str, options: &Options) -> Result<Box<dyn Formatter>, Status> {
    match by_name(format, options.formatter_options.clone()) {
        Some(f) => Ok(f),
        None => {
            print_err(&format!("Unknown format {}", format));
            print_err("Supported formats:");
            for name in options::FORMAT_NAMES {
                print_err(&format!("  {}", name));
            }
            Err(Status::SupportFailure)
        }
    }
}

/// One `--output=FORMAT:PATH`: its formatter, the file and the report so far.
struct OutputFile {
    format: Box<dyn Formatter>,
    path: String,
    file: std::fs::File,
    buf: Vec<u8>,
}

/// Runs the `-f` formatter and every `--output` formatter off one set of
/// results, so each script is checked once.
struct Tee {
    primary: Box<dyn Formatter>,
    outputs: Vec<OutputFile>,
}

/// Opens (creates) every `--output` file before anything is checked, so an
/// unwritable path fails up front instead of after a report went to stdout.
fn tee_outputs(primary: Box<dyn Formatter>, options: &Options) -> Result<Box<dyn Formatter>, Status> {
    let mut outputs = vec![];
    for (format, path) in &options.outputs {
        let formatter = new_formatter(format, options)?;
        match std::fs::File::create(path) {
            Ok(file) => outputs.push(OutputFile { format: formatter, path: path.clone(), file, buf: vec![] }),
            Err(e) => {
                print_err(&format!(
                    "Could not write output file: {}: {}",
                    path,
                    sys::show_io_error_in("openFile", path, &e)
                ));
                return Err(Status::RuntimeException);
            }
        }
    }
    Ok(Box::new(Tee { primary, outputs }))
}

impl Formatter for Tee {
    fn header(&mut self, out: &mut dyn Write) {
        self.primary.header(out);
        for o in &mut self.outputs {
            o.format.header(&mut o.buf);
        }
    }

    fn on_result(
        &mut self,
        r: &shelllint_core::interface::CheckResult,
        sys: &dyn SystemInterface,
        out: &mut dyn Write,
    ) {
        self.primary.on_result(r, sys, out);
        for o in &mut self.outputs {
            o.format.on_result(r, sys, &mut o.buf);
        }
    }

    fn on_failure(&mut self, file: &str, msg: &str, out: &mut dyn Write) {
        self.primary.on_failure(file, msg, out);
        for o in &mut self.outputs {
            o.format.on_failure(file, msg, &mut o.buf);
        }
    }

    fn footer(&mut self, out: &mut dyn Write) {
        self.primary.footer(out);
        for o in &mut self.outputs {
            o.format.footer(&mut o.buf);
            if let Err(e) = o.file.write_all(&o.buf).and_then(|_| o.file.flush()) {
                print_err(&format!(
                    "Could not write output file: {}: {}",
                    o.path,
                    sys::show_io_error_in("write", &o.path, &e)
                ));
                OUTPUT_FAILED.store(true, Ordering::SeqCst);
            }
        }
    }

    fn exit_requested(&self) -> bool {
        self.primary.exit_requested()
    }
}

fn read_files_from(path: &str) -> Result<Vec<String>, Status> {
    if path == "-" {
        // DIVERGENCE: stdin is read as UTF-8 here (invalid input yields an empty
        // list); Haskell's getContents uses the locale encoding.
        return match sys::read_stdin(true) {
            Ok(bytes) => Ok(parse_file_list_lines(&String::from_utf8(bytes).unwrap_or_default())),
            // A second `getContents` throws an IOException nothing catches.
            Err(e) => die(&e.to_string()),
        };
    }
    match sys::input_file(path) {
        Err(e) => {
            print_err(&format!("Could not read file list: {}: {}", path, sys::show_io_error_in("openFile", path, &e)));
            Err(Status::RuntimeException)
        }
        Ok((contents, _)) => Ok(parse_file_list_lines(&contents)),
    }
}

pub(crate) fn run_formatter(
    sys: &sys::IoInterface,
    mut format: Box<dyn Formatter>,
    options: &Options,
    files: &[String],
) -> Status {
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    format.header(&mut out);
    let mut result = Status::NoProblems;
    let mut tally = run_control::Tally::default();
    for file in files {
        let (new_status, findings) = process_file(sys, format.as_mut(), options, file, &mut out, &mut tally);
        result = result.max(new_status);
        let _ = out.flush();
        // DIVERGENCE: Haskell's Quiet formatter calls exitFailure itself.
        if format.exit_requested() {
            exit(1);
        }
        // DIVERGENCE: --fail-fast (extension) stops after the first file with findings.
        if options.fail_fast && findings > 0 {
            break;
        }
    }
    format.footer(&mut out);
    let _ = out.flush();
    // DIVERGENCE: --summary (extension) reports totals on stderr only.
    if options.summary {
        print_err(&tally.summary());
    }
    result
}

fn process_file(
    sys: &sys::IoInterface,
    format: &mut dyn Formatter,
    options: &Options,
    filename: &str,
    out: &mut dyn Write,
    tally: &mut run_control::Tally,
) -> (Status, usize) {
    verbose::announce(sys, options, filename);
    let contents = match sys.read_file(None, filename) {
        Ok(c) => c,
        Err(msg) => {
            format.on_failure(filename, &msg, out);
            return (Status::RuntimeException, 0);
        }
    };
    if options.strict_rc && !options.check_spec.ignore_rc && rcstrict::rc_has_problems(options, filename) {
        return (Status::RuntimeException, 0);
    }
    let mut spec = CheckSpec { filename: filename.to_string(), script: contents, ..options.check_spec.clone() };
    let shell_flag = options.check_spec.shell_type_override.is_some();
    match shell_inference::decide(&options.shell_inference, shell_flag, spec.ignore_rc, sys, filename, &spec.script) {
        Some(shell_inference::Decision::Skip) => return (Status::NoProblems, 0),
        Some(shell_inference::Decision::Use(sh)) => spec.shell_type_override = Some(sh),
        None => {}
    }
    let result = match &options.cache_dir {
        Some(dir) if filename != "-" => cache::check_cached(sys, dir, options, spec),
        _ => check_script_owned(sys, spec),
    };
    let result = discover::keep_changed(options, result);
    format.on_result(&result, sys, out);
    let findings = tally.record(&result);
    // A malformed EditorConfig (invalid 'root' or 'shellcheck.*' directive)
    // means shellcheck cannot apply the requested configuration.
    let status =
        if result.comments.iter().any(|pc| pc.comment.code == 1134 && pc.start_pos.file.ends_with(".editorconfig")) {
            Status::SupportFailure
        } else if result.comments.is_empty() {
            Status::NoProblems
        } else {
            Status::SomeProblems
        };
    (status, findings)
}

fn parse_enum<T: Copy>(name: &str, value: &str, list: &[(&str, T)]) -> Result<T, Status> {
    match list.iter().find(|(k, _)| *k == value) {
        Some((_, v)) => Ok(*v),
        None => {
            let names: Vec<&str> = list.iter().map(|(k, _)| *k).collect();
            print_err(&format!("Unknown value for --{}. Valid options are: {}", name, names.join(", ")));
            Err(Status::SupportFailure)
        }
    }
}

fn parse_num(s: &str) -> Result<i64, Status> {
    let mut num = s;
    while let Some(rest) = num.strip_prefix("SC") {
        num = rest;
    }
    if num.is_empty() || !num.chars().all(|c| c.is_ascii_digit()) {
        print_err(&format!("Invalid number: {}", num));
        return Err(Status::SyntaxFailure);
    }
    // DIVERGENCE: Haskell's `read ""` crashes on an empty number (rejected above
    // instead); Integer is unbounded, here values past i64::MAX saturate.
    Ok(num.parse::<i64>().unwrap_or(i64::MAX))
}

fn parse_bool(s: &str) -> Result<bool, Status> {
    match s {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => {
            print_err(&format!("Invalid boolean, expected true/false: {}", s));
            Err(Status::SyntaxFailure)
        }
    }
}

fn parse_option(flag: &Flag, options: &mut Options) -> Result<(), Status> {
    let Flag(name, val) = flag;
    match name.as_str() {
        "shell" => match shell_for_executable(val) {
            Some(shell) => options.check_spec.shell_type_override = Some(shell),
            None => {
                print_err(&format!("Unknown shell: {}", val));
                return Err(Status::SupportFailure);
            }
        },
        "exclude" => {
            let mut new = vec![];
            for s in split(',', val).iter().filter(|s| !s.is_empty()) {
                new.push(parse_num(s)?);
            }
            new.append(&mut options.check_spec.excluded_warnings);
            options.check_spec.excluded_warnings = new;
        }
        "include" => {
            let mut new = vec![];
            for s in split(',', val).iter().filter(|s| !s.is_empty()) {
                new.push(parse_num(s)?);
            }
            if !new.is_empty() {
                // Just new `mappend` old
                if let Some(old) = options.check_spec.included_warnings.take() {
                    new.extend(old);
                }
                options.check_spec.included_warnings = Some(new);
            }
        }
        "version" => {
            print_version();
            return Err(Status::NoProblems);
        }
        "list-optional" => {
            print_optional();
            return Err(Status::NoProblems);
        }
        "list-checks" => {
            list_checks::print(val)?;
            return Err(Status::NoProblems);
        }
        "help" => {
            println!("{}", get_usage_info());
            return Err(Status::NoProblems);
        }
        "externals" => options.external_sources = true,
        "color" => {
            options.formatter_options.color_option = parse_enum(
                "color",
                val,
                &[
                    ("auto", ColorOption::ColorAuto),
                    ("always", ColorOption::ColorAlways),
                    ("never", ColorOption::ColorNever),
                ],
            )?;
        }
        // DIVERGENCE: a leading `~`, `$HOME` or `${HOME}` is expanded.
        "source-path" => options.source_paths.extend(split_search_path(val).iter().map(|p| expand_home(p))),
        "sourced" => options.check_spec.check_sourced = true,
        "severity" => {
            // DIVERGENCE: remembered so that it beats `severity=` in an rc file.
            options.check_spec.min_severity_explicit = true;
            options.check_spec.min_severity = parse_enum(
                "severity",
                val,
                &[
                    ("error", Severity::ErrorC),
                    ("warning", Severity::WarningC),
                    ("info", Severity::InfoC),
                    ("style", Severity::StyleC),
                ],
            )?;
        }
        "wiki-link-count" => options.formatter_options.wiki_link_count = parse_num(val)?,
        "norc" => options.check_spec.ignore_rc = true,
        "rcfile" => options.rcfile = Some(val.clone()),
        "enable" => options.check_spec.optional_checks.extend(split(',', val)),
        "extended-analysis" => options.check_spec.extended_analysis = Some(parse_bool(val)?),
        // Extensions beyond ShellCheck.
        "external-vars" => {
            for name in split(',', val).into_iter().filter(|s| !s.is_empty()) {
                if !is_external_var_pattern(&name) {
                    print_err(&format!("Invalid variable name for --external-vars: {}", name));
                    return Err(Status::SyntaxFailure);
                }
                options.check_spec.external_vars.push(name);
            }
        }
        "fix" => options.fix = true,
        "dry-run" => options.dry_run = true,
        "verbose" => options.verbose = true,
        "fallback-shell" => match shell_for_executable(val) {
            Some(shell) => options.shell_inference.fallback = Some(shell),
            None => {
                print_err(&format!("Unknown shell: {}", val));
                return Err(Status::SupportFailure);
            }
        },
        "infer-shell-from-name" => options.shell_inference.infer_from_name = true,
        "skip-unsupported-shebang" => options.shell_inference.skip_unsupported = true,
        "dump-ast" => options.dump_ast = true,
        "summary" => options.summary = true,
        "fail-fast" => options.fail_fast = true,
        "stdin-filename" => options.stdin_filename = Some(val.clone()),
        "output" => match val.split_once(':') {
            Some((format, path)) if !format.is_empty() && !path.is_empty() => {
                options.outputs.push((format.to_string(), path.to_string()))
            }
            _ => {
                print_err(&format!("Invalid value for --output: {}. Expected FORMAT:PATH.", val));
                return Err(Status::SyntaxFailure);
            }
        },
        "cache-dir" => options.cache_dir = Some(val.clone()),
        "context" => options.formatter_options.context_lines = parse_num(val)?,
        "strict-rc" => options.strict_rc = true,
        "tab-width" => match parse_num(val)? {
            n if n >= 1 => options.formatter_options.tab_width = Some(n.min(1024) as usize),
            _ => {
                print_err(&format!("Invalid tab width: {}", val));
                return Err(Status::SyntaxFailure);
            }
        },
        "source-functions" => options.source_functions.extend(split(',', val).into_iter().filter(|s| !s.is_empty())),
        "source-from-path" => options.source_from_path = true,
        "modern-dialects" => options.check_spec.optional_checks.push("modern-dialects".to_string()),
        "ignore-directives" => options.check_spec.ignore_directives = true,
        "report-unused-disables" => options.check_spec.report_unused_disables = true,
        "safe-vars" => options.check_spec.safe_vars.extend(split(',', val).into_iter().filter(|s| !s.is_empty())),
        "strict-env-vars" => options.check_spec.strict_env_vars = Some(true),
        // These flags are handled specially in 'process'
        "format" | "files-from" | "recursive" | "exclude-path" | "changed-since" => {}
        other => print_err(&format!("Internal error for --{}. Please file a bug :(", other)),
    }
    Ok(())
}

/// System.FilePath `splitSearchPath` (POSIX): empty components become ".".
fn split_search_path(s: &str) -> Vec<String> {
    s.split(':').map(|p| if p.is_empty() { ".".to_string() } else { p.to_string() }).collect()
}

fn verify_files(files: &[String]) -> Result<(), Status> {
    if files.is_empty() {
        print_err("No files specified.\n");
        print_err(&get_usage_info());
        return Err(Status::SyntaxFailure);
    }
    Ok(())
}

fn print_version() {
    println!("shelllint - shell script analysis tool (a Rust port of ShellCheck)");
    println!("version: {} (ports ShellCheck v{}-171-ge11f964)", env!("CARGO_PKG_VERSION"), SHELLCHECK_VERSION);
    println!("license: GNU General Public License, version 3");
    println!("website: {}", PROJECT_WEBSITE);
}

fn print_optional() {
    // sortOn cdName ShellCheck.Analyzer.optionalChecks
    let mut list = optional_checks();
    list.sort_by(|a, b| a.name.cmp(&b.name));
    for item in list {
        println!("name:    {}", item.name);
        let ids: Vec<String> = item.id.iter().map(|n| format!("SC{}", n)).collect();
        println!("id:      {}", ids.join(", "));
        let wikis: Vec<String> = item.id.iter().map(|n| format!("{}SC{}", WIKI_LINK, n)).collect();
        println!("wiki:    {}", wikis.join(", "));
        println!("desc:    {}", item.description);
        println!("example: {}", item.positive);
        println!("fix:     {}", item.negative);
        println!();
    }
}
