// SPDX-License-Identifier: GPL-3.0-or-later
// Port of ShellCheck src/ShellCheck/Checker.hs and src/ShellCheck/Analyzer.hs (e11f964),
// plus `decodeString` from shellcheck.hs (the CLI's file decoding).
//
// Not ported: the TemplateHaskell `runTests` footer and the test helpers
// (`getErrors`, `check`, ...); the `prop_` definitions live in
// `crates/checker/tests/checker.rs`.
#![forbid(unsafe_code)]

pub mod ast_dump;
pub mod directive_audit;
pub mod directive_ranges;
pub mod editorconfig;
pub mod filepath;

use std::collections::HashMap;

// The check registry: every `CheckEntry`, passed to the analyzer's module
// checkers.
use shelllint_checks::CHECKS;

use shelllint_analyzer::analyzerlib::{Checker, Params, filter_by_annotation, make_parameters, run_checker};
use shelllint_analyzer::api::{
    analytics_checker, analytics_optional_checks, commands_checker, commands_optional_checks, shell_support_checker,
};
use shelllint_core::ast::{Ast, Id};
use shelllint_core::astlib::get_enable_directives;
use shelllint_core::extras::{get_external_var_directives, get_severity_directive};
use shelllint_core::interface::{
    AnalysisResult, AnalysisSpec, CheckDescription, CheckResult, CheckSpec, Code, ExecutionMode, ParseSpec,
    PositionedComment, Severity, Shell, SystemInterface, TokenComment, empty_check_result, empty_check_spec,
    mocked_system_interface, new_analysis_result, new_analysis_spec, new_parse_spec, new_positioned_comment,
};
use shelllint_parser::{ParseResult, parse_script};

// ---- Analyzer.hs ---------------------------------------------------------

// TODO: Clean up the cruft this is layered on
/// `analyzeScript`. Records `ast`'s parents for `root` first.
// DIVERGENCE: `asScript` is passed as the arena and its root id (core's
// `AnalysisSpec` has no AST).
pub fn analyze_script(spec: &AnalysisSpec, ast: &mut Ast, root: Id) -> AnalysisResult {
    ast.compute_parents(root);
    let ast: &Ast = ast;
    let params = make_parameters(spec, ast, root);
    let notes = nub_token_comments(run_checker(&params, &checkers(spec, &params)));
    AnalysisResult { comments: filter_by_annotation(spec, &params, notes), ..new_analysis_result() }
}

/// `checkers spec params`
// Checks/ControlFlow.hs and Checks/Custom.hs contribute no checks at
// e11f964 (an empty `controlFlowEffectChecks` and a `nullCheck`), so they
// are intentionally omitted.
fn checkers(spec: &AnalysisSpec, params: &Params<'_>) -> Checker {
    Checker::mconcat([
        analytics_checker(CHECKS, spec),
        commands_checker(CHECKS, spec),
        shell_support_checker(CHECKS, params),
    ])
}

/// `optionalChecks`
// Checks/ControlFlow.hs `optionalChecks = []` at e11f964, so it is
// intentionally omitted.
pub fn optional_checks() -> Vec<CheckDescription> {
    let mut v = analytics_optional_checks(CHECKS);
    v.extend(commands_optional_checks(CHECKS));
    v
}

/// `nub` on token comments.
// DIVERGENCE: Haskell's `nub` is quadratic. Equal comments have the same id
// and code, so each comment is only compared with the kept comments sharing
// those; the result (first occurrences, in order) is the same.
fn nub_token_comments(list: Vec<TokenComment>) -> Vec<TokenComment> {
    let mut seen: HashMap<(Id, Code), Vec<usize>> = HashMap::new();
    let mut out: Vec<TokenComment> = Vec::new();
    for c in list {
        let kept = seen.entry((c.id, c.comment.code)).or_default();
        if kept.iter().any(|&i| out[i] == c) {
            continue;
        }
        kept.push(out.len());
        out.push(c);
    }
    out
}

// ---- Checker.hs ----------------------------------------------------------

/// `tokenToPosition startMap t`
// DIVERGENCE: in Haskell, a fix's replacement positions come from
// `tokenPositions` and so carry their file name. Here checks build them
// from the arena spans, which have none; a replacement with an empty file
// gets the file of the comment's token (a fix edits the file its comment
// is in).
pub fn token_to_position(pr: &ParseResult, t: TokenComment) -> PositionedComment {
    let Some((start, end)) = pr.token_positions(t.id) else {
        panic!("Internal shellcheck error: id doesn't exist. Please report!");
    };
    let fix = t.fix.map(|mut fix| {
        for r in &mut fix.replacements {
            for pos in [&mut r.start_pos, &mut r.end_pos] {
                if pos.file.is_empty() {
                    pos.file = start.file.clone();
                }
            }
        }
        fix
    });
    PositionedComment { start_pos: start, end_pos: end, comment: t.comment, fix, ..new_positioned_comment() }
}

pub fn shell_from_filename(filename: &str) -> Option<Shell> {
    let shell_extensions = [
        (".ksh", Shell::Ksh),
        (".bash", Shell::Bash),
        (".bats", Shell::Bash),
        (".dash", Shell::Dash),
        (".envrc", Shell::Bash),
    ];
    // The `.sh` is too generic to determine the shell:
    // We fallback to Bash in this case and emit SC2148 if there is no shebang
    shell_extensions.iter().find(|(ext, _)| filename.ends_with(ext)).map(|&(_, sh)| sh)
}

/// Stack size of the thread `check_script` parses and analyses on.
// Measured on 5000 nested `$(`: one nesting level costs roughly 45 KB of
// stack in a debug build and 15-25 KB in release, so 64 MB overflows at
// about 1500 (debug) / 3000-5000 (release) levels. 512 MB is address space
// reserved for the thread, not memory: only the pages actually used are
// committed.
pub const CHECK_STACK_BYTES: usize = 512 * 1024 * 1024;

/// `checkScript`
// DIVERGENCE: the parser's readers recurse once per nesting level, like the
// Haskell (whose stack lives on the heap and grows to most of RAM). Parsing
// and analysis run on a fresh thread with a `CHECK_STACK_BYTES` stack, so
// deeply nested input (5000 nested `$(` needs ~225 MB in a debug build)
// cannot overflow; nesting beyond ~10000 levels still aborts the process.
// This is why `SystemInterface` requires `Sync`.
pub fn check_script(sys: &dyn SystemInterface, spec: &CheckSpec) -> CheckResult {
    check_script_owned(sys, spec.clone())
}

/// `check_script` taking the spec by value, so the script is moved into the
/// parser instead of copied.
pub fn check_script_owned(sys: &dyn SystemInterface, mut spec: CheckSpec) -> CheckResult {
    run_on_check_stack(|| {
        let contents = std::mem::take(&mut spec.script);
        let results = check_script_contents(sys, &spec, contents);
        CheckResult { filename: spec.filename.clone(), comments: results, ..empty_check_result() }
    })
}

#[cfg(not(target_arch = "wasm32"))]
thread_local! {
    /// Set on threads started by `with_check_stack`.
    static ON_CHECK_STACK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Runs `f` on a thread with a `CHECK_STACK_BYTES` stack. `check_script`
/// calls made inside `f` run on that thread directly instead of each
/// starting their own, which saves a thread start and fresh stack pages per
/// script. Use it around a loop that checks many scripts. Stack pages a deep
/// script touches stay committed until `f` returns.
#[cfg(not(target_arch = "wasm32"))]
pub fn with_check_stack<R: Send>(f: impl FnOnce() -> R + Send) -> R {
    if ON_CHECK_STACK.get() {
        return f();
    }
    shelllint_parser::engine::with_stack(CHECK_STACK_BYTES, || {
        ON_CHECK_STACK.set(true);
        f()
    })
}

/// `wasm32-unknown-unknown` has no threads, so `f` runs on the caller's stack.
#[cfg(target_arch = "wasm32")]
pub fn with_check_stack<R>(f: impl FnOnce() -> R) -> R {
    f()
}

/// Runs `f` on a thread with a `CHECK_STACK_BYTES` stack.
#[cfg(not(target_arch = "wasm32"))]
fn run_on_check_stack<R: Send>(f: impl FnOnce() -> R + Send) -> R {
    with_check_stack(f)
}

/// `wasm32-unknown-unknown` has no threads, so `f` runs on the caller's stack.
// WASM: that stack is set at link time, not by `CHECK_STACK_BYTES`. The
// default is wasm-ld's 1 MiB, which overflows at a few hundred nested `$(`;
// the workspace `.cargo/config.toml` raises it with `-zstack-size`. The
// resulting nesting limit is not measured yet (the wasm build does not link,
// see the note in scripts/build-wasm.sh).
#[cfg(target_arch = "wasm32")]
fn run_on_check_stack<R>(f: impl FnOnce() -> R) -> R {
    f()
}

/// The `where`-bound `checkScript contents` of `checkScript`.
fn check_script_contents(sys: &dyn SystemInterface, spec: &CheckSpec, mut contents: String) -> Vec<PositionedComment> {
    // `--ignore-directives` covers the range directives too.
    let ranges = if spec.ignore_directives { None } else { directive_ranges::DirectiveRanges::scan(&contents) };
    // Only the audit needs the script twice; a normal run moves it.
    let first_pass = if spec.report_unused_disables { contents.clone() } else { std::mem::take(&mut contents) };
    let (mut all, result) = collect_messages(sys, spec, first_pass, spec.ignore_directives);
    if spec.report_unused_disables {
        // DIVERGENCE: extension (`--report-unused-disables`), see `directive_audit`.
        let (other, other_result) = collect_messages(sys, spec, contents.clone(), !spec.ignore_directives);
        let (honoured, honoured_result, ignored) =
            if spec.ignore_directives { (&other, &other_result, &all) } else { (&all, &result, &other) };
        let reports = directive_audit::unused_disable_reports(spec, &contents, honoured_result, honoured, ignored);
        all.extend(reports);
    }
    // DIVERGENCE: `--severity` beats a file-level `severity=` directive, which
    // beats one in the rc file (the root's annotations list the file's first).
    let min_severity = match result.root {
        Some(root) if !spec.min_severity_explicit => {
            get_severity_directive(&result.ast, root).unwrap_or(spec.min_severity)
        }
        _ => spec.min_severity,
    };
    let included: Vec<PositionedComment> =
        all.into_iter().filter(|pc| should_include(spec, min_severity, pc)).collect();
    let included = match &ranges {
        Some(r) => included.into_iter().filter(|pc| !r.suppresses(&spec.filename, pc)).collect(),
        None => included,
    };
    nub_sorted(sort_messages(included))
}

/// Parse and analyze `contents`: every message, before the `-S`/`-i`/`-e` filters.
fn collect_messages(
    sys: &dyn SystemInterface,
    spec: &CheckSpec,
    contents: String,
    ignore_directives: bool,
) -> (Vec<PositionedComment>, ParseResult) {
    let mut result = parse_script(
        sys,
        &ParseSpec {
            filename: spec.filename.clone(),
            script: contents,
            check_sourced: spec.check_sourced,
            ignore_rc: spec.ignore_rc,
            shell_type_override: spec.shell_type_override,
            ignore_directives,
            ..new_parse_spec()
        },
    );
    let parse_messages = std::mem::take(&mut result.comments);
    let analysis_spec = |ast: &Ast, root: Id| {
        let mut optional_checks = get_enable_directives(ast, root);
        optional_checks.extend(spec.optional_checks.iter().cloned());
        // DIVERGENCE: `external-vars` from the flag, plus directives anywhere.
        let mut external_vars = spec.external_vars.clone();
        external_vars.extend(get_external_var_directives(ast, root));
        AnalysisSpec {
            external_vars,
            shell_type: spec.shell_type_override,
            fallback_shell: shell_from_filename(&spec.filename),
            check_sourced: spec.check_sourced,
            execution_mode: ExecutionMode::Executed,
            extended_analysis: spec.extended_analysis,
            safe_vars: spec.safe_vars.clone(),
            strict_env_vars: spec.strict_env_vars,
            optional_checks,
            ..new_analysis_spec()
        }
    };
    let analysis_messages = match result.root {
        None => vec![],
        Some(root) => {
            let a_spec = analysis_spec(&result.ast, root);
            analyze_script(&a_spec, &mut result.ast, root).comments
        }
    };
    let mut all = parse_messages;
    all.extend(analysis_messages.into_iter().map(|t| token_to_position(&result, t)));
    (all, result)
}

fn should_include(spec: &CheckSpec, min_severity: Severity, pc: &PositionedComment) -> bool {
    let code = pc.comment.code;
    let severity = pc.comment.severity;
    severity <= min_severity
        && match &spec.included_warnings {
            None => !spec.excluded_warnings.contains(&code),
            Some(included_warnings) => included_warnings.contains(&code),
        }
}

/// `sortMessages = sortOn order`: by file, line, column, severity, code,
/// message (stable).
pub fn sort_messages(mut list: Vec<PositionedComment>) -> Vec<PositionedComment> {
    list.sort_by(|a, b| order(a).cmp(&order(b)));
    list
}

fn order(pc: &PositionedComment) -> (&str, i64, i64, Severity, Code, &str) {
    let pos = &pc.start_pos;
    let comment = &pc.comment;
    (&pos.file, pos.line, pos.column, comment.severity, comment.code, &comment.message)
}

/// `nub` on a list sorted by `order`.
// DIVERGENCE: Haskell's `nub` is quadratic. Equal comments have equal sort
// keys, so on a sorted list each comment is only compared with the kept
// comments in its run of equal keys; the result is the same.
fn nub_sorted(list: Vec<PositionedComment>) -> Vec<PositionedComment> {
    let mut out: Vec<PositionedComment> = Vec::with_capacity(list.len());
    let mut run_start = 0;
    for c in list {
        if out.last().is_none_or(|l| order(l) != order(&c)) {
            run_start = out.len();
        }
        if !out[run_start..].contains(&c) {
            out.push(c);
        }
    }
    out
}

// ---- harness entry point ---------------------------------------------------

/// The codes the full pipeline reports for `script`, as the oracle was run
/// for the corpus (`shellcheck -f json1 --norc -o all [-s shell] tNNNNN.sh`):
/// `mockedSystemInterface []` (nothing can be sourced), no rc file, every
/// optional check enabled. In report order.
pub fn check_script_codes(script: &str, shell: Option<Shell>) -> Vec<Code> {
    let spec = CheckSpec {
        filename: "script.sh".to_string(),
        script: script.to_string(),
        ignore_rc: true,
        shell_type_override: shell,
        optional_checks: vec!["all".to_string()],
        ..empty_check_spec()
    };
    check_script_owned(&mocked_system_interface(vec![]), spec).comments.into_iter().map(|pc| pc.comment.code).collect()
}

// ---- shellcheck.hs -----------------------------------------------------------

/// shellcheck.hs `decodeString`: decode a byte string as UTF-8, falling
/// back to ISO-8859-1 for each byte that does not start a valid sequence.
/// Like the Haskell, overlong forms are accepted.
// DIVERGENCE: the Haskell decodes UTF-16 surrogate code points (U+D800 to
// U+DFFF) to a `Char`; Rust's `char` cannot hold them, so they become
// U+FFFD, still one character (columns match the oracle's). Only message
// text that echoes such a character differs (the oracle prints it as a lone
// surrogate, e.g. SC1042 close-match text). A faithful fix would need a
// non-`str` text type through parser and checks, so it is not attempted.
pub fn decode_string(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c.is_ascii() {
            out.push(c as char);
            i += 1;
            continue;
        }
        let num = c as u32;
        let rest = &bytes[i + 1..];
        let next = if num >= 0xF8 {
            None
        } else if num >= 0xF0 {
            construct(num & 0x07, 3, rest)
        } else if num >= 0xE0 {
            construct(num & 0x0F, 2, rest)
        } else if num >= 0xC0 {
            construct(num & 0x1F, 1, rest)
        } else {
            None
        };
        match next {
            Some((n, used)) => {
                out.push(char::from_u32(n).unwrap_or('\u{FFFD}'));
                i += 1 + used;
            }
            None => {
                out.push(c as char);
                i += 1;
            }
        }
    }
    out
}

/// `construct x n rest`: the code point and the number of continuation
/// bytes consumed.
fn construct(mut x: u32, n: usize, rest: &[u8]) -> Option<(u32, usize)> {
    for k in 0..n {
        let num = *rest.get(k)? as u32;
        if !(0x80..=0xBF).contains(&num) {
            return None;
        }
        x = (x << 6) | (num & 0x3f);
    }
    (x <= 0x10FFFF).then_some((x, n))
}

#[cfg(test)]
mod tests {
    use super::*;
    use shelllint_core::interface::{Comment, Position};

    fn pc(line: i64, code: Code, end: i64) -> PositionedComment {
        let pos = |column| Position { file: "f".into(), line, column };
        PositionedComment {
            start_pos: pos(1),
            end_pos: pos(end),
            comment: Comment { severity: Severity::ErrorC, code, message: "m".into() },
            ..new_positioned_comment()
        }
    }

    #[test]
    fn nub_sorted_keeps_first_occurrences() {
        // Same key, different end positions: both kept, duplicates dropped.
        let list = sort_messages(vec![pc(1, 1, 5), pc(1, 1, 3), pc(1, 1, 5), pc(2, 1, 5), pc(1, 1, 3)]);
        let got: Vec<(i64, i64)> = nub_sorted(list).iter().map(|p| (p.start_pos.line, p.end_pos.column)).collect();
        assert_eq!(got, vec![(1, 5), (1, 3), (2, 5)]);
    }

    #[test]
    fn nub_token_comments_keeps_first_occurrences() {
        let tc = |id: u32, code: Code, msg: &str| TokenComment {
            id: Id(id),
            comment: Comment { severity: Severity::InfoC, code, message: msg.into() },
            fix: None,
        };
        let got = nub_token_comments(vec![tc(1, 2, "a"), tc(1, 2, "b"), tc(1, 2, "a"), tc(2, 2, "a"), tc(2, 2, "a")]);
        assert_eq!(got, vec![tc(1, 2, "a"), tc(1, 2, "b"), tc(2, 2, "a")]);
    }

    #[test]
    fn shell_from_filename_cases() {
        assert_eq!(shell_from_filename("a.ksh"), Some(Shell::Ksh));
        assert_eq!(shell_from_filename("x/.envrc"), Some(Shell::Bash));
        assert_eq!(shell_from_filename("a.bats"), Some(Shell::Bash));
        assert_eq!(shell_from_filename("a.dash"), Some(Shell::Dash));
        assert_eq!(shell_from_filename("a.sh"), None);
    }
}
