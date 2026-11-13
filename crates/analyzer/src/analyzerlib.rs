// SPDX-License-Identifier: GPL-3.0-or-later
// Port of ShellCheck src/ShellCheck/AnalyzerLib.hs (e11f964)
//
// DIVERGENCE: the `RWS Parameters [TokenComment] Cache` monad (`AnalyzerM`)
// is replaced by explicit arguments: an `Analysis` is a function taking
// `&Params` (the Reader), the token `Id`, and `&mut Comments` (the Writer).
// `Cache` is an empty record in Haskell and is not ported.
//
// DIVERGENCE: `Parameters`' `idMap`, `parentMap`, `rootNode` and
// `tokenPositions` are covered by the arena: `params.ast.get(id)`,
// `params.ast.parent(id)`, `params.root` and `params.ast.span(id)`. Every
// function that takes the Haskell `parentMap` (`tree`) takes the `&Ast`
// instead, whose parents must have been recorded with
// `Ast::compute_parents(root)`. `getParentTree` and `getTokenMap` are
// therefore not ported.
//
// Not ported: the TemplateHaskell `runTests` footer (the `prop_` definitions
// live in `crates/analyzer/tests/analyzerlib.rs`), and `literalizer` (unused
// in `getReferencedVariables`).

use std::cell::RefCell;
use std::sync::LazyLock;

use regex::Regex;
use shelllint_core::ast::{Annotation, AssignmentMode, Ast, ConditionType, Id, Token};
use shelllint_core::data::{FLAGS_FOR_READ, shell_for_executable};
use shelllint_core::interface::{
    AnalysisSpec, Code, Comment, Fix, ParseSpec, Severity, Shell, TokenComment, mocked_system_interface,
    new_analysis_spec, new_parse_spec,
};
use shelllint_core::regex::{match_all_submatches, matches, mk_regex};
use shelllint_parser::{ParseResult, parse_script};

use crate::astlib::*;
use crate::cfg::CfgParameters;

/// `type Analysis = AnalyzerM ()`: a check run on one token.
pub type Analysis = dyn Fn(&Params<'_>, Id, &mut Comments);

/// `data Checker = Checker { perScript, perToken }`
// DIVERGENCE: `perScript`/`perToken` are single functions composed with
// `composeAnalyzers` (`f x >> g x`). Here each is the list of the composed
// functions, run in order; `nullCheck` is the empty list.
#[derive(Default)]
pub struct Checker {
    pub per_script: Vec<Box<Analysis>>,
    pub per_token: Vec<Box<Analysis>>,
}

/// `runChecker`: run every `perScript` on the root in order, then walk the
/// tree once (pre-order, `doAnalysis`) calling every `perToken` at each node.
pub fn run_checker(params: &Params<'_>, checker: &Checker) -> Vec<TokenComment> {
    let root = params.root;
    let mut notes = Comments::new();
    for f in &checker.per_script {
        f(params, root, &mut notes);
    }
    if !checker.per_token.is_empty() {
        params.ast.analyze(
            root,
            &mut |t| {
                for f in &checker.per_token {
                    f(params, t, &mut notes);
                }
            },
            &mut |_| {},
        );
    }
    notes.into_vec()
}

impl Checker {
    /// `instance Semigroup Checker`: `x <> y`
    pub fn compose(mut self, mut other: Checker) -> Checker {
        self.per_script.append(&mut other.per_script);
        self.per_token.append(&mut other.per_token);
        self
    }

    /// `mconcat`
    pub fn mconcat(list: impl IntoIterator<Item = Checker>) -> Checker {
        list.into_iter().fold(Checker::default(), Checker::compose)
    }
}

/// `CF.CFGAnalysis`; see `crate::cfg_analysis` for the query API.
pub use crate::cfg_analysis::CfgAnalysis;

/// `data Parameters`
#[derive(Clone, Debug)]
pub struct Params<'a> {
    /// Replaces `idMap` (`ast.get`), `parentMap` (`ast.parent`) and
    /// `tokenPositions` (`ast.span`).
    pub ast: &'a Ast,
    /// The root node of the AST (`rootNode`)
    pub root: Id,
    /// Whether this script has 'set -a' or 'set -o allexport' anywhere.
    pub has_allexport: bool,
    /// Whether this script has the 'lastpipe' option set/default.
    pub has_lastpipe: bool,
    /// Whether this script has the 'inherit_errexit' option set/default.
    pub has_inherit_errexit: bool,
    /// Whether this script has 'set -e' or 'set -o errexit' anywhere.
    pub has_errexit: bool,
    /// Whether this script has 'set -f' or 'set -o noglob' anywhere.
    pub has_noglob: bool,
    /// Whether this script has 'set -o pipefail' anywhere.
    pub has_pipefail: bool,
    /// Whether this script has 'shopt -s execfail' anywhere.
    pub has_execfail: bool,
    /// DIVERGENCE: `--modern-dialects` / `modern-dialects=true` (shelllint extension).
    pub modern_dialects: bool,
    /// A linear (bad) analysis of data flow
    pub variable_flow: VariableFlow,
    /// The shell type, such as Bash or Ksh
    pub shell_type: Shell,
    /// True if shell type was forced via flags
    pub shell_type_specified: bool,
    /// Result from Control Flow Graph analysis (including data flow analysis)
    // DIVERGENCE: behind an `Rc` so that cloning `Params` (e.g.
    // `Scratch::params`) does not copy the analysis. Use
    // `params.cfg_analysis.as_deref()` for Haskell's `cfgAnalysis params`.
    pub cfg_analysis: Option<std::rc::Rc<CfgAnalysis>>,
    /// Not in Haskell: a reusable copy of `ast` for `checkCommand`'s
    /// synthetic `builtin X` commands (see `api::check_command`). Cloning
    /// `Params` gives the clone an empty one.
    pub builtin_scratch: BuiltinScratch,
    /// Not in Haskell: `external-vars` names (a trailing `*` is a prefix
    /// glob) that SC2154 treats as assigned.
    pub external_vars: Vec<String>,
    /// Not in upstream: variables from `safe-vars` (no spaces or globs).
    pub safe_vars: std::rc::Rc<Vec<String>>,
    /// Not in upstream: `strict-env-vars` (uppercase names get SC2154 too).
    pub strict_env_vars: bool,
}

/// `variableFlow :: [StackData]`
// DIVERGENCE (performance only): shared behind an `Rc`, so cloning `Params`
// does not copy it. It derefs to the `Vec` and iterates like one.
#[derive(Clone, Debug, Default)]
pub struct VariableFlow(std::rc::Rc<Vec<StackData>>);

impl From<Vec<StackData>> for VariableFlow {
    fn from(v: Vec<StackData>) -> Self {
        VariableFlow(std::rc::Rc::new(v))
    }
}

impl std::ops::Deref for VariableFlow {
    type Target = Vec<StackData>;
    fn deref(&self) -> &Vec<StackData> {
        &self.0
    }
}

impl<'b> IntoIterator for &'b VariableFlow {
    type Item = &'b StackData;
    type IntoIter = std::slice::Iter<'b, StackData>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

/// A lazily made copy of `Params::ast`, reused by every `builtin X`
/// command of the script instead of copying the arena per command.
#[derive(Default)]
pub struct BuiltinScratch(pub(crate) RefCell<Option<Ast>>);

impl Clone for BuiltinScratch {
    /// A clone may point at a different `ast`, so it starts empty.
    fn clone(&self) -> Self {
        BuiltinScratch::default()
    }
}

impl std::fmt::Debug for BuiltinScratch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BuiltinScratch")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scope {
    SubshellScope(String),
    FunctionScope,
    NoneScope,
}

#[derive(Clone, Debug)]
pub enum StackData {
    StackScope(Scope),
    StackScopeEnd,
    /// (Base expression, specific position, var name, assigned values)
    Assignment(Id, Id, String, DataType),
    Reference(Id, Id, String),
}

#[derive(Clone, Debug)]
pub enum DataType {
    DataString(DataSource),
    DataArray(DataSource),
}

#[derive(Clone, Debug)]
pub enum DataSource {
    SourceFrom(Vec<Id>),
    SourceExternal,
    SourceDeclaration,
    SourceInteger,
    SourceChecked,
}

#[derive(Clone, Debug)]
pub enum VariableState {
    Dead(Id, String),
    Alive,
}

/// `defaultSpec pr`
// The Haskell sets `asScript`/`asTokenPositions` from `pr`; those live in the
// arena here, so `pr` is unused.
pub fn default_spec(_pr: &ParseResult) -> AnalysisSpec {
    AnalysisSpec {
        shell_type: None,
        check_sourced: false,
        execution_mode: shelllint_core::interface::ExecutionMode::Executed,
        ..new_analysis_spec()
    }
}

/// `pScript s`
pub fn p_script(s: &str) -> ParseResult {
    let p_spec = ParseSpec { filename: "script".to_string(), script: s.to_string(), ..new_parse_spec() };
    parse_script(&mocked_system_interface(vec![]), &p_spec)
}

/// For testing. If parsed, returns whether there are any comments
pub fn produces_comments(c: &Checker, s: &str) -> Option<bool> {
    run_and_get_codes(c, s).map(|codes| !codes.is_empty())
}

/// If parsed, returns the list of codes
pub fn run_and_get_codes(c: &Checker, s: &str) -> Option<Vec<Code>> {
    let mut pr = p_script(s);
    let root = pr.root?;
    pr.ast.compute_parents(root);
    let spec = default_spec(&pr);
    let params = make_parameters(&spec, &pr.ast, root);
    let mut codes: Vec<Code> =
        filter_by_annotation(&spec, &params, run_checker(&params, c)).into_iter().map(|tc| tc.comment.code).collect();
    codes.sort();
    Some(codes)
}

pub fn make_comment(severity: Severity, id: Id, code: Code, note: impl Into<String>) -> TokenComment {
    TokenComment { id, comment: Comment { severity, code, message: note.into() }, fix: None }
}

/// The Writer half of `AnalyzerM`: the comments a check emits, in order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Comments(pub Vec<TokenComment>);

impl Comments {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn into_vec(self) -> Vec<TokenComment> {
        self.0
    }

    /// `addComment note` (`tell [note]`)
    pub fn add_comment(&mut self, note: TokenComment) {
        self.0.push(note);
    }

    /// `tell notes` for a list of comments
    pub fn tell(&mut self, notes: impl IntoIterator<Item = TokenComment>) {
        self.0.extend(notes);
    }

    pub fn warn(&mut self, id: Id, code: Code, str: impl Into<String>) {
        self.add_comment(make_comment(Severity::WarningC, id, code, str));
    }

    pub fn err(&mut self, id: Id, code: Code, str: impl Into<String>) {
        self.add_comment(make_comment(Severity::ErrorC, id, code, str));
    }

    pub fn info(&mut self, id: Id, code: Code, str: impl Into<String>) {
        self.add_comment(make_comment(Severity::InfoC, id, code, str));
    }

    pub fn style(&mut self, id: Id, code: Code, str: impl Into<String>) {
        self.add_comment(make_comment(Severity::StyleC, id, code, str));
    }

    pub fn err_with_fix(&mut self, id: Id, code: Code, str: impl Into<String>, fix: Fix) {
        self.add_comment_with_fix(Severity::ErrorC, id, code, str, fix);
    }

    pub fn warn_with_fix(&mut self, id: Id, code: Code, str: impl Into<String>, fix: Fix) {
        self.add_comment_with_fix(Severity::WarningC, id, code, str, fix);
    }

    pub fn info_with_fix(&mut self, id: Id, code: Code, str: impl Into<String>, fix: Fix) {
        self.add_comment_with_fix(Severity::InfoC, id, code, str, fix);
    }

    pub fn style_with_fix(&mut self, id: Id, code: Code, str: impl Into<String>, fix: Fix) {
        self.add_comment_with_fix(Severity::StyleC, id, code, str, fix);
    }

    pub fn add_comment_with_fix(&mut self, severity: Severity, id: Id, code: Code, str: impl Into<String>, fix: Fix) {
        self.add_comment(make_comment_with_fix(severity, id, code, str, fix));
    }
}

pub fn make_comment_with_fix(severity: Severity, id: Id, code: Code, str: impl Into<String>, fix: Fix) -> TokenComment {
    let comment = make_comment(severity, id, code, str);
    TokenComment {
        // If fix is empty, pretend it wasn't there.
        fix: if fix.replacements.is_empty() { None } else { Some(fix) },
        ..comment
    }
}

/// DIVERGENCE: internal name under which `--modern-dialects` and the
/// `modern-dialects=true` rc key travel in `AnalysisSpec::optional_checks`.
/// It is not a registered optional check, so `--enable=all` does not select it.
pub const MODERN_DIALECTS: &str = "modern-dialects";

/// DIVERGENCE: does the script's shebang name ash or busybox? Used by `--modern-dialects`.
pub fn shebang_names_ash(ast: &Ast, root: Id) -> bool {
    let script = match ast.get(root) {
        Token::T_Annotation(_, s) => *s,
        _ => root,
    };
    match ast.get(script) {
        Token::T_Script(sb, _) => match ast.get(*sb) {
            Token::T_Literal(s) => {
                matches!(executable_from_shebang(s).as_str(), "ash" | "busybox" | "busybox sh" | "busybox ash")
            }
            _ => false,
        },
        _ => false,
    }
}

/// `makeParameters spec`. `ast` must have had `compute_parents(root)` called.
// DIVERGENCE: `variableFlow` refers to `params` lazily in Haskell; here the
// other fields are computed first and the flow is filled in afterwards.
pub fn make_parameters<'a>(spec: &AnalysisSpec, ast: &'a Ast, root: Id) -> Params<'a> {
    debug_assert!(
        ast.children(root).all(|c| ast.parent(c) == Some(root)),
        "make_parameters: call Ast::compute_parents(root) first"
    );
    let extended_analysis =
        spec.extended_analysis.or_else(|| get_extended_analysis_directive(ast, root)).unwrap_or(true);
    let mut safe_vars = spec.safe_vars.clone();
    safe_vars.extend(shelllint_core::astlib::get_safe_vars_directive(ast, root));
    let shell_type = spec.shell_type.unwrap_or_else(|| determine_shell(ast, spec.fallback_shell, root));
    let mut params = Params {
        external_vars: spec.external_vars.clone(),
        ast,
        root,
        shell_type,
        has_allexport: contains_allexport(ast, root),
        has_errexit: contains_errexit(ast, root),
        has_noglob: contains_noglob(ast, root),
        has_lastpipe: match shell_type {
            Shell::Bash => is_option_set(ast, "lastpipe", root),
            Shell::Dash => false,
            Shell::BusyboxSh => false,
            Shell::Sh => false,
            Shell::Ksh => true,
        },
        has_inherit_errexit: match shell_type {
            Shell::Bash => is_option_set(ast, "inherit_errexit", root),
            Shell::Dash => true,
            Shell::BusyboxSh => true,
            Shell::Sh => true,
            Shell::Ksh => false,
        },
        has_pipefail: match shell_type {
            Shell::Bash => is_option_set(ast, "pipefail", root),
            Shell::Dash => is_option_set(ast, "pipefail", root),
            Shell::BusyboxSh => is_option_set(ast, "pipefail", root),
            Shell::Sh => is_option_set(ast, "pipefail", root),
            Shell::Ksh => is_option_set(ast, "pipefail", root),
        },
        has_execfail: match shell_type {
            Shell::Bash => is_option_set(ast, "execfail", root),
            _ => false,
        },
        modern_dialects: spec.optional_checks.iter().any(|k| k == MODERN_DIALECTS),
        shell_type_specified: spec.shell_type.is_some() || spec.fallback_shell.is_some(),
        variable_flow: VariableFlow::default(),
        cfg_analysis: None,
        builtin_scratch: BuiltinScratch::default(),
        safe_vars: std::rc::Rc::new(safe_vars),
        strict_env_vars: spec
            .strict_env_vars
            .or_else(|| shelllint_core::astlib::get_strict_env_vars_directive(ast, root))
            .unwrap_or(false),
    };
    params.variable_flow = get_variable_flow(&params, root).into();
    // `cfgAnalysis = do guard extendedAnalysis; return $ CF.analyzeControlFlow cfParams root`
    let cf_params = CfgParameters { cf_lastpipe: params.has_lastpipe, cf_pipefail: params.has_pipefail };
    params.cfg_analysis = if extended_analysis {
        Some(std::rc::Rc::new(crate::cfg_analysis::analyze_control_flow_with(&cf_params, &params.safe_vars, ast, root)))
    } else {
        None
    };
    params
}

/// `isNothing $ doAnalysis (guard . not . p) root`: does any token match?
fn any_token(ast: &Ast, root: Id, p: &dyn Fn(Id) -> bool) -> bool {
    let mut stack = vec![root];
    while let Some(t) = stack.pop() {
        if p(t) {
            return true;
        }
        stack.extend(ast.children(t));
    }
    false
}

/// `[[:space:]]-[^-]*<c>`, compiled once per ASCII flag letter: every script
/// asks about `-a` and `-e`, and compiling the regex dominated the lookup.
fn short_flag_regex(short_opt: char) -> std::borrow::Cow<'static, Regex> {
    static CACHE: [std::sync::OnceLock<Regex>; 128] = [const { std::sync::OnceLock::new() }; 128];
    let compile = || mk_regex(&format!("[[:space:]]-[^-]*{short_opt}"));
    match CACHE.get(short_opt as usize) {
        Some(slot) => std::borrow::Cow::Borrowed(slot.get_or_init(compile)),
        None => std::borrow::Cow::Owned(compile()),
    }
}

/// detect e.g. 'set -o errexit' or 'set -e'
pub fn is_option_set_(ast: &Ast, long_opt: &str, short_opt: char, root: Id) -> bool {
    let re = short_flag_regex(short_opt);
    let is_set_option = |t: Id| match ast.get(t) {
        Token::T_Script(sb, _) => match ast.get(*sb) {
            Token::T_Literal(str) => matches(str, &re),
            _ => false,
        },
        Token::T_SimpleCommand(..) => {
            is_unqualified_command(ast, t, "set")
                && (oversimplify(ast, t).iter().any(|s| s == long_opt)
                    || get_all_flags(ast, t).iter().any(|(_, f)| *f == short_opt.to_string()))
        }
        _ => false,
    };
    any_token(ast, root, &is_set_option)
}

pub fn contains_allexport(ast: &Ast, root: Id) -> bool {
    is_option_set_(ast, "allexport", 'a', root)
}

/// Does this script mention 'set -e' anywhere?
/// Used as a hack to disable certain warnings.
pub fn contains_errexit(ast: &Ast, root: Id) -> bool {
    is_option_set_(ast, "errexit", 'e', root)
}

pub fn contains_noglob(ast: &Ast, root: Id) -> bool {
    is_option_set_(ast, "noglob", 'f', root)
}

pub fn contains_set_option(ast: &Ast, opt: &str, root: Id) -> bool {
    let is_pipefail = |t: Id| match ast.get(t) {
        Token::T_SimpleCommand(..) => {
            is_unqualified_command(ast, t, "set")
                && (oversimplify(ast, t).iter().any(|s| s == opt)
                    || get_all_flags(ast, t).iter().any(|(_, f)| f == "o"))
        }
        _ => false,
    };
    any_token(ast, root, &is_pipefail)
}

pub fn contains_shopt(ast: &Ast, shopt: &str, root: Id) -> bool {
    let is_shopt_last_pipe = |t: Id| match ast.get(t) {
        Token::T_SimpleCommand(..) => {
            is_unqualified_command(ast, t, "shopt") && oversimplify(ast, t).iter().any(|s| s == shopt)
        }
        _ => false,
    };
    any_token(ast, root, &is_shopt_last_pipe)
}

/// Does this script mention 'shopt -s $opt' or 'set -o $opt' anywhere?
pub fn is_option_set(ast: &Ast, opt: &str, root: Id) -> bool {
    contains_shopt(ast, opt, root) || contains_set_option(ast, opt, root)
}

pub fn determine_shell_test(s: &str) -> Shell {
    determine_shell_test_(None, s)
}

pub fn determine_shell_test_(fallback_shell: Option<Shell>, s: &str) -> Shell {
    let pr = p_script(s);
    let root = pr.root.expect("fromJust: script did not parse");
    determine_shell(&pr.ast, fallback_shell, root)
}

pub fn determine_shell(ast: &Ast, fallback_shell: Option<Shell>, t: Id) -> Shell {
    let from_shebang = |t: Id| -> String {
        match ast.get(t) {
            Token::T_Script(sb, _) => match ast.get(*sb) {
                Token::T_Literal(s) => executable_from_shebang(s),
                _ => panic!("determineShell: non-literal shebang"),
            },
            _ => panic!("determineShell: not a T_Script"),
        }
    };
    let get_candidate = |t: Id| -> String {
        match ast.get(t) {
            Token::T_Script(..) => from_shebang(t),
            Token::T_Annotation(annotations, s) => annotations
                .iter()
                .find_map(|a| match a {
                    Annotation::ShellOverride(s) => Some(s.clone()),
                    _ => None,
                })
                // DIVERGENCE: the shell of a nix-shell shebang's `-i`.
                .or_else(|| {
                    annotations.iter().find_map(|a| match a {
                        Annotation::ShellFromNix(s) => Some(s.clone()),
                        _ => None,
                    })
                })
                .unwrap_or_else(|| from_shebang(*s)),
            _ => panic!("determineShell: unexpected root"),
        }
    };
    let shell_string = get_candidate(t);
    shell_for_executable(&shell_string).or(fallback_shell).unwrap_or(Shell::Bash)
}

/// Is this token in a quoting free context? (i.e. would variable expansion split)
/// True:  Assignments, [[ .. ]], here docs, already in double quotes
/// False: Regular words
pub fn is_strictly_quote_free(ast: &Ast, shell: Shell, t: Id) -> bool {
    is_quote_free_node(ast, true, shell, t)
}

/// Like above, but also allow some cases where splitting may be desired.
/// True:  Like above + for loops
/// False: Like above
pub fn is_quote_free(ast: &Ast, shell: Shell, t: Id) -> bool {
    is_quote_free_node(ast, false, shell, t)
}

pub fn is_quote_free_node(ast: &Ast, strict: bool, shell: Shell, t: Id) -> bool {
    // Is this assignment a parameter to a command like export/typeset/etc?
    let is_assignment_param_to_command = |id: Id| match ast.parent(id).map(|p| ast.get(p)) {
        Some(Token::T_SimpleCommand(_, words)) if !words.is_empty() => words[1..].contains(&id),
        _ => false,
    };
    // Check whether this assignment is self-quoting due to being a recognized
    // assignment passed to a Declaration Utility. This will soon be required
    // by POSIX: https://austingroupbugs.net/view.php?id=351
    let shell_parses_params_as_assignments = shell != Shell::Sh;
    let assignment_is_quoting = |id: Id| shell_parses_params_as_assignments || !is_assignment_param_to_command(id);
    // Is this node self-quoting in itself?
    let is_quote_free_element = |t: Id| match ast.get(t) {
        Token::T_Assignment(..) => assignment_is_quoting(t),
        Token::T_FdRedirect(..) => true,
        _ => false,
    };
    // Are any subnodes inherently self-quoting?
    let is_quote_free_context = |t: Id| -> Option<bool> {
        use ConditionType::DoubleBracket;
        match ast.get(t) {
            Token::TC_Nullary(DoubleBracket, _) => Some(true),
            Token::TC_Unary(DoubleBracket, _, _) => Some(true),
            Token::TC_Binary(DoubleBracket, _, _, _) => Some(true),
            Token::TA_Sequence(..) => Some(true),
            Token::T_Arithmetic(..) => Some(true),
            Token::T_Assignment(..) => Some(assignment_is_quoting(t)),
            Token::T_Redirecting(..) => Some(false),
            Token::T_DoubleQuoted(..) => Some(true),
            Token::T_DollarDoubleQuoted(..) => Some(true),
            Token::T_CaseExpression(..) => Some(true),
            Token::T_HereDoc(..) => Some(true),
            Token::T_DollarBraced(..) => Some(true),
            // When non-strict, pragmatically assume it's desirable to split here
            Token::T_ForIn(..) => Some(!strict),
            Token::T_SelectIn(..) => Some(!strict),
            _ => None,
        }
    };
    is_quote_free_element(t) || path_iter(ast, t).skip(1).find_map(is_quote_free_context).unwrap_or(false)
}

/// Check if a token is a parameter to a certain command by name:
/// Example: isParamTo (parentMap params) "sed" t
pub fn is_param_to(ast: &Ast, cmd: &str, t: Id) -> bool {
    let mut x = t;
    loop {
        let Some(parent) = ast.parent(x) else { return false };
        match ast.get(parent) {
            Token::T_SingleQuoted(_) | Token::T_DoubleQuoted(_) | Token::T_NormalWord(_) => {
                x = parent;
            }
            Token::T_SimpleCommand(..) | Token::T_Redirecting(..) => {
                return is_command(ast, parent, cmd);
            }
            _ => return false,
        }
    }
}

/// Get the parent command (T_Redirecting) of a Token, if any.
pub fn get_closest_command(ast: &Ast, t: Id) -> Option<Id> {
    let find_command = |t: &Id| match ast.get(*t) {
        Token::T_Redirecting(..) => Some(true),
        Token::T_Script(..) => Some(false),
        _ => None,
    };
    for x in path_iter(ast, t) {
        match find_command(&x) {
            Some(true) => return Some(x),
            Some(false) => return None,
            None => {}
        }
    }
    None
}

/// Like above, if koala_man knew Haskell when starting this project.
pub fn get_closest_command_m(params: &Params<'_>, t: Id) -> Option<Id> {
    get_closest_command(params.ast, t)
}

/// Is the token used as a command name (the first word in a T_SimpleCommand)?
pub fn used_as_command_name(ast: &Ast, token: Id) -> bool {
    let mut current_id = token;
    for t in path_iter(ast, token).skip(1) {
        match ast.get(t) {
            Token::T_NormalWord(l) | Token::T_DoubleQuoted(l) if l.len() == 1 && l[0] == current_id => {
                current_id = t;
            }
            Token::T_SimpleCommand(_, words) if !words.is_empty() => {
                return words[0] == current_id || get_command_token_or_this(ast, t) == current_id;
            }
            _ => return false,
        }
    }
    false
}

/// `getPath` as a lazy iterator (the token, then its parents), for the
/// callers that stop early: Haskell's `getPath` list is lazy, and
/// materialising it is O(depth) per call.
fn path_iter(ast: &Ast, t: Id) -> impl Iterator<Item = Id> + '_ {
    std::iter::successors(Some(t), |&x| ast.parent(x))
}

/// Version of the above taking the map from the current context
/// Todo: give this the name "getPath"
pub fn get_path_m(params: &Params<'_>, t: Id) -> Vec<Id> {
    get_path(params.ast, t)
}

pub fn is_parent_of(ast: &Ast, parent: Id, child: Id) -> bool {
    path_iter(ast, child).any(|x| x == parent)
}

pub fn parents(params: &Params<'_>, t: Id) -> Vec<Id> {
    get_path(params.ast, t)
}

/// Find the first match in a list where the predicate is Just True.
/// Stops if it's Just False and ignores Nothing.
pub fn find_first<T>(p: impl Fn(&T) -> Option<bool>, list: &[T]) -> Option<&T> {
    for x in list {
        match p(x) {
            Some(true) => return Some(x),
            Some(false) => return None,
            None => {}
        }
    }
    None
}

/// Check whether a word is entirely output from a single command
pub fn token_is_just_command_output(ast: &Ast, t: Id) -> bool {
    let check = |cmds: &[Id]| cmds.len() == 1 && !is_only_redirection(ast, cmds[0]);
    let expansion = |p: Id| match ast.get(p) {
        Token::T_DollarExpansion(cmds) | Token::T_Backticked(cmds) => Some(cmds),
        _ => None,
    };
    match ast.get(t) {
        Token::T_NormalWord(parts) if parts.len() == 1 => {
            if let Some(cmds) = expansion(parts[0]) {
                return check(cmds);
            }
            match ast.get(parts[0]) {
                Token::T_DoubleQuoted(inner) if inner.len() == 1 => expansion(inner[0]).is_some_and(|cmds| check(cmds)),
                _ => false,
            }
        }
        _ => false,
    }
}

/// TODO: Replace this with a proper Control Flow Graph
pub fn get_variable_flow(params: &Params<'_>, t: Id) -> Vec<StackData> {
    let ast = params.ast;
    // DIVERGENCE: the Haskell prepends to a list and reverses it at the end;
    // appending gives the same order.
    let state = RefCell::new(Vec::new());
    let assign_first = |t: Id| matches!(ast.get(t), Token::T_ForIn(..) | Token::T_SelectIn(..) | Token::T_BatsTest(..));
    let set_read = |t: Id| {
        let read = get_referenced_variables(ast, t);
        state.borrow_mut().extend(read.into_iter().map(|(a, b, c)| StackData::Reference(a, b, c)));
    };
    let set_written = |t: Id| {
        let written = get_modified_variables(ast, t);
        state.borrow_mut().extend(written.into_iter().map(|(a, b, c, d)| StackData::Assignment(a, b, c, d)));
    };
    let start_scope = |t: Id| {
        let scope_type = lead_type(params, t);
        if scope_type != Scope::NoneScope {
            state.borrow_mut().push(StackData::StackScope(scope_type));
        }
        if assign_first(t) {
            set_written(t);
        }
    };
    let end_scope = |t: Id| {
        let scope_type = lead_type(params, t);
        set_read(t);
        if !assign_first(t) {
            set_written(t);
        }
        if scope_type != Scope::NoneScope {
            state.borrow_mut().push(StackData::StackScopeEnd);
        }
    };
    ast.analyze(t, &mut |x| start_scope(x), &mut |x| end_scope(x));
    state.into_inner()
}

pub fn lead_type(params: &Params<'_>, t: Id) -> Scope {
    let ast = params.ast;
    let parent_pipeline = || -> Option<Id> {
        let parent = ast.parent(t)?;
        match ast.get(parent) {
            Token::T_Pipeline(..) => Some(parent),
            _ => None,
        }
    };
    let causes_subshell = || -> Option<bool> {
        let Token::T_Pipeline(_, list) = ast.get(parent_pipeline()?) else {
            return None;
        };
        Some(if list.len() >= 2 { !params.has_lastpipe || *list.last().expect("non-empty") != t } else { false })
    };
    match ast.get(t) {
        Token::T_DollarExpansion(_) => Scope::SubshellScope("$(..) expansion".to_string()),
        Token::T_Backticked(_) => Scope::SubshellScope("`..` expansion".to_string()),
        Token::T_Backgrounded(_) => Scope::SubshellScope("backgrounding &".to_string()),
        Token::T_Subshell(_) => Scope::SubshellScope("(..) group".to_string()),
        Token::T_BatsTest(..) => Scope::SubshellScope("@bats test".to_string()),
        Token::T_CoProcBody(_) => Scope::SubshellScope("coproc".to_string()),
        Token::T_Function(..) => Scope::FunctionScope,
        Token::T_Redirecting(..) => {
            if causes_subshell() == Some(true) {
                Scope::SubshellScope("pipeline".to_string())
            } else {
                Scope::NoneScope
            }
        }
        _ => Scope::NoneScope,
    }
}

/// `(base, token, name, value)` as produced by the getModifiedVariables family.
pub type ModifiedVariable = (Id, Id, String, DataType);
/// `(base, token, name)` as produced by the getReferencedVariables family.
pub type ReferencedVariable = (Id, Id, String);

pub fn get_modified_variables(ast: &Ast, t: Id) -> Vec<ModifiedVariable> {
    use DataSource::*;
    use DataType::*;
    // markAsChecked place token = mapMaybe (f place) $ getWordParts token
    let mark_as_checked = |place: Id, token: Id| -> Vec<ModifiedVariable> {
        get_word_parts(ast, token)
            .into_iter()
            .filter_map(|t| match ast.get(t) {
                Token::T_DollarBraced(_, l) => {
                    let str = get_braced_reference(&oversimplify(ast, *l).concat());
                    if !is_variable_name(&str) {
                        return None;
                    }
                    Some((place, t, str, DataString(SourceChecked)))
                }
                _ => None,
            })
            .collect()
    };
    match ast.get(t) {
        Token::T_SimpleCommand(vars, words) if words.is_empty() => vars
            .iter()
            .filter_map(|&x| match ast.get(x) {
                Token::T_Assignment(_, name, _, w) => Some((x, x, name.clone(), data_type_from(ast, DataString, *w))),
                _ => None,
            })
            .collect(),
        Token::T_SimpleCommand(..) => get_modified_variable_command(ast, t),

        Token::TA_Unary(op, v) if op.contains("--") || op.contains("++") => match ast.get(*v) {
            Token::TA_Variable(name, _) => vec![(t, *v, name.clone(), DataString(SourceInteger))],
            _ => vec![],
        },
        Token::TA_Assignment(op, lhs, _rhs) => match ast.get(*lhs) {
            Token::TA_Variable(name, _)
                if ["=", "*=", "/=", "%=", "+=", "-=", "<<=", ">>=", "&=", "^=", "|="].contains(&op.as_str()) =>
            {
                vec![(t, t, name.clone(), DataString(SourceInteger))]
            }
            _ => vec![],
        },

        Token::T_BatsTest(..) => vec![
            (t, t, "lines".to_string(), DataArray(SourceExternal)),
            (t, t, "status".to_string(), DataString(SourceInteger)),
            (t, t, "output".to_string(), DataString(SourceExternal)),
            (t, t, "stderr".to_string(), DataString(SourceExternal)),
            (t, t, "stderr_lines".to_string(), DataArray(SourceExternal)),
        ],

        // Count [[ -v foo ]] as an "assignment".
        // This is to prevent [ -v foo ] being unassigned or unused.
        Token::TC_Unary(_, op, token) if op == "-v" => get_variable_for_test_dash_v(ast, *token)
            .map(|str| (t, *token, str, DataString(SourceChecked)))
            .into_iter()
            .collect(),

        Token::TC_Unary(_, op, token) if op == "-n" => mark_as_checked(t, *token),
        Token::TC_Unary(_, op, token) if op == "-z" => mark_as_checked(t, *token),
        Token::TC_Nullary(_, token) => mark_as_checked(t, *token),

        Token::T_DollarBraced(_, l) => {
            let string = oversimplify(ast, *l).concat();
            let modifier = get_braced_modifier(&string);
            if ["=", ":="].iter().any(|p| modifier.starts_with(p)) {
                vec![(t, t, get_braced_reference(&string), DataString(SourceFrom(vec![*l])))]
            } else {
                vec![]
            }
        }

        // {foo}>&2 modifies foo
        Token::T_FdRedirect(fd, op) if fd.starts_with('{') => {
            if is_closing_file_op(ast, *op) {
                vec![]
            } else {
                let var: String = fd[1..].chars().take_while(|&c| c != '}').collect();
                vec![(t, t, var, DataString(SourceInteger))]
            }
        }

        Token::T_CoProc(None, _) => vec![(t, t, "COPROC".to_string(), DataArray(SourceInteger))],

        Token::T_CoProc(Some(token), _) => {
            get_literal_string(ast, *token).map(|name| (t, t, name, DataArray(SourceInteger))).into_iter().collect()
        }

        //Points to 'for' rather than variable
        Token::T_ForIn(str, words, _) if words.is_empty() => {
            vec![(t, t, str.clone(), DataString(SourceExternal))]
        }
        Token::T_ForIn(str, words, _) => vec![(t, t, str.clone(), DataString(SourceFrom(words.clone())))],
        Token::T_SelectIn(str, words, _) => {
            vec![(t, t, str.clone(), DataString(SourceFrom(words.clone())))]
        }
        _ => vec![],
    }
}

/// Variables set by bats' run command
pub fn get_bats_run_variables(ast: &Ast, args: &[Id]) -> Vec<(String, DataType)> {
    use DataSource::*;
    use DataType::*;
    let opts: Vec<String> = args
        .iter()
        .map(|&a| get_literal_string(ast, a).unwrap_or_default())
        .take_while(|s| s == "!" || (s != "--" && s.starts_with('-')))
        .collect();
    let mut out = vec![
        ("status".to_string(), DataString(SourceInteger)),
        ("output".to_string(), DataString(SourceExternal)),
        ("lines".to_string(), DataArray(SourceExternal)),
    ];
    if opts.iter().any(|o| o == "--separate-stderr") {
        out.push(("stderr".to_string(), DataString(SourceExternal)));
        out.push(("stderr_lines".to_string(), DataArray(SourceExternal)));
    }
    out
}

/// `T_SimpleCommand _ _ (T_NormalWord _ (T_Literal _ x:_):rest)`: the
/// command's literal first-part string and its remaining words.
fn literal_command<'t>(ast: &Ast, words: &'t [Id]) -> Option<(String, &'t [Id])> {
    let (&first, rest) = words.split_first()?;
    let Token::T_NormalWord(parts) = ast.get(first) else { return None };
    match ast.get(*parts.first()?) {
        Token::T_Literal(x) => Some((x.clone(), rest)),
        _ => None,
    }
}

/// `map snd $ getAllFlags base` for a command whose words are `words`.
// DIVERGENCE: `getModifiedVariableCommand` recurses on a synthetic
// `T_SimpleCommand id cmdPrefix rest` for `builtin`; an arena cannot hold it,
// so the flags are computed from the word list directly.
fn all_flag_strings(ast: &Ast, words: &[Id]) -> Vec<String> {
    get_flags_until_words(ast, &|s| s == "--", words.get(1..).unwrap_or(&[])).into_iter().map(|(_, f)| f).collect()
}

/// Consider 'export/declare -x' a reference, since it makes the var available
pub fn get_referenced_variable_command(ast: &Ast, base: Id) -> Vec<ReferencedVariable> {
    let Token::T_SimpleCommand(_, words) = ast.get(base) else { return vec![] };
    let Some((x, rest)) = literal_command(ast, words) else { return vec![] };
    let flags: Vec<String> = get_all_flags(ast, base).into_iter().map(|(_, f)| f).collect();
    let has = |f: &str| flags.iter().any(|x| x == f);
    let get_reference = |t: Id| -> Vec<ReferencedVariable> {
        match ast.get(t) {
            Token::T_Assignment(_, name, _, _) => vec![(t, t, name.clone())],
            Token::T_NormalWord(parts) if parts.len() == 1 => match ast.get(parts[0]) {
                Token::T_Literal(name) if !name.starts_with('-') => vec![(t, t, name.clone())],
                _ => vec![],
            },
            _ => vec![],
        }
    };
    let for_declare = || {
        if ["x", "p"].iter().any(|f| has(f)) && !["f", "F"].iter().any(|f| has(f)) {
            rest.iter().flat_map(|&t| get_reference(t)).collect()
        } else {
            vec![]
        }
    };
    match x.as_str() {
        "declare" => for_declare(),
        "typeset" => for_declare(),

        "export" => {
            if has("f") {
                vec![]
            } else {
                rest.iter().flat_map(|&t| get_reference(t)).collect()
            }
        }
        "local" => {
            if has("x") {
                rest.iter().flat_map(|&t| get_reference(t)).collect()
            } else {
                vec![]
            }
        }
        "trap" => match rest.first() {
            Some(&head) => get_variables_from_literal_token(ast, head).into_iter().map(|x| (base, head, x)).collect(),
            None => vec![],
        },
        "alias" => rest
            .iter()
            .flat_map(|&token| {
                get_variables_from_literal_token(ast, token).into_iter().map(move |name| (base, token, name))
            })
            .collect(),
        _ => vec![],
    }
}

/// The function returns a tuple consisting of four items describing an assignment.
/// Given e.g. declare foo=bar
/// (
///   BaseCommand :: Token,     -- The command/structure assigning the variable, i.e. declare foo=bar
///   AssignmentToken :: Token, -- The specific part that assigns this variable, i.e. foo=bar
///   VariableName :: String,   -- The variable name, i.e. foo
///   VariableValue :: DataType -- A description of the value being assigned, i.e. "Literal string with value foo"
/// )
pub fn get_modified_variable_command(ast: &Ast, base: Id) -> Vec<ModifiedVariable> {
    match ast.get(base) {
        Token::T_SimpleCommand(_, words) => modified_variable_command_words(ast, base, words),
        _ => vec![],
    }
}

/// `getModifiedVariableCommand` on `T_SimpleCommand base _ words`.
fn modified_variable_command_words(ast: &Ast, base: Id, words: &[Id]) -> Vec<ModifiedVariable> {
    use DataSource::*;
    use DataType::*;
    let Some((x, rest)) = literal_command(ast, words) else { return vec![] };
    let flags = all_flag_strings(ast, words);
    let has = |f: &str| flags.iter().any(|x| x == f);

    let get_literal_of_data_type = |t: Id, d: DataType| -> Option<ModifiedVariable> {
        let s = get_literal_string(ast, t)?;
        if s.starts_with('-') {
            return None; // fail "argument"
        }
        Some((base, t, s, d))
    };
    let get_literal = |t: Id| get_literal_of_data_type(t, DataString(SourceExternal));
    let get_literal_array = |t: Id| get_literal_of_data_type(t, DataArray(SourceExternal));

    let get_modifier_param = |def: fn(DataSource) -> DataType, t: Id| -> Vec<ModifiedVariable> {
        match ast.get(t) {
            Token::T_Assignment(_, name, _, value) => {
                vec![(base, t, name.clone(), data_type_from(ast, def, *value))]
            }
            Token::T_NormalWord(_) => get_literal_string(ast, t)
                .filter(|name| is_variable_name(name))
                .map(|name| (base, t, name, def(SourceDeclaration)))
                .into_iter()
                .collect(),
            _ => vec![],
        }
    };
    let get_modifier_param_string = |t: Id| get_modifier_param(DataString, t);

    let for_declare = || -> Vec<ModifiedVariable> {
        if ["F", "f", "p"].iter().any(|f| has(f)) {
            return vec![];
        }
        let default_type: fn(DataSource) -> DataType =
            if ["a", "A"].iter().any(|f| has(f)) { DataArray } else { DataString };
        rest.iter().flat_map(|&t| get_modifier_param(default_type, t)).collect()
    };

    // DIVERGENCE: `stripEqualsFrom` builds a synthetic word whose leading
    // T_Literal (in `T_NormalWord (T_Literal ..:rs)` or
    // `T_NormalWord [T_DoubleQuoted [T_Literal ..]]`) loses everything up to
    // and including its first '=' (all of it if there is none). The arena
    // cannot hold that word, so `SourceFrom` gets the original `let` argument.
    // Consumers (checkQuotesInLiterals) only test the text for quotes and
    // `\ `, so the result differs only when that single T_Literal contains a
    // quote or `\ ` in the stripped part, i.e. before its first '='.
    let let_param_to_literal = |token: Id| -> Vec<ModifiedVariable> {
        let s = oversimplify(ast, token).concat();
        let var: String = s.chars().skip_while(|c| "+-".contains(*c)).take_while(|&c| is_variable_char(c)).collect();
        if var.is_empty() { vec![] } else { vec![(base, token, var, DataString(SourceFrom(vec![token])))] }
    };

    fn get_set_params(ast: &Ast, list: &[Id]) -> Option<Vec<Id>> {
        match list {
            [t, _, rest @ ..] if get_literal_string(ast, *t).as_deref() == Some("-o") => get_set_params(ast, rest),
            [t, rest @ ..] => match get_literal_string(ast, *t) {
                Some(s) if s == "--" => Some(rest.to_vec()),
                Some(s) if s.starts_with('-') => get_set_params(ast, rest),
                _ => {
                    let mut out = vec![*t];
                    out.extend(get_set_params(ast, rest).unwrap_or_default());
                    Some(out)
                }
            },
            [] => None,
        }
    }

    let get_flag_assigned_variable =
        |str: &str, data_source: DataSource, maybe_flags: Option<Vec<Opt>>| -> Option<ModifiedVariable> {
            let flags = maybe_flags?;
            let (_, (_flag, value)) = flags.into_iter().find(|(f, _)| f == str)?;
            let variable_name = get_literal_string_ext(ast, &|_| Some("!".to_string()), value)?;
            let split = variable_name.find('[').unwrap_or(variable_name.len());
            let (base_name, index) = variable_name.split_at(split);
            let ctor: fn(DataSource) -> DataType = if index.is_empty() { DataString } else { DataArray };
            Some((base, value, base_name.to_string(), ctor(data_source)))
        };
    let get_printf_variable =
        |list: &[Id]| get_flag_assigned_variable("v", SourceFrom(list.to_vec()), get_bsd_opts(ast, "v:", list));
    let get_wait_variable =
        |list: &[Id]| get_flag_assigned_variable("p", SourceInteger, Some(get_generic_opts(ast, list)));

    // mapfile has some curious syntax allowing flags plus 0..n variable names
    // where only the first non-option one is used if any.
    let get_mapfile_array = |base: Id, rest: &[Id]| -> Option<ModifiedVariable> {
        let f = |arg: Id| -> Option<(String, Id)> {
            let name = get_literal_string(ast, arg)?;
            if !is_variable_name(&name) {
                return None;
            }
            Some((name, arg))
        };
        let parse_args = || -> Option<ModifiedVariable> {
            let args = get_gnu_opts(ast, "d:n:O:s:u:C:c:t", rest)?;
            let ys: Vec<Id> = args.into_iter().filter(|(n, _)| n.is_empty()).map(|(_, (_, y))| y).collect();
            match ys.first() {
                None => Some((base, base, "MAPFILE".to_string(), DataArray(SourceExternal))),
                Some(&first) => {
                    let name = get_literal_string(ast, first)?;
                    if !is_variable_name(&name) {
                        return None;
                    }
                    Some((base, first, name, DataArray(SourceExternal)))
                }
            }
        };
        // If arg parsing fails (due to bad or new flags), get the last variable name
        let fallback = || -> Option<ModifiedVariable> {
            let (name, token) = rest.iter().rev().find_map(|&a| f(a))?;
            Some((base, token, name, DataArray(SourceExternal)))
        };
        parse_args().or_else(fallback)
    };

    // get the FLAGS_ variable created by a shflags DEFINE_ call
    let get_flag_variable = |list: &[Id]| -> Option<ModifiedVariable> {
        match list {
            [n, _v, ..] => {
                let name = get_literal_string(ast, *n)?;
                Some((base, *n, format!("FLAGS_{name}"), DataString(SourceExternal)))
            }
            _ => None,
        }
    };

    let result: Vec<ModifiedVariable> = match x.as_str() {
        "builtin" => modified_variable_command_words(ast, base, rest),
        "read" => {
            // catMaybes $ takeWhile isJust (reverse $ map getLiteral rest)
            let fallback = || -> Vec<ModifiedVariable> { rest.iter().rev().map_while(|&t| get_literal(t)).collect() };
            let parsed = || -> Option<Vec<ModifiedVariable>> {
                let parsed = get_gnu_opts(ast, FLAGS_FOR_READ, rest)?;
                match parsed.iter().find(|(n, _)| n == "a") {
                    Some((_, (_, var))) => get_literal_array(*var).map(|x| vec![x]),
                    None => Some(
                        parsed.iter().filter(|(n, _)| n.is_empty()).filter_map(|(_, (_, v))| get_literal(*v)).collect(),
                    ),
                }
            };
            parsed().unwrap_or_else(fallback)
        }

        "getopts" => match rest {
            [_opts, var, ..] => get_literal(*var).into_iter().collect(),
            _ => vec![],
        },

        "let" => rest.iter().flat_map(|&t| let_param_to_literal(t)).collect(),

        "export" => {
            if has("f") {
                vec![]
            } else {
                rest.iter().flat_map(|&t| get_modifier_param_string(t)).collect()
            }
        }

        "declare" => for_declare(),
        "typeset" => for_declare(),

        "local" => rest.iter().flat_map(|&t| get_modifier_param_string(t)).collect(),
        "readonly" => {
            if ["f", "p"].iter().any(|f| has(f)) {
                vec![]
            } else {
                rest.iter().flat_map(|&t| get_modifier_param_string(t)).collect()
            }
        }
        "set" => get_set_params(ast, rest)
            .map(|params| (base, base, "@".to_string(), DataString(SourceFrom(params))))
            .into_iter()
            .collect(),

        "printf" => get_printf_variable(rest).into_iter().collect(),
        "wait" => get_wait_variable(rest).into_iter().collect(),

        "mapfile" => get_mapfile_array(base, rest).into_iter().collect(),
        "readarray" => get_mapfile_array(base, rest).into_iter().collect(),

        "DEFINE_boolean" => get_flag_variable(rest).into_iter().collect(),
        "DEFINE_float" => get_flag_variable(rest).into_iter().collect(),
        "DEFINE_integer" => get_flag_variable(rest).into_iter().collect(),
        "DEFINE_string" => get_flag_variable(rest).into_iter().collect(),

        "run" => get_bats_run_variables(ast, rest).into_iter().map(|(name, value)| (base, base, name, value)).collect(),

        _ => vec![],
    };
    result.into_iter().filter(|(_, _, s, _)| !s.starts_with('-')).collect()
}

/// Given a NormalWord like foo or foo[$bar], get foo.
/// Primarily used to get references for [[ -v foo[bar] ]]
pub fn get_variable_for_test_dash_v(ast: &Ast, t: Id) -> Option<String> {
    // foo[bar] gets parsed with [bar] as a glob, so undo that
    // Turn foo[$x] into foo[\0] so that we can get the constant array name
    // in a non-constant expression (while filtering out foo$x[$y])
    let to_str = |t: Id| match ast.get(t) {
        Token::T_Glob(s) => Some(s.clone()),
        _ => Some("\0".to_string()),
    };
    let str: String = get_literal_string_ext(ast, &to_str, t)?.chars().take_while(|&c| c != '[').collect();
    if !is_variable_name(&str) {
        return None;
    }
    Some(str)
}

pub fn get_referenced_variables(ast: &Ast, t: Id) -> Vec<ReferencedVariable> {
    // Try to reduce false positives for unused vars only referenced from evaluated vars
    let special_references = |name: &str, base: Id, word: Id| -> Vec<ReferencedVariable> {
        if ["PS1", "PS2", "PS3", "PS4", "PROMPT_COMMAND"].contains(&name) {
            get_variables_from_literal_token(ast, word).into_iter().map(|x| (base, base, x)).collect()
        } else {
            vec![]
        }
    };
    let get_if_reference = |context: Id, token: Id| -> Vec<ReferencedVariable> {
        get_variable_for_test_dash_v(ast, token)
            .map(|str| (context, token, get_braced_reference(&str)))
            .into_iter()
            .collect()
    };
    let is_arithmetic_assignment = |t: Id| {
        let path = get_path(ast, t);
        match path.get(1).map(|&p| ast.get(p)) {
            Some(Token::TA_Assignment(op, lhs, _)) if op == "=" => ast.structurally_eq(*lhs, t),
            _ => false,
        }
    };
    match ast.get(t) {
        Token::T_DollarBraced(_, l) => {
            let str = oversimplify(ast, *l).concat();
            let mut out = vec![(t, t, get_braced_reference(&str))];
            let mut more = get_index_references(&str);
            more.extend(get_offset_references(&get_braced_modifier(&str)));
            out.extend(more.into_iter().map(|x| (*l, *l, x)));
            out
        }
        Token::TA_Variable(name, _) => {
            if is_arithmetic_assignment(t) {
                vec![]
            } else {
                vec![(t, t, name.clone())]
            }
        }
        Token::T_Assignment(mode, str, _, word) => {
            let mut out = vec![];
            if *mode == AssignmentMode::Append {
                out.push((t, t, str.clone()));
            }
            out.extend(special_references(str, t, *word));
            out
        }

        Token::TC_Unary(_, op, token) if op == "-v" => get_if_reference(t, *token),
        Token::TC_Unary(_, op, token) if op == "-R" => get_if_reference(t, *token),
        Token::TC_Binary(ConditionType::DoubleBracket, op, lhs, rhs) => {
            if is_dereferencing_binary_op(op) {
                [*lhs, *rhs].iter().flat_map(|&x| get_if_reference(t, x)).collect()
            } else {
                vec![]
            }
        }

        // {foo}>&- references and closes foo
        Token::T_FdRedirect(fd, op) if fd.starts_with('{') => {
            if is_closing_file_op(ast, *op) {
                vec![(t, t, fd[1..].chars().take_while(|&c| c != '}').collect())]
            } else {
                vec![]
            }
        }
        _ => get_referenced_variable_command(ast, t),
    }
}

pub fn is_dereferencing_binary_op(op: &str) -> bool {
    ["-eq", "-ne", "-lt", "-le", "-gt", "-ge"].contains(&op)
}

pub fn data_type_from(ast: &Ast, default_type: fn(DataSource) -> DataType, v: Id) -> DataType {
    let ctor: fn(DataSource) -> DataType = match ast.get(v) {
        Token::T_Array(..) => DataType::DataArray,
        _ => default_type,
    };
    ctor(DataSource::SourceFrom(vec![v]))
}

//- Command specific checks

/// Compare a command to a string: t `isCommand` "sed" (also matches /usr/bin/sed)
pub fn is_command(ast: &Ast, token: Id, str: &str) -> bool {
    is_command_match(ast, token, &|cmd| cmd == str || cmd.ends_with(&format!("/{str}")))
}

/// Compare a command to a literal. Like above, but checks full path.
pub fn is_unqualified_command(ast: &Ast, token: Id, str: &str) -> bool {
    is_command_match(ast, token, &|cmd| cmd == str)
}

pub fn is_command_match(ast: &Ast, token: Id, matcher: &dyn Fn(&str) -> bool) -> bool {
    get_command_name(ast, token).is_some_and(|n| matcher(&n))
}

/// Does this regex look like it was intended as a glob?
/// True:  *foo*
/// False: .*foo.*
pub fn is_confused_glob_regex(s: &str) -> bool {
    let chars: Vec<char> = s.chars().collect();
    match chars.as_slice() {
        ['*', ..] => true,
        [x, '*'] if !"\\.".contains(*x) => true,
        _ => false,
    }
}

pub fn get_variables_from_literal_token(ast: &Ast, token: Id) -> Vec<String> {
    get_variables_from_literal(&get_literal_string_def(ast, " ", token))
}

static VARIABLE_REGEX: LazyLock<Regex> = LazyLock::new(|| mk_regex("\\$\\{?([A-Za-z0-9_]+)"));

/// Try to get referenced variables from a literal string like "$foo"
/// Ignores tons of cases like arithmetic evaluation and array indices.
pub fn get_variables_from_literal(string: &str) -> Vec<String> {
    match_all_submatches(&VARIABLE_REGEX, string)
        .into_iter()
        .map(|groups| groups.into_iter().next().expect("one group"))
        .collect()
}

/// Run a command if the shell is in the given list
pub fn when_shell(params: &Params<'_>, l: &[Shell], c: impl FnOnce()) {
    if l.contains(&params.shell_type) {
        c();
    }
}

pub fn filter_by_annotation(
    as_spec: &AnalysisSpec,
    params: &Params<'_>,
    notes: Vec<TokenComment>,
) -> Vec<TokenComment> {
    let ast = params.ast;
    let should_ignore_for = |code: Code, t: Id| match ast.get(t) {
        Token::T_Include(_) => !as_spec.check_sourced,
        _ => is_annotation_ignoring_code(ast, code, t),
    };
    let should_ignore = |note: &TokenComment| {
        // `getPath parents (T_Bang $ tcId note)`: the dummy T_Bang stands in
        // for the note's token, so only its parents are tested.
        path_iter(ast, note.id).skip(1).any(|t| should_ignore_for(note.comment.code, t))
    };
    notes.into_iter().filter(|n| !should_ignore(n)).collect()
}

pub fn should_ignore_code(params: &Params<'_>, code: Code, t: Id) -> bool {
    path_iter(params.ast, t).any(|p| is_annotation_ignoring_code(params.ast, code, p))
}

/// Is this a ${#anything}, to get string length or array count?
pub fn is_counting_reference(ast: &Ast, t: Id) -> bool {
    match ast.get(t) {
        Token::T_DollarBraced(_, token) => oversimplify(ast, *token).concat().starts_with('#'),
        _ => false,
    }
}

static QUOTED_ALTERNATIVE_RE: LazyLock<Regex> = LazyLock::new(|| mk_regex("(^|\\]):?\\+"));

/// FIXME: doesn't handle ${a:+$var} vs ${a:+"$var"}
pub fn is_quoted_alternative_reference(ast: &Ast, t: Id) -> bool {
    match ast.get(t) {
        Token::T_DollarBraced(_, l) => {
            matches(&get_braced_modifier(&oversimplify(ast, *l).concat()), &QUOTED_ALTERNATIVE_RE)
        }
        _ => false,
    }
}

pub fn supports_arrays(shell: Shell) -> bool {
    matches!(shell, Shell::Bash | Shell::Ksh)
}

pub fn is_true_assignment_source(c: &DataType) -> bool {
    use DataSource::*;
    use DataType::*;
    !matches!(
        c,
        DataString(SourceChecked)
            | DataString(SourceDeclaration)
            | DataArray(SourceChecked)
            | DataArray(SourceDeclaration)
    )
}

pub fn modifies_variable(params: &Params<'_>, token: Id, name: &str) -> bool {
    get_variable_flow(params, token).iter().any(|t| match t {
        StackData::Assignment(_, _, n, source) => is_true_assignment_source(source) && n == name,
        _ => false,
    })
}

pub fn is_test_command(ast: &Ast, t: Id) -> bool {
    match ast.get(t) {
        Token::T_Condition(..) => true,
        Token::T_SimpleCommand(..) => is_command(ast, t, "test"),
        Token::T_Redirecting(_, t) => is_test_command(ast, *t),
        Token::T_Annotation(_, t) => is_test_command(ast, *t),
        Token::T_Pipeline(_, cmds) if cmds.len() == 1 => is_test_command(ast, cmds[0]),
        _ => false,
    }
}
