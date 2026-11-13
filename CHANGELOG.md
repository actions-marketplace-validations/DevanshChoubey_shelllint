# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Each release also states which upstream ShellCheck commit it ports.

## [Unreleased]

## [0.2.1] - 2026-11-13

Ports ShellCheck at upstream commit `e11f964` (`v0.11.0-171-ge11f964`), the same
commit as 0.2.0.

### Added

- `shelllint_checker::with_check_stack`: runs a closure on one big-stack thread,
  and `check_script` calls inside it reuse that thread instead of starting one
  each. Use it around a loop that checks many scripts.

### Changed

- Faster on many small scripts: the `set -e` / `set -a` lookups no longer
  compile a regex for every script, and the CLI checks all its files on one
  big-stack thread. Output is unchanged.

## [0.2.0] - 2026-11-09

Ports ShellCheck at upstream commit `e11f964` (`v0.11.0-171-ge11f964`), the same
commit as 0.1.0.

### Added

See [docs/extensions.md](docs/extensions.md) for details. Numbers refer to
ShellCheck issues.

- File selection: `-r` (#143, #1895), `--exclude-path` (#2011, #2411),
  `--changed-since` (#1935), `--stdin-filename` (#2735).
- Output: `-f sarif` (#2405), `-f github`, `-f context` (#3146), `--output`
  (#2348), `--tab-width` (#3454), `--summary` and `--fail-fast` (#2018, #3599),
  `--verbose` (#2228, #3590), `--dump-ast` (#2696), `--list-checks`,
  `--completions` (#309), `--cache-dir` (#2939).
- Shell selection: `--fallback-shell`, `--infer-shell-from-name`,
  `--skip-unsupported-shebang` (#2610, #2971, #2425).
- Directives and rc files: `disable-start`, `disable-end`, `disable-line`;
  `severity`, `external-vars`, `source-functions`, `RCDIR`, `color`,
  `wiki-link-count`; `--strict-rc`; `--source-from-path`.
- `--ignore-directives` and `--report-unused-disables` (#1417, #645).
- `--modern-dialects` relaxes dialect warnings (#3099, #3062, #2393).
- `safe-vars` lists variables the quoting checks can trust (#587), and
  `strict-env-vars` reports unassigned uppercase variables (#930).
- Optional checks: `require-strict-mode` (#409), `prefer-local` (#468),
  `arith-errexit` (#2777), `undefined-command` (#2574), `unused-function` (#612).
- An Alpine container image.

### Changed

- `nix-shell` shebangs are understood, and `~` and `$HOME` are expanded in source
  paths. See [docs/divergences.md](docs/divergences.md).

### Fixed

- Scripts that source each other no longer use unbounded time and memory
  (#3442, #2954).

## [0.1.0] - 2026-11-09

Ports ShellCheck at upstream commit `e11f964` (`v0.11.0-171-ge11f964`).

### Added

- A complete port of ShellCheck's parser, analyzer and every registered check
  (`Analytics.hs`, `Checks/Commands.hs`, `Checks/ShellSupport.hs`), including
  control-flow and data-flow analysis.
- The `shelllint` command-line tool, with ShellCheck's flags and the
  `tty`, `gcc`, `json`, `json1`, `checkstyle`, `diff` and `quiet` output
  formats.
- Support for `.shellcheckrc` and `shellcheckrc` lookup, `--rcfile`, `--norc`,
  EditorConfig `shellcheck_*` keys, and in-script directives.
- A conformance harness (`shelllint-conformance`) with the `report` and
  `parity` gates, and pathological-input tests for time and memory.
  2105 of 2105 corpus scripts match the warning codes of upstream ShellCheck.
- Project documentation: README, NOTICE, CONTRIBUTING, Code of Conduct,
  security policy, issue and pull request templates, and CI and release
  workflows.

[Unreleased]: https://github.com/DevanshChoubey/shelllint/compare/v0.2.1...main
[0.2.1]: https://github.com/DevanshChoubey/shelllint/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/DevanshChoubey/shelllint/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/DevanshChoubey/shelllint/releases/tag/v0.1.0
