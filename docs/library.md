# Using shelllint-lib as a library

The `shelllint-lib` crate (library name `shellcheck`) is the embeddable
facade over the linter. It exposes a small, stable surface and keeps the
internal crates (parser, analyzer, formatter) private.

```toml
[dependencies]
shelllint-lib = "0.2.1"              # add features = ["serde"] for JSON
```

## Quick start

```rust
use shelllint::{Linter, Severity, Shell};

let linter = Linter::builder()
    .shell(Shell::Bash)
    .enable_all_optional()
    .exclude([2086])
    .severity(Severity::Warning)
    .build();

for d in linter.check_str("echo $foo\n") {
    println!("{}:{}: SC{} {}", d.line, d.column, d.code, d.message);
}
```

## Configuring a linter

`Linter::builder()` returns a `LinterBuilder`. Each setting returns the
builder, and `build()` returns a `Linter`.

| Method | CLI equivalent | Notes |
| --- | --- | --- |
| `shell(Shell)` | `-s` | Otherwise detected from the shebang, then the file extension. |
| `enable_all_optional()` | `-o all` | |
| `enable(names)` | `-o name,...` | Names come from `list_checks()`. |
| `exclude(codes)` | `-e` | Repeated calls add codes. |
| `include(codes)` | `-i` | Only the listed codes are reported. |
| `severity(Severity)` | `-S` | Drops less serious diagnostics. |

The defaults match `shellcheck --norc`. The facade never reads
`.shellcheckrc` files and never follows `source` directives.

## Checking

- `check_str(&str) -> Vec<Diagnostic>` checks a string.
- `check_file(path) -> io::Result<Vec<Diagnostic>>` reads a file, decoding
  it as UTF-8 with an ISO-8859-1 fallback, as the CLI does.

Diagnostics come back in the same order as the CLI report. Line and
column are 1-based, and a tab counts as one column.

A `Linter` is `Send + Sync` and immutable. Build it once and share it, for
example behind an `Arc`. The parser runs on a thread with a large stack
internally, so you do not need to size the stack yourself.

## Applying fixes

A `Diagnostic` may carry a `Fix`:

- `fix.apply(src)` applies that one fix.
- `apply_fixes(src, &diagnostics)` applies every fix at once. It merges them
  the way `shellcheck -f diff` does, dropping a fix that overlaps one already
  kept.

```rust
use shelllint::{Linter, apply_fixes};

let src = "rm $file\n";
let diags = Linter::new().check_str(src);
assert_eq!(apply_fixes(src, &diags), "rm \"$file\"\n");
```

## Listing checks

`shelllint::list_checks()` returns the optional checks, sorted by name, with
their codes and descriptions. Pass a name to `enable` to turn one on.

## Serialisation (`serde` feature)

With `features = ["serde"]`, `Diagnostic`, `Fix`, `Replacement`,
`InsertionPoint` and `Severity` implement `Serialize` and `Deserialize`. The
field names match the CLI's `json1` output, except that a diagnostic has no
`file` key.

```rust
let json = serde_json::to_string(&linter.check_str(src))?;
```

## Examples

The `examples/` directory of the crate has three programs:

- `basic`: check a string and print the diagnostics.
- `fix-all`: apply all fixes, and a single fix.
- `custom-config`: a configured linter that checks a file.

Run one with `cargo run -p shelllint-lib --example basic`.

## Errors

Only `check_file` can fail, with the `io::Error` from reading the file.
Checking itself never fails: a script with parse errors yields diagnostics
instead.
