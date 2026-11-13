# Installing shelllint

shelllint is a single native binary, `shelllint`. Pick the method
that fits your setup; all of them put the same binary on your `PATH`.

| Method | Command | Needs |
|---|---|---|
| Release binary | download + extract | nothing |
| Docker / Podman | `docker run --rm -i ghcr.io/devanshchoubey/shelllint -f gcc - < script.sh` | Docker |
| cargo | `cargo install --git https://github.com/DevanshChoubey/shelllint shelllint` | Rust |
| npm | `npm install -g shelllint` | Node 16+ |
| pip | `pip install shelllint` | Python 3.8+ |
| Homebrew | `brew install DevanshChoubey/tap/shelllint` | Homebrew |
| Arch (AUR) | `yay -S shelllint-bin` (or `shelllint` to build) | an AUR helper |
| Nix | `nix run github:DevanshChoubey/shelllint` | Nix flakes/`nix-build` |
| pre-commit | see [pre-commit](#pre-commit) | pre-commit |
| GitHub Actions | see [GitHub Action](#github-action) | a workflow |

Platform support for the prebuilt binaries: Linux x86_64 and aarch64 (static
musl, runs on any distro), macOS x86_64 and Apple Silicon, Windows x86_64 (MSVC).

Replace `0.2.1` with the
release you want.

## Release binary

Every release attaches one archive per target plus a `SHA256SUMS` file:

```sh
V=0.2.1
T=x86_64-unknown-linux-musl          # or aarch64-unknown-linux-musl,
                                     # x86_64-apple-darwin, aarch64-apple-darwin
curl -fsSLO "https://github.com/DevanshChoubey/shelllint/releases/download/v$V/shelllint-v$V-$T.tar.gz"
curl -fsSLO "https://github.com/DevanshChoubey/shelllint/releases/download/v$V/SHA256SUMS"
grep "shelllint-v$V-$T.tar.gz" SHA256SUMS | sha256sum -c -
tar -xzf "shelllint-v$V-$T.tar.gz"
install -m755 "shelllint-v$V-$T/shelllint" ~/.local/bin/
```

Windows: download `shelllint-v<V>-x86_64-pc-windows-msvc.zip`, extract,
and put `shelllint.exe` on your `PATH`.

## Docker

The image is built `FROM scratch` around a static musl binary (a few MB, no
shell, no libc). It takes the same arguments as the binary:

```sh
docker run --rm -i ghcr.io/devanshchoubey/shelllint:0.2.1 -f gcc - < script.sh
docker run --rm -v "$PWD:/src" -w /src ghcr.io/devanshchoubey/shelllint:0.2.1 -f tty scripts/*.sh
```

To build it locally from a checkout:

```sh
docker build --memory=6g -t shelllint .
```

The `-i` flag is needed for `-` (read the script from stdin). Because the
image has no shell, pass file paths as arguments, not as a shell glob.

## cargo

From crates.io once the crates are published (not yet, see below):

```sh
cargo install shelllint
```

From git, today:

```sh
cargo install --git https://github.com/DevanshChoubey/shelllint shelllint
# or from a checkout:
cargo install --path crates/cli
```

Build your own fast binary with `--locked` so the workspace `Cargo.lock` is used.

## npm

The `shelllint` package is a launcher. The binary comes from one of the
`@shelllint/<os>-<arch>` optional dependencies, so npm installs only the
one for your platform.

```sh
npm install -g shelllint        # global
npx shelllint -f gcc script.sh  # one-off, no install
```

Do not pass `--omit=optional` (or `--no-optional`), or the binary is missing.

## pip

The wheel ships the native binary as a console script, with no Python API:

```sh
pip install shelllint
shelllint --version
```

Or into an isolated tool environment: `pipx install shelllint`.

## Homebrew

```sh
brew install DevanshChoubey/tap/shelllint
```

The formula is in `packaging/homebrew/shelllint.rb`, a template that the
release job fills in (version and sha256 values). Copy it into your tap's
`Formula/` directory.

## Arch Linux (AUR)

```sh
yay -S shelllint-bin   # prebuilt static binary
yay -S shelllint       # build from source with cargo
```

The PKGBUILDs are in `packaging/aur/`. The checksums are placeholders until a
release is cut.

## Nix

```sh
nix run github:DevanshChoubey/shelllint
nix-build packaging/nix      # from a checkout
```

`packaging/nix/default.nix` builds from the checkout with `rustPlatform` and
the workspace `Cargo.lock`.

## pre-commit

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/DevanshChoubey/shelllint
    rev: v0.2.1
    hooks:
      - id: shelllint          # language: rust, builds with cargo
      # - id: shelllint-docker # language: docker_image, needs Docker
```

The `rust` hook builds the tool the first time pre-commit runs, so it needs a
Rust toolchain. The `docker_image` hook needs Docker but no toolchain. Pass
flags with `args: [--severity=warning]` in your config.

## GitHub Action

```yaml
- uses: actions/checkout@v4
- uses: DevanshChoubey/shelllint@v0.2.1
  with:
    paths: "scripts/**/*.sh install.sh"
    severity: warning
```

The action downloads the release for the runner OS and architecture, verifies
it against `SHA256SUMS`, registers a problem matcher (so findings show as
annotations on the PR), and runs the tool. Inputs: `paths`, `severity`,
`format` (default `gcc`), `extra-args`, `version`, `repository`,
`fail-on-findings`.

## Verifying the install

```sh
shelllint --version
printf '#!/bin/sh\necho $x\n' | shelllint -f gcc -
```

The second command should report SC2154 and SC2086 and exit with status 1.
