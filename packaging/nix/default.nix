# Nix build of shelllint from this checkout.
#   nix-build packaging/nix          # or: nix build -f packaging/nix
# Uses the workspace Cargo.lock, so no cargoHash is needed.
{ lib, rustPlatform }:

rustPlatform.buildRustPackage {
  pname = "shelllint";
  version = "0.2.1";

  src = lib.cleanSource ../..;
  cargoLock.lockFile = ../../Cargo.lock;

  cargoBuildFlags = [ "-p" "shelllint" ];
  cargoTestFlags = [ "-p" "shelllint" ];
  doCheck = false;

  meta = {
    description = "A Rust port of ShellCheck: finds bugs in shell scripts";
    homepage = "https://github.com/DevanshChoubey/shelllint";
    license = lib.licenses.gpl3Plus;
    mainProgram = "shelllint";
  };
}
