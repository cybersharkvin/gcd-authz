{
  description = "gcd-authz — GCD as a positive, provable per-request authorization control for LLM agents (paper-one artifact)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    crane.url = "github:ipetkov/crane";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, crane, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };
        rustToolchain = pkgs.rust-bin.stable.latest.default;
        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        # Full source (includes embedded JSON/data/templates) for buildPackage.
        src = pkgs.lib.cleanSourceWith {
          src = ./.;
          filter = path: type:
            (craneLib.filterCargoSources path type)
            || (builtins.match ".*\\.json$" path != null)
            || (builtins.match ".*/data/.*" path != null)
            || (builtins.match ".*\\.gbnf$" path != null);
        };

        # Cargo-only source for the dependency cache (so data changes don't bust deps).
        depsSrc = craneLib.cleanCargoSource ./.;

        commonArgs = {
          inherit src;
          strictDeps = true;
          buildInputs = [ pkgs.openssl ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [ ];
          nativeBuildInputs = [ pkgs.pkg-config ];
        };

        cargoArtifacts = craneLib.buildDepsOnly (commonArgs // { src = depsSrc; });

        workspace = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          doCheck = false;
        });
      in
      {
        packages.default = workspace;

        # TODO(build step 6/7): wire `nix run .#experiment` to the harness binary,
        # pin model weights by hash + the llama.cpp fork commit (MTP off), and
        # declare the multi-model llama-server launcher. See the README
        # "Reproducing the experiment" section for the current manual run path.
        # apps.experiment = flake-utils.lib.mkApp { drv = ...; };

        checks.workspace-clippy = craneLib.cargoClippy (commonArgs // {
          inherit cargoArtifacts;
          cargoClippyExtraArgs = "--all-targets -- --deny warnings";
        });

        devShells.default = craneLib.devShell {
          packages = [ rustToolchain pkgs.pkg-config pkgs.openssl ];
        };
      });
}
