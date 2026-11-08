{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs";

  outputs =
    {
      self,
      nixpkgs,
    }:
    let
      forEachSystem =
        fn:
        nixpkgs.lib.genAttrs nixpkgs.lib.platforms.linux (
          system: fn system (nixpkgs.legacyPackages.${system})
        );
    in
    {
      packages = forEachSystem (
        system: pkgs: rec {
          default = compass;

          compass = pkgs.rustPlatform.buildRustPackage {
            pname = "compass";
            version = (pkgs.lib.importTOML ./Cargo.toml).workspace.package.version;

            src = pkgs.lib.fileset.toSource {
              root = ./.;
              fileset = pkgs.lib.fileset.unions [
                ./Cargo.toml
                ./Cargo.lock
                ./crates
              ];
            };

            cargoLock.lockFile = ./Cargo.lock;

            nativeBuildInputs = [ pkgs.cmake ];

            cargoBuildFlags = [
              "-p"
              "compass"
              "-p"
              "compassd"
            ];

            meta.mainProgram = "compass";
          };
        }
      );

      devShells = forEachSystem (
        system: pkgs: {
          default = import ./shell.nix { inherit pkgs; };
        }
      );

      formatter = forEachSystem (system: pkgs: pkgs.nixfmt-tree);

      nixosModules.default = import ./nix/module.nix self;
    };
}
