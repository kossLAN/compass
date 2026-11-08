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
        system: pkgs:
        let
          build =
            {
              pname,
              packages,
              daemons,
            }:
            let
              packageFlags = pkgs.lib.concatMap (package: [
                "-p"
                package
              ]) packages;
            in
            pkgs.rustPlatform.buildRustPackage {
              inherit pname;
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

              nativeBuildInputs = with pkgs; [
                cmake
                makeWrapper
              ];

              cargoBuildFlags = packageFlags;

              postInstall = pkgs.lib.concatMapStrings (daemon: ''
                wrapProgram $out/bin/${daemon} \
                  --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.nftables ]}
              '') daemons;

              meta.mainProgram = pname;
            };
        in
        rec {
          default = compass;

          compass = build {
            pname = "compass";
            packages = [
              "compass"
              "compassd"
            ];
            daemons = [ "compassd" ];
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
