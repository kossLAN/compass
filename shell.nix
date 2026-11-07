{
  pkgs ? import <nixpkgs> { },
}:
pkgs.mkShell {
  nativeBuildInputs = with pkgs; [
    rustc
    cargo
    clippy
    rustfmt
    rust-analyzer
    cmake
  ];

  packages = with pkgs; [
    dig
    iproute2
    nftables
    wireguard-tools
  ];
}
