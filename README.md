# compass

compass is a WireGuard mesh VPN, a bit like Tailscale, where everything is set up in config
files. Lighthouses hand out addresses, decide who can talk to whom and relay when they must.
Machines connect to each other directly whenever they can.

## Features

- **Lighthouses.** Clients register with multiple lighthouse, for redundancy or other mesh networks.
- **Stateless.** Neither the client nor the lighthouse writes state to disk.
- **Built-in DNS.** Every node gets a name under the mesh domain and can publish A, AAAA and
  CNAME records to a lighthouse, for the names the ACL allows.
- **NAT traversal.** Peers talk directly when hole punching works, and relay through a
  lighthouse when it doesn't. Relayed packets are still WireGuard-encrypted between the two
  peers, so the lighthouse only forwards them.
- **Exit nodes.** You can send your internet traffic through another node. If the direct path
  to it drops, that traffic is blocked instead of leaking out.

## Setup

See [`examples/`](examples) for an annotated `compassd.toml`, and `client.nix` and
`lighthouse.nix` for the NixOS module this flake provides (`nixosModules.default`).
