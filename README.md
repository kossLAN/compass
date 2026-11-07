# bunnyhop

bunnyhop is a WireGuard mesh VPN, a bit like Tailscale, where everything is set up in config
files. Lighthouses hand out addresses, decide who can talk to whom and relay when they must.
Machines connect to each other directly whenever they can.

It comes with two programs and a library:

- `bunnyhopd` is the daemon. It runs a mesh client, a lighthouse, or both.
- `bunnyhop` is the command-line tool for checking on and controlling the daemon, and for
  making keys.
- The `bunnyhop` crate holds the client, the lighthouse and the control socket client, for
  building other clients on.

## Features

- **Everything in config files.** Pre-auth keys, groups and ACLs live in `bunnyhopd.toml`. Edit
  it and send `SIGHUP` to apply the changes. Removing a key also removes the nodes that used it.
- **Several lighthouses.** Clients register with every lighthouse. If one goes down, the others
  keep coordinating and relaying, and new nodes can still join.
- **Stateless.** Neither the client nor the lighthouse writes state to disk. Addresses and
  hostnames are derived from each node's key, so every lighthouse agrees on them, and a
  restarted lighthouse gets its nodes back as they register again.
- **Built-in DNS.** Every node gets a name under the mesh domain and can publish its own A, AAAA
  and CNAME records, there or in other zones the lighthouse serves, such as `home.arpa`. Records,
  like the other DNS and exit node settings, are set per lighthouse, so a node in several meshes
  decides what each one gets. Mesh addresses resolve back to names. The daemon registers its
  stub with `resolvconf` ahead of the host's other nameservers, and the stub refuses everything
  outside the mesh's domain and zones so lookups fall through to them. That works with
  openresolv, and with systemd-resolved through its `resolvconf` shim.
- **NAT traversal.** Peers talk directly when hole punching works, and relay through a
  lighthouse when it doesn't. Relayed packets are still WireGuard-encrypted between the two
  peers, so the lighthouse only forwards them.
- **Exit nodes.** You can send your internet traffic through another node. If the direct path
  to it drops, that traffic is blocked instead of leaking out.

## Setup

See [`examples/`](examples) for an annotated `bunnyhopd.toml`, and `client.nix` and
`lighthouse.nix` for the NixOS module this flake provides (`nixosModules.default`).
