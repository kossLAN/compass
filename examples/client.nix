# A machine that joins a mesh, as a NixOS module. Import it next to the flake's module:
#
#   modules = [ compass.nixosModules.default ./client.nix ];
#
# `settings` becomes compassd.toml, and the compassd.toml in this directory explains every
# option. To make the machine a lighthouse too, add `settings.lighthouse` (see
# lighthouse.nix). The key paths here are plain strings. With agenix or sops-nix you would
# use their `.path` instead.
{
  services.compass = {
    enable = true;
    # Opens the WireGuard port so other nodes can connect to this one directly.
    openFirewall = true;

    settings = {
      # The socket the `compass` CLI talks to. Keep it under /run/compass, the only place the
      # service is allowed to write.
      socket = {
        path = "/run/compass/compass.sock";
        # Members of this group can use the CLI without root.
        group = "wheel";
      };

      client = {
        # A lighthouse is set up like a WireGuard peer: where to reach it, and its hub's
        # public key. Every lighthouse you list belongs to the same mesh unless you give it a
        # `mesh` name, so listing two is how you get a spare. The dns and exit_node settings
        # apply to the whole mesh, and lighthouses of one mesh must not disagree on them.
        lighthouses = [
          {
            endpoint = "lh1.example.com:51820";
            public_key = "QBOaPq4VcC/weEXCD8j3gJDzP2bmCb79WUVcllxn0hk=";

            dns = {
              # Resolve the mesh's names on this machine. compassd runs a small resolver for
              # them and registers it with resolvconf. On by default.
              accept = true;
              # Records this node adds to the mesh. A plain name goes under the mesh domain,
              # so the first one is grafana.laptop.mesh.internal. The lighthouse's acl
              # decides which names a node may take.
              records = [
                {
                  name = "grafana.laptop";
                  type = "CNAME";
                  # Another mesh name: laptop.mesh.internal.
                  value = "laptop";
                }
                {
                  name = "docs.laptop";
                  type = "CNAME";
                  # A trailing dot means a name outside the mesh.
                  value = "docs.example.com.";
                }
                {
                  name = "nas.alice";
                  type = "A";
                  value = "192.168.1.20";
                }
                {
                  name = "nas.alice";
                  type = "AAAA";
                  value = "2001:db8::20";
                }
                # With `zone`, the record goes in one of the lighthouse's extra zones
                # instead. This one is printer.home.arpa. Use `name = "@"` for the zone
                # itself.
                {
                  zone = "home.arpa";
                  name = "printer";
                  type = "A";
                  value = "192.168.1.30";
                }
                {
                  zone = "home.arpa";
                  name = "wiki";
                  type = "CNAME";
                  # Still a mesh name, even in a zone: laptop.mesh.internal.
                  value = "laptop";
                }
              ];
            };

            exit_node = {
              # Send this machine's internet traffic through another node. That only happens
              # while there is a direct path to it. If the path drops, the traffic is blocked
              # rather than sent out the normal way. Only one mesh can have an exit node, and
              # `compass exit-node` overrides this until the next restart.
              peer = "web";
              # Let other nodes use this machine as their exit node. The lighthouse also has
              # to list it with `exit_node = true`.
              advertise = false;
            };
          }
          # A second lighthouse for the same mesh. It gets the records and settings given
          # for lh1.
          {
            endpoint = "lh2.example.com:51820";
            public_key = "ZemVXzGDbiOIPQd8+KvX5kuWH8FY32UK8V3UKBsV0g8=";
          }
          # A different mesh, because it has its own `mesh` name. If two meshes serve the
          # same domain or zone, the one listed first wins.
          {
            endpoint = "lh.work.example:51820";
            public_key = "HwT2lNrnPcBbmfjA5NUgbP5uh5X4Sz5R+DGsJT6AYRc=";
            mesh = "work";
            dns.accept = false;
          }
        ];
        # The name other nodes know this machine by. Leave it out to use the system hostname.
        hostname = "laptop";

        interface = {
          # One WireGuard interface carries everything: the lighthouses and every peer,
          # direct or relayed.
          name = "bh0";
          listen_port = 51821;
          # Interfaces whose addresses are never offered to peers as a way to reach this
          # machine. A trailing `*` matches anything.
          exclude = [
            "docker*"
            "br-*"
            "veth*"
            "virbr*"
            "tailscale0"
          ];
        };

        # This machine's WireGuard key. Make one with `compass genkey`, then give its public
        # key (`compass pubkey < file`) to whoever runs the lighthouse.
        private_key_file = "/run/secrets/compass-node.key";
      };
    };
  };
}
