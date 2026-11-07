# A mesh client as a NixOS module. Import it next to the flake's module:
#
#   modules = [ bunnyhop.nixosModules.default ./client.nix ];
#
# `settings` is bunnyhopd.toml; see bunnyhopd.toml next to this file for every option. A node
# that is also a lighthouse adds `settings.lighthouse` (see lighthouse.nix). Secrets are given
# as plain paths; with agenix or sops-nix, use their `.path` instead.
{
  services.bunnyhop = {
    enable = true;
    # Opens the client's listen port (UDP) so peers can connect directly.
    openFirewall = true;

    settings = {
      # Where `bunnyhop status` and `bunnyhop dns` reach the daemon. The module points the CLI
      # at it; keep it under /run/bunnyhop, the only directory the service may write.
      socket = {
        path = "/run/bunnyhop/bunnyhop.sock";
        # Members may use the CLI without root.
        group = "wheel";
      };

      client = {
        # The node registers with every lighthouse. Lighthouses that share an auth key serve
        # one mesh, and any of them can coordinate and relay. Settings apply to the
        # lighthouse's whole mesh; lighthouses of one mesh may each set them but must not
        # disagree. Without settings, a URL is enough.
        lighthouses = [
          {
            url = "https://lh1.example.com:8443";

            dns = {
              # Resolve this mesh's names through a stub registered with resolvconf.
              accept = true;
              # Records this node publishes in the lighthouse's mesh, as
              # <name>.mesh.internal. Names below the hostname are always allowed; others need
              # the pre-auth key's `dns` patterns (here keys.laptops allows *.alice and
              # *.home.arpa.).
              records = [
                {
                  name = "grafana.laptop";
                  type = "CNAME";
                  # A mesh name, i.e. laptop.mesh.internal.
                  value = "laptop";
                }
                {
                  name = "docs.laptop";
                  type = "CNAME";
                  # A trailing dot points outside the mesh.
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
                # With `zone`, the record goes into one of the lighthouse's zones as
                # <name>.<zone> instead, and `name = "@"` is the zone itself. Only the key's
                # `dns` patterns can allow it.
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
                  # Still a mesh name: laptop.mesh.internal.
                  value = "laptop";
                }
              ];
            };

            exit_node = {
              # Send internet traffic through this peer of the mesh while a direct path to it
              # is up; without one the traffic is blocked. Only one mesh can set it.
              # `bunnyhop exit-node` overrides this until a restart.
              peer = "web";
              # Offer this node as an exit node in the mesh; its pre-auth key needs
              # `exit_node = true`.
              advertise = false;
            };
          }
          # The same mesh as lh1, so it publishes lh1's records and uses lh1's settings too.
          { url = "https://lh2.example.com:8443"; }
          # Another mesh, with its own key and settings. When two meshes answer for the same
          # zone or domain, this node keeps the one whose lighthouse is listed first.
          {
            url = "https://lh.work.example:8443";
            auth_key_file = "/run/secrets/bunnyhop-work";
            dns.accept = false;
          }
        ];
        # The same secret as the lighthouses' keys.laptops.secret_file.
        auth_key_file = "/run/secrets/bunnyhop-laptops";
        # Defaults to the system hostname.
        hostname = "laptop";
        # Only needed when the lighthouses' certificate is not from a public CA.
        ca_file = "/etc/bunnyhop/ca.pem";

        interface = {
          # The node's only WireGuard interface, for direct and relayed peers alike.
          name = "bh0";
          listen_port = 51821;
          # Addresses of these interfaces are never offered to peers; a trailing `*` matches
          # any suffix.
          exclude = [
            "docker*"
            "br-*"
            "veth*"
            "virbr*"
            "tailscale0"
          ];
        };

        # The node's WireGuard key, created with `bunnyhop genkey`. Without it the node gets a
        # new identity on every start, which calls for a pre-auth key with a short offline_ttl.
        private_key_file = "/run/secrets/bunnyhop-node.key";
      };
    };
  };
}
