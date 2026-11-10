# A lighthouse as a NixOS module. Import it next to the flake's module:
#
#   modules = [ compass.nixosModules.default ./lighthouse.nix ];
#
# You can run several lighthouses for one mesh. They keep no state, so give them all this
# same config, each with its own hub key, and list every one of them on the clients. To
# put the lighthouse itself in the mesh, add `settings.client` (see client.nix) and list
# its key under `nodes` like any other machine.
{
  services.compass = {
    enable = true;
    # Opens the hub's WireGuard port.
    openFirewall = true;

    settings.lighthouse = {
      network = {
        # Nodes find each other as <hostname>.mesh.internal.
        domain = "mesh.internal";
        # Extra zones that nodes can publish records in, if the acl lets them. A name nobody
        # has published still resolves the normal way, so a zone can sit on top of a real
        # domain, and it can be the parent of the mesh domain. Zones can change on reload.
        # The rest of this section needs a restart.
        zones = [ "home.arpa" ];
        # Every node gets one address from each range, so both are required. Tailscale uses
        # this IPv4 range too, so pick a private (RFC 1918) one if a machine runs both.
        ipv4 = "100.64.0.0/10";
        ipv6 = "fd26:d40f:838e::/48";
        mtu = 1280;
      };

      hub = {
        # The lighthouse's own WireGuard interface. Nodes connect to it to talk to the
        # lighthouse, and only the keys listed under `nodes` get in.
        interface = "compass-hub";
        # UDP. Nodes also ask this port what their public address is.
        listen_port = 51820;
        # Make one with `compass genkey`. Clients need its public key
        # (`compass pubkey < file`).
        private_key_file = "/run/secrets/compass-hub.key";
      };

      # The machines in the mesh. One whose key is not listed gets no answer at all, and
      # deleting an entry removes that machine on the next reload. The name is only a label.
      # `owner` and `tags` are what the acl below goes by. Public keys are not secret, so
      # this list can live in your config repo.
      nodes = {
        laptop = {
          public_key = "0D5zlRK6XORev2ICQb4hDebYYTP8edb4T0dPGDifChE=";
          owner = "alice";
          tags = [ "tag:laptop" ];
        };
        runner = {
          public_key = "83BaEg3M6qOBBNn1+5A9aegDGREMbz0ZClKEyNCS2Vw=";
          tags = [ "tag:ci" ];
        };
        # A web server that may be used as an exit node, if it offers to be one.
        web = {
          public_key = "jIneXXAKF+muwHfPDdYBKpy+8ABOzudJKsPsSAqGsE8=";
          tags = [ "tag:web" ];
          exit_node = true;
        };
      };

      # Groups of users. A user is whoever is named as the `owner` of a node.
      groups = {
        admins = [ "alice" ];
        devs = [
          "alice"
          "bob@example.com"
        ];
      };

      # Nothing is allowed until a rule says so. A rule lets `src` open connections to `dst`,
      # and replies always get back. Leave out `proto` and the ports cover TCP and UDP. Leave
      # out `ports` and every port is open. `dns` lets `src` publish those names. They are
      # under the mesh domain unless they end in a dot, and "*.{hostname}" means anything
      # below the node's own hostname.
      acl = [
        {
          src = [ "group:admins" ];
          dst = [ "*" ];
        }
        {
          src = [
            "group:devs"
            "tag:ci"
          ];
          dst = [ "tag:web" ];
          proto = "tcp";
          ports = [
            80
            443
            "8000-8100"
          ];
        }
        {
          src = [ "bob@example.com" ];
          dst = [ "tag:ci" ];
          proto = "tcp";
          ports = [ 22 ];
        }
        {
          src = [ "*" ];
          dst = [ "*" ];
          proto = "icmp";
        }
        # Admins can use any exit node they can reach.
        {
          src = [ "group:admins" ];
          dst = [ "autogroup:internet" ];
        }
        # Every node can publish names below its own hostname, like grafana.laptop.
        {
          src = [ "*" ];
          dns = [ "*.{hostname}" ];
        }
        # Alice's machines can also take names under alice, and anything in the home.arpa
        # zone.
        {
          src = [ "alice" ];
          dns = [
            "*.alice"
            "*.home.arpa."
          ];
        }
        {
          src = [ "tag:web" ];
          dns = [ "status" ];
        }
      ];
    };
  };
}
