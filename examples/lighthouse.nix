# A lighthouse as a NixOS module. Import it next to the flake's module:
#
#   modules = [ bunnyhop.nixosModules.default ./lighthouse.nix ];
#
# Run as many lighthouses as you like: they keep no state, so every one runs this same
# section, apart from the hub's endpoint and key, and clients register with all of them. To
# put the lighthouse in the mesh too, add `settings.client` (see client.nix). Secrets are
# given as plain paths; with agenix or sops-nix, use their `.path` instead.
{ config, ... }:
let
  domain = "lh1.example.com";
  certs = config.security.acme.certs.${domain}.directory;
in
{
  services.bunnyhop = {
    enable = true;
    # Opens the API's TCP port, which also carries relayed traffic, and the hub's UDP port.
    openFirewall = true;

    settings.lighthouse = {
      api = {
        listen = "[::]:8443";
        # Omit both when a reverse proxy terminates TLS. Reloading re-reads them.
        tls_cert_file = "${certs}/fullchain.pem";
        tls_key_file = "${certs}/key.pem";
      };

      network = {
        # Peers resolve each other as <hostname>.mesh.internal.
        domain = "mesh.internal";
        # More zones the mesh answers for. Nodes publish records in them as their key's `dns`
        # patterns allow, and clients answer every other name in them with NXDOMAIN. Unlike
        # the rest of this section, zones can change on reload.
        zones = [ "home.arpa" ];
        # Both are required: every node gets one address from each. Tailscale uses these
        # ranges too; pick others on hosts that also run it.
        ipv4 = "100.64.0.0/10";
        ipv6 = "fd7a:115c:a1e0::/48";
        mtu = 1280;
      };

      hub = {
        # Answers STUN, so nodes learn their public address.
        listen_port = 51820;
        # How clients reach this port.
        endpoint = "${domain}:51820";
        # Created with `bunnyhop genkey`; when unset, a new key is generated on each start.
        private_key_file = "/run/secrets/bunnyhop-hub.key";
      };

      nodes = {
        # Every node is removed once it has been offline this long; a key can override it.
        offline_ttl = "30d";
        # Public keys (shown by `bunnyhop status`) that may never register again.
        revoked = [ "0D5zlRK6XORev2ICQb4hDebYYTP8edb4T0dPGDifChE=" ];
      };

      # Pre-auth keys. Each secret_file holds a secret created with `bunnyhop authkey`; clients
      # present the same secret. Removing a key removes its nodes.
      keys = {
        # Alice's devices. Besides <hostname> and *.<hostname>, they may claim *.alice, and
        # names in the home.arpa zone. Names are under the mesh domain unless they end in a dot.
        laptops = {
          secret_file = "/run/secrets/bunnyhop-laptops";
          owner = "alice";
          tags = [ "tag:laptop" ];
          dns = [
            "*.alice"
            "*.home.arpa."
          ];
        };
        # CI runners without key files: every run is a new node. Each logs out when it ends,
        # and one that crashes is removed after 10 minutes offline.
        ci = {
          secret_file = "/run/secrets/bunnyhop-ci";
          tags = [ "tag:ci" ];
          offline_ttl = "10m";
        };
        # A web server that may also claim the name "status" and act as an exit node.
        web = {
          secret_file = "/run/secrets/bunnyhop-web";
          tags = [ "tag:web" ];
          dns = [ "status" ];
          exit_node = true;
        };
      };

      # Users are the `owner`s of keys.
      groups = {
        admins = [ "alice" ];
        devs = [
          "alice"
          "bob@example.com"
        ];
      };

      # Default deny: each rule lets `src` reach `dst`, and replies are always allowed.
      # Without `proto`, ports apply to TCP and UDP; without `ports`, every port is open.
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
        # Admins may send their internet traffic through any exit node they can reach.
        {
          src = [ "group:admins" ];
          dst = [ "autogroup:internet" ];
        }
      ];
    };
  };

  # Reload the lighthouse when the API certificate is renewed.
  security.acme.certs.${domain}.reloadServices = [ "bunnyhopd" ];
}
