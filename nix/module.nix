self:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.compass;
  toml = pkgs.formats.toml { };

  client = cfg.settings.client or null;
  lighthouse = cfg.settings.lighthouse or null;

  apiPort = 51819;

  resolvconf = config.networking.resolvconf.enable || config.services.resolved.enable;
  resolvconfExe = lib.getExe' config.networking.resolvconf.package "resolvconf";
in
{
  options.services.compass = {
    enable = lib.mkEnableOption "compassd, the compass mesh client and lighthouse";
    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.compass;
      description = "The compass package, with compassd and the compass CLI.";
    };
    settings = lib.mkOption {
      inherit (toml) type;
      default = { };
      description = "Contents of compassd.toml: a `client` section, a `lighthouse` section, or both.";
    };
    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Open the client's WireGuard port and the lighthouse hub's.";
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.compassd = {
      description = "compass daemon";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];
      path = [
        config.networking.firewall.package
      ]
      ++ lib.optional resolvconf config.networking.resolvconf.package;
      serviceConfig = {
        Type = "notify";
        ExecStart = "${lib.getExe' cfg.package "compassd"} --config ${toml.generate "compassd.toml" cfg.settings}";
        ExecReload = "${lib.getExe' pkgs.coreutils "kill"} -HUP $MAINPID";
        ExecStopPost = lib.mkIf (
          resolvconf && client != null
        ) "-${resolvconfExe} -f -d ${client.interface.name or "bh0"}";
        ReadWritePaths = lib.mkIf resolvconf [
          "-/etc/resolv.conf"
          "-/run/resolvconf"
        ];
        Restart = "on-failure";
        RuntimeDirectory = "compass";
        CapabilityBoundingSet = [
          "CAP_NET_ADMIN"
          "CAP_NET_BIND_SERVICE"
          "CAP_NET_RAW"
          "CAP_CHOWN"
        ];
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        LimitNOFILE = 65536;
      };
    };

    environment = {
      systemPackages = [ cfg.package ];

      variables = lib.mkIf (cfg.settings ? socket.path) {
        COMPASS_SOCKET = cfg.settings.socket.path;
      };
    };

    boot.kernel.sysctl = lib.mkIf (client.exit_node.advertise or false) {
      "net.ipv4.conf.all.forwarding" = lib.mkDefault true;
      "net.ipv6.conf.all.forwarding" = lib.mkDefault true;
    };

    networking.firewall = {
      trustedInterfaces = lib.optional (client != null) (client.interface.name or "bh0");
      interfaces = lib.mkIf (lighthouse != null) {
        ${lighthouse.hub.interface or "compass-hub"}.allowedTCPPorts = [ apiPort ];
      };
      allowedUDPPorts = lib.mkIf cfg.openFirewall (
        lib.optional (client != null) (client.interface.listen_port or 51821)
        ++ lib.optional (lighthouse != null) (lighthouse.hub.listen_port or 51820)
      );
    };
  };
}
