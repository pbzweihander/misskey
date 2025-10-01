{ misskey, dockerTools, lib, ... }:

dockerTools.streamLayeredImage {
  name = "misskey";

  uid = 991;
  gid = 991;
  uname = "misskey";
  gname = "misskey";

  contents = [
    dockerTools.binSh
    dockerTools.caCertificates
  ];

  extraCommands = ''
    mkdir -p tmp
  '';

  config = {
    Cmd = ["${lib.getExe misskey}" "/misskey/.config/default.yml"];
    Healthcheck = {
      Test = ["${misskey}/bin/misskey-healthcheck" "/misskey/.config/default.yml"];
      Interval = 5 * 1000 * 1000 * 1000;
      Retries = 20;
    };
  };
}
