{
  inputs = {
    nixpkgs.url = "nixpkgs/nixos-unstable-small";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { localSystem = system; };

        nodejs-slim = pkgs.nodejs-slim_26;
        pnpm = pkgs.pnpm_12.override {
          inherit nodejs-slim;
        };

        misskey = pkgs.callPackage ./nix/build.nix {
          inherit nodejs-slim pnpm;
        };

        misskey-image = pkgs.callPackage ./nix/image.nix {
          inherit misskey;
        };
      in
      {
        packages = {
          inherit misskey misskey-image;
        };

        apps = {
          stream-image = {
            type = "app";
            program = "${misskey-image}";
          };
        };

        devShell = pkgs.mkShell {
          name = "misskey-dev";

          packages = [
            nodejs-slim
            pnpm
          ] ++ (with pkgs; [
            dart-sass
            python3

            ffmpeg
            postgresql
            valkey
          ]);

          SASS_EMBEDDED_BIN_PATH = "${pkgs.dart-sass}/bin/sass";
        };
      }
    );
}
