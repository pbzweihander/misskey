{
  stdenv,
  lib,
  fetchFromGitHub,

  nodejs,
  pnpm,

  # node-gyp
  node-gyp,
  python3,
  pkg-config,

  # Runtime dependencies
  bash,
  coreutils,
  curl,
  ffmpeg,

  # typeorm CLI
  gnused,

  # sharp
  vips,

  useJemalloc ? true,
  jemalloc,

  ...
}:

let
  runtimeBins = [
    bash
    nodejs
    curl
    ffmpeg
    gnused
    coreutils
  ];
  runtimePaths = lib.makeBinPath runtimeBins;
  runtimeLibs = [
    vips
  ];
  runtimeLibPaths = lib.makeLibraryPath runtimeLibs;
  preloadLib = lib.optionalString useJemalloc "${jemalloc}/lib/libjemalloc.so.2";

  packageJson = import ./package-json.nix;
in

stdenv.mkDerivation (finalAttrs: {
  pname = "misskey";
  version = packageJson.version;

  outputs = ["out" "app"];

  srcMisskey = ./..;
  srcFluentEmojis = fetchFromGitHub {
    owner = "misskey-dev";
    repo = "emojis";
    rev = "cae981eb4c5189ea9ea3230e83b876a5068df7d1";
    hash = "sha256-DsaNYhlH8PO2jKjt+RvvcBXZ6klwQGaqmMNxqDLpPbI=";

    name = "fluent-emojis";
  };

  srcs = [
    finalAttrs.srcMisskey
    finalAttrs.srcFluentEmojis
  ];
  setSourceRoot = ''
    sourceRoot="$(stripHash $srcMisskey)"
  '';

  patches = [
    ./find-config-from-cwd.patch
  ];

  strictDeps = true;

  nativeBuildInputs = [
    nodejs
    python3
    pkg-config

    pnpm.configHook
  ];

  buildInputs = runtimeBins ++ runtimeLibs ++ lib.optional useJemalloc jemalloc;

  pnpmDeps = pnpm.fetchDeps {
    inherit (finalAttrs) pname version;
    src = finalAttrs.srcMisskey;
    fetcherVersion = 2;
    hash = "";
  };

  postPatch = ''
    export HOME=$PWD
  '';

  configurePhase = ''
    runHook preConfigure

    rm -rf ./fluent-emojis
    ln -s "../${finalAttrs.srcFluentEmojis.name}" ./fluent-emojis

    # set nodedir to prevent node-gyp from downloading headers
    # taken from https://nixos.org/manual/nixpkgs/stable/#javascript-tool-specific
    mkdir -p $HOME/.node-gyp/${nodejs.version}
    echo 9 > $HOME/.node-gyp/${nodejs.version}/installVersion
    ln -sfv ${nodejs}/include $HOME/.node-gyp/${nodejs.version}
    export npm_config_nodedir=${nodejs}

    # use updated node-gyp. fixes the following error on Darwin:
    # PermissionError: [Errno 1] Operation not permitted: '/usr/sbin/pkgutil'
    export npm_config_node_gyp=${node-gyp}/lib/node_modules/node-gyp/bin/node-gyp.js

    runHook postConfigure
  '';

  buildPhase = ''
    runHook preBuild

    pnpm rebuild --filter frontend --stream v-code-diff
    pnpm rebuild --filter backend --stream re2

    export NODE_ENV=production
    pnpm build-pre
    pnpm run --recursive --stream build
    pnpm build-assets

    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall

    mkdir -p $app

    cp ./package.json $app/
    cp ./pnpm-lock.yaml $app/
    cp ./pnpm-workspace.yaml $app/
    cp -r ./patches $app/patches
    for package in ./packages/*; do
      if [[ -d "$package" ]]; then
        mkdir -p "$app/$package"
        cp "$package/package.json" "$app/$package/"
      fi
    done

    pushd $app
    pnpm install --filter backend... --prod --offline --ignore-scripts --frozen-lockfile
    popd

    mkdir -p $app/packages/backend/node_modules/re2/build/Release
    cp ./packages/backend/node_modules/re2/build/Release/re2.node $app/packages/backend/node_modules/re2/build/Release

    cp -r ./built $app/built
    for package in ./packages/*; do
      if [[ -d "$package/built" ]]; then
        cp -r "$package/built" "$app/$package/built"
      fi
    done

    mkdir -p "$app/assets"
    cp ./assets/*.{png,svg} "$app/assets"
    cp -r ./packages/frontend/assets "$app/packages/frontend/assets"

    cp -r ./packages/backend/{assets,scripts,migration,nsfw-model} "$app/packages/backend/"
    cp ./packages/backend/ormconfig.js $app/packages/backend/

    export runtimePaths="${runtimePaths}"
    export runtimeLibs="${runtimeLibPaths}"
    export preloadLib="${preloadLib}"

    mkdir -p $out/bin
    substituteAll ${./misskey-server} $out/bin/misskey-server
    chmod +x $out/bin/misskey-server
    substituteAll ${./misskey-healthcheck} $out/bin/misskey-healthcheck
    chmod +x $out/bin/misskey-healthcheck

    runHook postInstall
  '';

  postFixup = ''
    striperr="$(mktemp --tmpdir="$TMPDIR" 'striperr.XXXXXX')"
    find "$app/node_modules/.pnpm" -type f -a -name '*.node' -printf '%D-%i,%p\0' |
      sort -t, -k1,1 -u -z | cut -d, -f2- -z |
      xargs -r -0 -n1 -P "$NIX_BUILD_CORES" -- $STRIP ''${stripDebugFlags[*]:--S -p} 2>"$striperr" || exit_code=$?
    [[ "$exit_code" = 123 || -z "$exit_code" ]] || (cat "$striperr" 1>&2 && exit 1)
    cat "$striperr"
    rm "$striperr"
  '';

  doCheck = false;

  meta = {
    mainProgram = "misskey-server";
  };
})
