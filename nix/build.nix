{
  stdenv,
  lib,
  fetchPnpmDeps,
  makeWrapper,
  pnpmConfigHook,

  dart-sass,
  nodejs-slim,
  pnpm_12,

  # node-gyp
  python3,
  pkg-config,

  # Runtime dependencies
  bash,
  coreutils,
  curl,
  ffmpeg-headless,

  # typeorm CLI
  gnused,

  # sharp
  vips,

  useJemalloc ? true,
  jemalloc,

  ...
}:

let
  pnpm = pnpm_12.override {
    inherit nodejs-slim;
  };

  runtimeBins = [
    bash
    nodejs-slim
    curl
    ffmpeg-headless
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

  src = ./..;

  strictDeps = true;

  nativeBuildInputs = [
    dart-sass
    makeWrapper
    nodejs-slim
    python3
    pkg-config
    pnpm

    pnpmConfigHook
  ];

  buildInputs = runtimeBins ++ runtimeLibs ++ lib.optional useJemalloc jemalloc;

  pnpmDeps = fetchPnpmDeps {
    inherit (finalAttrs) pname version;
    inherit pnpm;
    src = finalAttrs.src;
    fetcherVersion = 5;
    hash = "";
  };

  SASS_EMBEDDED_BIN_PATH = "${dart-sass}/bin/sass";

  buildPhase = ''
    runHook preBuild

    for dir in $PWD/node_modules/.pnpm/node-gyp@*; do
      wrapProgram $dir/node_modules/node-gyp/bin/node-gyp.js \
        --add-flags '--nodedir ${nodejs-slim}'
    done

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

    cp -r ./packages/backend/{assets,scripts,migration} "$app/packages/backend/"
    cp ./packages/backend/ormconfig.js $app/packages/backend/

    mkdir -p "$app/scripts"
    cp ./scripts/start.mjs $app/scripts/start.mjs

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
