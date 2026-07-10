# NTDF Mod v2.4 Reproducibility Notes

This repository is being used to reproduce the official `monster860/ntdf-mod`
`v2.4` runtime hack-menu build before making any further runtime PNACH changes.

## Known-good release artifact

Official release:

```text
https://github.com/monster860/ntdf-mod/releases/tag/v2.4
```

Official tag commit:

```text
f3fd845d435b501ba74218ed7e994c34e1625836
```

Official `v2.4` assets:

| Asset | Size | SHA-256 |
| --- | ---: | --- |
| `934F9081.pnach` | `125248` bytes | `8eee249568fd94e05998b0dab30b8fa427e064845dd8b73f9e9f4f25865eb214` |
| `df_hack.elf` | `842828` bytes | `43eba6baafba8aa20bfa2b2c9d8c7e5fcb24eb30ce2d9c92f2bbd4eea8bacf30` |

The official `v2.4` PNACH matches the locally known-good PCSX2 cheat hash.

## Why this matters

Modern local rebuilds using macOS and GCC 15 are not equivalent to the official
release artifact. A zero-source-change GCC 15 rebuild produced:

```text
45817c121b47655bb124e48808288448efcc7c805edd87e7c217bf6616e3717d
```

That rebuild shifts symbol-derived hook targets and is not byte-identical to the
official `v2.4` PNACH. A minimal read-only outfit probe built with the same
modern path stayed under the previous layout guard but still failed at runtime,
so further outfit work must wait until the unmodified hack-menu build is
reproducible or proven runtime-equivalent.

## Official build environment

The original workflow builds on GitHub Actions:

```yaml
runs-on: ubuntu-latest
```

Setup:

```sh
sudo apt-get update && sudo apt-get install nodejs
wget https://github.com/ps2dev/ps2dev/releases/download/v1.1/ps2dev-ubuntu-latest.tar.gz
sudo tar -xzf ps2dev-ubuntu-latest.tar.gz --directory /usr/local
```

Build:

```sh
export PS2DEV=/usr/local/ps2dev
export PS2SDK=$PS2DEV/ps2sdk
export GSKIT=$PS2DEV/gsKit
export PATH=$PATH:$PS2DEV/bin:$PS2DEV/ee/bin:$PS2DEV/iop/bin:$PS2DEV/dvp/bin:$PS2SDK/bin
cd mod
./build.sh
```

Original `mod/build.sh`:

```sh
ee-g++ --save-temps -fno-exceptions -Os -G 0 -c mod.cpp
node ./make_mod.js
cd loader
ee-gcc *.c -I$(echo -n $PS2SDK)/ee/include -I$(echo -n $PS2SDK)/common/include -Os -G 0 -L$(echo -n $PS2SDK)/ee/lib -ldebug -lpad -Wl,-Ttext -Wl,0x1000000 -o ../df_hack.elf
cd ..
```

## Reproducibility rule

Do not use a modified runtime PNACH as a test candidate until an unmodified
`v2.4` build produces either:

1. byte-for-byte matching `934F9081.pnach`, or
2. a separately validated runtime-equivalent zero-change rebuild.

For this investigation, byte-for-byte matching is the preferred gate.

The manual reproduction workflow verifies both official release hashes:

```text
934F9081.pnach = 8eee249568fd94e05998b0dab30b8fa427e064845dd8b73f9e9f4f25865eb214
df_hack.elf    = 43eba6baafba8aa20bfa2b2c9d8c7e5fcb24eb30ce2d9c92f2bbd4eea8bacf30
```

The workflow also uploads a hash report, PNACH layout comparison report,
generated artifacts, official comparison artifacts, and post-build git status.
