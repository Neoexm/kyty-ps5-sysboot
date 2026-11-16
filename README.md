# kyty-ps5-sysboot

This fork of [KytyPS5](https://github.com/KytyPS5/KytyPS5) boots the PS5's own system software rather than games. It loads the decrypted 13.60 `mini-syscore.elf` and lets the firmware come up from there: SysCore, ShellCore, the system services, and finally ShellUI. The current target is the first-power-on initial boot animation that ShellUI's BGLayer plays (`initial_boot_movie.mp4` plus `sfx_initialboot`).

Upstream KytyPS5 runs games. This fork changes a lot of the kernel, IPMI, loader and service code so that firmware processes start the way they do on hardware. Game support is whatever upstream has; for game emulation, use upstream.

> [!IMPORTANT]
> Not affiliated with Sony Interactive Entertainment.

## Getting it

`firmware/` is about 4 GB and stored with [Git LFS](https://git-lfs.com). Downloading the repo as a zip gives you LFS pointer files instead of the firmware, and the boot refuses to start. Clone it instead:

```bash
git lfs install
git clone --recurse-submodules https://github.com/Neoexm/kyty-ps5-sysboot.git
cd kyty-ps5-sysboot
git lfs pull
```

If you already cloned without LFS, run `git lfs install` and then `git lfs pull` inside the repo.

## Layout

The boot reads `firmware/` and `kyty.ini`, and writes each run's output to `evidence/`.

| Path | Git | What it is |
| --- | --- | --- |
| `firmware/` | committed (LFS) | Every file the boot reads. Layout below. |
| `kyty.ini` | ignored | Your local settings. Copy from `kyty.example.ini`. |
| `evidence/` | ignored | Run folders, plus research material the boot never touches. |

`scripts/boot_profile.json` is the committed list of environment variables the emulator boots with. Paths in it are written as `{firmware}/...`, and the launcher replaces that with the `firmware` path from `kyty.ini`. Before starting, the launcher checks that every path it names exists.

### firmware/

```text
firmware/
  storage/     mirror of the console's system storage (system, system_ex, system_data, ...);
               root of the captured storage manifest
  decrypted/   decrypted SELFs: mini-syscore.elf, system/, system_ex/ ...; also the guest sysroot
  system_b/    unpacked 13.60 system_b partition from the PUP
  shellui/     ShellUI (NPXS40087) managed assemblies and native extractions
  console/     state read from a live console: kernel image, devfs listings, iccnvs4 prefix,
               registry snapshot, inode supplement, authorization observations
  manifests/   captured_storage_manifest.json and system_ex_decrypted_overlay.manifest
```

Both manifests are hash-pinned in `boot_profile.json`. Change a manifest or anything it lists and the emulator won't start until the pins in the profile are updated. The overlay manifest uses paths relative to itself, so you can move the whole `firmware/` folder anywhere. Point `kyty.ini` at the new location.

### evidence/

All non-boot material lives here:

- `evidence/runs/manual_boots/<timestamp>/` holds one folder per launcher run, containing `boot.json`, `host_console.log`, `error_report.log`, and per-process logs.
- `evidence/firmware/` holds firmware files the boot doesn't read: the PUP and its unpack, rollback research, and the kernel dump.
- `evidence/ida/` holds IDA databases, kept out of `firmware/` so they don't show up in guest directory listings.
- `evidence/ps5_remote/` holds the PC-side tooling for live work on a jailbroken console, plus the native traces captured with it.
- `evidence/KernelRecovery_13.60/` holds the checkpoint history and diagnostic harnesses from bring-up.

## Configuration

```bat
copy kyty.example.ini kyty.ini
```

| Section | Key | Meaning |
| --- | --- | --- |
| `paths` | `firmware` | The `firmware/` folder. Relative paths resolve from the repo root. |
| `paths` | `evidence` | Where run folders go. |
| `paths` | `emulator` | The built `kyty_emulator.exe`. |
| `provider` | `token_file` | Path to the console provider's HMAC token file. Required. |
| `provider` | `port` | Loopback port of the provider (default 9038). |
| `provider` | `timeout_ms` | Per-request timeout. 100 to 300000. |
| `boot` | `readbacks` | `yes` dumps presented frames to `<run>/present` every 200 ms. |
| `boot` | `show_services` | `yes` gives every spawned service its own window, not just the main display window. |

`--readbacks` and `--show-services` on the command line turn the same options on for one run.

## The console provider

Some of what the firmware does can only be done by real PS5 hardware. Two operations are sent to a console:

1. **SBL envelope decrypt.** This is the security processor's decrypt of encrypted system blobs. ShellCore needs it for files like `psnow-config.env`.
2. **RNPS bundle decrypt.** ShellUI's React Native bundles (`/dev/rnps`) are encrypted, and only the console can open them.

The emulator doesn't do these itself. It sends each request to a provider on `127.0.0.1:<port>`, signed with an HMAC keyed by the token file. The provider passes it to a jailbroken PS5 on the same firmware and hands back whatever the console says. If the provider is down the request just fails, and the firmware has to deal with that like it would on hardware.

There is also an offline envelope backend for diagnostics. To use it, set `KYTY_PS5_ENVELOPE_BACKEND=local`, `KYTY_DIAGNOSTIC_ENVELOPE_LOCAL=1` and a `KYTY_PS5_ENVELOPE_LOCAL_KEYTABLE`. The log then shows `offline=1`. The launcher never turns it on.

The provider is part of the separate PS5 bridge project, not this repo. To set it up:

- Start the bridge with `scripts/supervise.py --start-bridge` from that project. The console must be on and reachable, with the bridge's payloads loaded.
- Create or rotate the token with `scripts/provision-envelope-provider.py --rotate`. Set `token_file` in `kyty.ini` to the file it writes. Rotate it at least once a day, the run scripts won't take a token older than 24 hours. After rotating, restart only the bridge child process; the supervisor brings it back.
- Never paste the token anywhere. Pass the file path only.

If provider requests in a run fail with `transport_error`, the console just wasn't reachable, so that run tells you nothing about the firmware. Don't bother comparing it against other runs.

## Building

Windows only for this fork. You need:

- Visual Studio 2022 or newer (for the Windows SDK and `vcvars64.bat`)
- LLVM (`clang-cl`, `lld-link`, `llvm-lib`)
- CMake 3.22.1 or newer
- Ninja
- `glslangValidator`

`cl.exe` is rejected at configure time.

From an x64 developer prompt:

```powershell
git submodule update --init --recursive
cmake -S . -B _Build/vsh -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo `
  -DCMAKE_C_COMPILER=clang-cl -DCMAKE_CXX_COMPILER=clang-cl `
  -DCMAKE_LINKER=lld-link -DCMAKE_AR=llvm-lib `
  -DKYTY_BUILD_LAUNCHER=OFF -DBUILD_TESTING=ON
ninja -C _Build/vsh kyty_emulator.exe
```

The first configure downloads FFmpeg, opus, xbyak, zydis, zstd and ZArchive. To configure offline afterwards, pass `-DFETCHCONTENT_FULLY_DISCONNECTED=ON` plus `-DFETCHCONTENT_SOURCE_DIR_<NAME>=_Build/vsh/_deps/<name>-src` for each dependency.

The build copies `libwinpthread-1.dll` next to the exe; the launcher needs it there.

A CMake build tree can't be moved. If you move the repo, delete `_Build/vsh/CMakeCache.txt` and `CMakeFiles/` and configure again.

### Tests

```powershell
ninja -C _Build/vsh kyty_tests
ctest --test-dir _Build/vsh --output-on-failure
```

## Running

```bat
start.bat
```

`start.bat` runs `scripts/start_kyty_ps5.py`, which does the following:

1. Reads `kyty.ini` and `boot_profile.json`, then checks that the emulator, the token file and every firmware path exist.
2. Opens one host window. The firmware's video output is presented there.
3. Starts `kyty_emulator.exe` with `mini-syscore.elf` as the entry ELF and `firmware/decrypted` as the sysroot. All processes the firmware spawns run in one job object.
4. Writes the run folder: `boot.json` records the binary, the firmware root and the profile hash; logs stream into the folder while the run goes.

Closing the window or pressing Ctrl+C ends the run (exit code 130).

The first boot after you build a new binary or move `firmware/` misses the startup metadata cache in `runtime/cache` and is slower. Later boots reuse the cache.

## Sending changes

The whole point is seeing what the firmware really does, so a hack that makes a service look like it came up isn't much use, even if it gets the boot further. If you need a workaround to get past something, put it behind a `KYTY_DIAGNOSTIC_*` env var and make it log `NON_AUTHENTIC`, so anyone reading the logs can tell it was on.

Firmware files are kept as dumped. The exception is personal stuff: user accounts, saves, logs, licenses and the console's network address were taken out of the capture before it was committed, and the manifests and pins were regenerated to match. The registry snapshot's settings rows are factory defaults, not my console's settings; only the NVS and handler-backed rows keep their captured values.

Keep `ps5_keys.txt` and provider tokens out of the repo, out of logs and out of commits.

### Formatting

```bash
python -m pip install pre-commit
python -m pre_commit install --install-hooks
```

The hook clang-formats staged `.cpp`, `.h` and `.inc` files in `src`.

## License

KytyPS5 is licensed under the [GNU General Public License version 2](LICENSE) (`GPL-2.0-only`).

This project is based on the original [Kyty](https://github.com/InoriRus/Kyty), released under the MIT License. Kyty's original copyright and license notice are kept in [`LICENSES/Kyty-MIT.txt`](LICENSES/Kyty-MIT.txt). Third-party components remain under the licenses included with them.

## Thanks

- [KytyPS5/KytyPS5](https://github.com/KytyPS5/KytyPS5): the emulator this fork is built on.
- [InoriRus/Kyty](https://github.com/InoriRus/Kyty): the original Kyty.
- [shadps4-emu/shadPS4](https://github.com/shadps4-emu/shadPS4): reference for PS4 memory behavior, GPU resource aliasing and cache coherency, and the AVPlayer implementation.
