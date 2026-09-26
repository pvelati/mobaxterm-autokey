# MobaXterm AutoKey

> **Status: ARCHIVED / NO LONGER MAINTAINED**
>
> This project is finished, not abandoned accidentally. The original author
> no longer uses MobaXterm or Windows and does not intend to actively
> maintain it. It is preserved as a historical baseline for study and
> forking. See [GOAL.md](GOAL.md) for the full maintenance policy,
> known limitations, and forking guidance.

A small, self-contained Go utility that automates the generation of a
`Custom.mxtpro` file for MobaXterm. It was developed as a reverse-engineering
experiment around MobaXterm's license-file format and Windows executable
version information.

## What the Original Program Did

1. Searches the current working directory for the first `MobaXterm*.exe` file.
2. Extracts the major/minor file version from the executable's Windows
   version resources (`version.dll` API).
3. Builds a license string in the format the original implementation reverse
   engineered: `type#username|major minor#count#...#` (see
   `generateLicense` in [main.go](main.go)).
4. Encrypts it with a rolling XOR key and encodes it with a custom
   base64-like scheme.
5. Writes the result as `Custom.mxtpro` — a ZIP archive containing a stored
   (uncompressed) `Pro.key` entry.

Implementation notes:

- Pure Go, **no external dependencies** (`go.mod` declares only the module).
- **Windows-only**: it calls `version.dll` directly via `syscall`.
- Several values (license type, username `registered_user`, count `1`,
  output filename `Custom.mxtpro`) are fixed for the original use case, not
  configurable.

## Final Release

**[1.0.0](https://github.com/pvelati/mobaxterm-autokey/releases/tag/1.0.0)** is
the final maintained state of the project. No compatibility with newer
MobaXterm releases is claimed or guaranteed.

## Building from Source

```bash
git clone https://github.com/pvelati/mobaxterm-autokey.git
cd mobaxterm-autokey

# Cross-compile for Windows (works on Linux/macOS)
GOOS=windows GOARCH=amd64 go build -o mobaxterm-autokey.exe

# Or build natively on Windows
go build -o mobaxterm-autokey.exe
```

Place `mobaxterm-autokey.exe` in the directory containing your MobaXterm
executable and run it. It reads the version, then writes `Custom.mxtpro` next
to it.

## Historical Limitations

These are properties of the original implementation, not a specification for
future work:

- Windows APIs only; expects the executable in the current directory.
- Takes the first `MobaXterm*.exe` match it finds.
- Extracts only major/minor version.
- Fixed output filename and fixed internal constants.

A fork must validate any of this independently for current MobaXterm
versions. Nothing in this repository is an authoritative implementation for
newer software.

## Forking

Forks are welcome. Treat this repository as a historical baseline. A fork
should maintain its own compatibility information, testing strategy, release
history, documentation, and security/legal review, and should clearly
distinguish its changes from the original implementation.

## Legal Notice

This source code is released under the [GNU General Public License v3](LICENSE).

The existence of this project does not grant any additional rights to
MobaXterm or its proprietary software, trademarks, licenses, or intellectual
property. Users and fork maintainers are responsible for determining whether
their use is permitted under the applicable MobaXterm license terms and
applicable law. This repository is preserved for historical, research, and
software-development purposes and is not legal advice.
