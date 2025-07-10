# MobaXterm AutoKey

A Go utility to automatically generate valid license keys for MobaXterm.

## Installation

### Option 1: Download Pre-built Binary
Download the latest release from the [Releases page](https://github.com/pvelati/mobaxterm-autokey/releases)

### Option 2: Build from Source
```bash
# Clone the repository
git clone https://github.com/pvelati/mobaxterm-autokey.git
cd mobaxterm-autokey

# Build for Windows (on Windows)
go build -o mobaxterm-autokey.exe

# Cross-compile for Windows (on Linux/Mac)
GOOS=windows GOARCH=amd64 go build -o mobaxterm-autokey.exe
```

## Usage
1. Place the `mobaxterm-autokey.exe` in the same directory as your MobaXterm installation
2. Run the executable by double-clicking it
3. The tool will automatically detect your MobaXterm version and generate a `Custom.mxtpro` license file

## Important Notices

### Legal Disclaimer
**Educational Purpose Only**: This tool is created for educational and research purposes to understand software licensing mechanisms.

Users are responsible for ensuring compliance with:
- MobaXterm's End User License Agreement
- Applicable copyright laws in their jurisdiction
- Local software licensing regulations

### Ethical Usage
- Consider purchasing a legitimate license if you use MobaXterm professionally
- Support the developers who create useful software
- Use this tool responsibly and legally

**Note**: Please consider purchasing a legitimate MobaXterm license to support the developers

### No Warranty
This software is provided "as is" without warranty of any kind. The authors assume no responsibility for:
- Any damages resulting from use of this software
- Legal consequences of misuse
- Compatibility with future MobaXterm versions

## Acknowledgments
- **MobaXterm Team**: For creating excellent terminal software
- *Other similar project on Github*: inspired by other scripts, especially for the reverse engineering part

