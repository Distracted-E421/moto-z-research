# Quick Start Guide

Get started with the Moto Z Research environment in 5 minutes.

## Prerequisites

- NixOS or Nix package manager installed
- USB cable for device connection
- A Moto Z device (Z, Z2, Z3, or Z4)

## Setup

### 1. Clone the Repository

```bash
git clone https://github.com/Distracted-E421/moto-z-research.git
cd moto-z-research
```

### 2. Enter Development Environment

```bash
nix develop
```

This provides:
- Ghidra, radare2, rizin (disassembly)
- Python 3.12 with RE packages (capstone, unicorn, pwntools)
- adb, fastboot (Android tools)
- mitmproxy (network analysis)
- ARM toolchains

### 3. Verify Device Connection

```bash
# Check available targets
make status

# Get device info
make info
```

### 4. Open in Cursor

The repository includes custom Cursor configuration:
- `.cursor/rules/` - Analysis workflow guidelines
- `.cursor/agents/` - Project-specific AI configuration
- `.cursor/mcp.json` - MCP server configuration

Simply open the folder in Cursor to use the configured assistant.

## Common Workflows

### Analyze Firmware Dump

```bash
# Place dump files in dumps/
cp /path/to/abl_a.img dumps/

# Run analysis
make analyze

# Or extract strings manually
make strings
```

### Run Ghidra Script

```bash
# Headless analysis with script
./src/scripts/ghidra-headless.sh dumps/abl_a.img find_unlock_functions.py

# Or launch GUI
ghidra
```

### Intercept Network Traffic

```bash
# Start mitmproxy
mitmproxy -p 8080

# Configure device to use proxy
# Then access Motorola unlock portal
```

### Parse Unlock Data

```bash
# Get unlock data from device
adb reboot bootloader
fastboot oem get_unlock_data 2>&1 | tee unlock_data.txt

# Analyze it
python src/tools/unlock_analyzer.py unlock_data.txt
```

## Project Layout

```
moto-z-research/
├── src/
│   ├── analysis/ghidra/    # Ghidra scripts
│   ├── tools/              # Python tools
│   └── scripts/            # Shell automation
├── docs/
│   ├── research/           # Technical findings
│   ├── hardware/           # Moto Mods specs
│   └── guides/             # How-to guides (you are here)
├── dumps/                  # Device dumps (gitignored)
├── firmware/               # Extracted firmware
└── flake.nix               # Nix environment
```

## Next Steps

1. **Read the research docs** - `docs/research/DEEP_TECHNICAL_ANALYSIS.md`
2. **Understand the vectors** - `docs/research/VECTOR_*.md`
3. **Get firmware dumps** - See "Dumping Firmware" section
4. **Start analysis** - Load dumps in Ghidra

## Troubleshooting

### "Device not found"

```bash
# Check USB connection
lsusb | grep -i motorola

# Restart adb server
adb kill-server
adb start-server
```

### "Permission denied" on USB

```bash
# On NixOS, ensure adb is enabled in configuration
programs.adb.enable = true;

# Add user to adbusers group
users.users.YOUR_USER.extraGroups = [ "adbusers" ];
```

### Ghidra won't start

```bash
# Ensure you're in the nix develop shell
nix develop

# Then try ghidra
ghidra
```
