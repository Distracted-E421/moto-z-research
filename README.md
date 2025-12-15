# 🔬 Moto Z Research

Reverse engineering Motorola bootloader unlock systems and the Moto Mods interface.

## 🎯 Project Goals

1. **Bootloader Unlock Research** - Understand and document the unlock verification system
2. **Carrier Liberation** - Enable locked devices to be repurposed
3. **Moto Mods Open Source** - Reverse engineer the proprietary mod interface
4. **Device Revival** - Extend the useful life of Moto Z hardware

## 📱 Target Devices

| Device | Codename | SoC | Status |
|--------|----------|-----|--------|
| Moto Z4 | foles | SD675 | 🔄 Primary |
| Moto Z3 | messi | SD835 | 📋 Planned |
| Moto Z2 Force | nash | SD835 | 📋 Planned |
| Moto Z | griffin | SD820 | 📋 Planned |

## 🚀 Quick Start

### Prerequisites

- NixOS or Nix package manager
- USB access to device

### Enter Development Environment

```bash
# Clone the repository
git clone https://github.com/YOUR_USER/moto-z-research.git
cd moto-z-research

# Enter the Nix development shell
nix develop

# You now have access to:
# - ghidra, radare2, rizin (disassembly)
# - adb, fastboot (device tools)
# - Python RE toolkit (capstone, unicorn, etc.)
# - mitmproxy (network analysis)
```

### Device Connection

```bash
# Verify device connected
adb devices

# Get bootloader info
adb reboot bootloader
fastboot getvar all

# Get unlock data (if portal method works)
fastboot oem get_unlock_data
```

## 📁 Repository Structure

```
moto-z-research/
├── .cursor/           # Cursor IDE configuration
│   ├── rules/         # AI assistant guidelines
│   ├── agents/        # Agent configurations
│   └── docs/          # Documentation index
│
├── src/
│   ├── analysis/      # Ghidra/r2 scripts
│   ├── tools/         # Python analysis tools
│   └── scripts/       # Automation scripts
│
├── docs/
│   ├── research/      # Technical findings
│   ├── hardware/      # Moto Mods specs
│   └── guides/        # How-to guides
│
├── firmware/          # Extracted firmware components
├── hardware/          # PCB designs, schematics
├── dumps/             # Device dumps (gitignored)
│
├── flake.nix          # Nix development environment
└── README.md
```

## 🔬 Research Areas

### Bootloader Unlock

The Motorola unlock system uses:
- Device-specific hardware ID (HWID)
- RSA signature verification
- TrustZone-backed key validation

Key files to analyze:
- `abl.elf` - Android Bootloader (ABL)
- `xbl.elf` - eXtensible Bootloader (XBL)
- `tz.mbn` - TrustZone image

### Moto Mods Interface

The mod connection uses:
- 16-pin POGO connector
- Greybus protocol (USB + I2C)
- UniPro physical layer
- ~15W power budget

## 🛠️ Tools

| Tool | Purpose | Documentation |
|------|---------|---------------|
| Ghidra | Primary disassembler | [docs/guides/ghidra.md](docs/guides/ghidra.md) |
| Radare2 | Quick analysis | [docs/guides/radare2.md](docs/guides/radare2.md) |
| mitmproxy | API analysis | [docs/guides/network.md](docs/guides/network.md) |
| EDL | Emergency flash | [docs/guides/edl.md](docs/guides/edl.md) |

## ⚠️ Legal & Ethics

This project is for:
- ✅ Educational security research
- ✅ Right-to-repair advocacy
- ✅ Reducing e-waste

This project is NOT for:
- ❌ Unlocking stolen devices
- ❌ Commercial unlock services
- ❌ Warranty fraud

**All research is conducted on devices owned by the researchers.**

See [.cursor/rules/safety-and-ethics.mdc](.cursor/rules/safety-and-ethics.mdc) for full guidelines.

## 📚 Documentation

- [Research Summary](docs/research/SUMMARY.md)
- [Technical Deep Dive](docs/research/DEEP_ANALYSIS.md)
- [Hardware Specs](docs/hardware/MOTO_MODS.md)

## 🤝 Contributing

1. Fork the repository
2. Enter dev environment: `nix develop`
3. Create analysis branch
4. Document findings thoroughly
5. Submit PR with analysis notes

## 📜 License

Research documentation: CC BY-SA 4.0
Code: MIT License

---

**Disclaimer**: This project is for educational and research purposes only. Use responsibly and ethically. The authors are not responsible for misuse.
