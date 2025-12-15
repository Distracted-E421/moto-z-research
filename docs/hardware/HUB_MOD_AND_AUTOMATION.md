# Hub Mod Concept & Ghidra Automation Setup

**Created**: 2025-12-15  
**Status**: Research & Planning

---

## Part 1: The Hub Mod Concept

### Vision

Create a physical "backplane" that connects multiple Moto Z phones together:
- Centralized power distribution
- Unified data bus for orchestration
- Single management interface

```
┌─────────────────────────────────────────────────────────────────┐
│                         HUB MOD                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                  Central Controller                       │   │
│  │         (Raspberry Pi / STM32 / ESP32-S3)                │   │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐     │   │
│  │  │Ethernet │  │USB Hub  │  │Power    │  │GPIO     │     │   │
│  │  │Switch   │  │Controller│  │Distrib  │  │Expander │     │   │
│  │  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘     │   │
│  └───────┼────────────┼────────────┼────────────┼──────────┘   │
│          │            │            │            │               │
│  ┌───────┴────────────┴────────────┴────────────┴──────────┐   │
│  │                    Backplane PCB                         │   │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐     │   │
│  │  │POGO Slot│  │POGO Slot│  │POGO Slot│  │POGO Slot│     │   │
│  │  │  #1     │  │  #2     │  │  #3     │  │  #4     │     │   │
│  │  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘     │   │
│  └───────┼────────────┼────────────┼────────────┼──────────┘   │
└──────────┼────────────┼────────────┼────────────┼──────────────┘
           │            │            │            │
      ┌────┴────┐  ┌────┴────┐  ┌────┴────┐  ┌────┴────┐
      │ Moto Z  │  │ Moto Z  │  │ Moto Z  │  │ Moto Z  │
      │  #1     │  │  #2     │  │  #3     │  │  #4     │
      └─────────┘  └─────────┘  └─────────┘  └─────────┘
```

### Interface Design Options

#### Option A: POGO-Only Connection

Each phone connects via POGO pins on back:
- **Pros**: Clean, uses existing interface
- **Cons**: Limited bandwidth (USB 2.0), phones face same direction

```
Per-Phone Connection:
- Power: VBAT rail (3.7-4.2V), up to 3A
- Data: USB 2.0 (480 Mbps theoretical)
- Control: I2C for mod identification
```

#### Option B: USB-C + POGO Hybrid

POGO for power, USB-C for data:
- **Pros**: Higher data bandwidth, easier cabling
- **Cons**: More complex, requires USB-C ports

```
Per-Phone Connection:
- Power: POGO (or USB-C PD)
- Data: USB 3.0 via USB-C (5 Gbps)
- Control: USB or I2C
```

#### Option C: Dock-Style (Face Down)

Phones sit face-down in cradles:
- **Pros**: Better cooling, gravity-assisted contact
- **Cons**: Can't see screens, harder to access

### Hub Controller Options

| Controller | Pros | Cons | Est. Cost |
|------------|------|------|-----------|
| **Raspberry Pi 4/5** | Linux, Ethernet, USB | Overkill, availability | $35-80 |
| **Raspberry Pi Pico W** | Cheap, WiFi | Limited I/O | $6 |
| **ESP32-S3** | WiFi, USB Host, cheap | Less RAM | $10 |
| **STM32H7** | Fast, USB, industrial | Complex dev | $20 |
| **Compute Module 4** | Powerful, PCIe | Expensive | $45+ |

### Power Architecture

```
Main Power Input: 12V/5A (60W) or 19V/3A (57W)
                        │
                        ▼
              ┌─────────────────┐
              │  Power Supply   │
              │    Module       │
              └────────┬────────┘
                       │
        ┌──────────────┼──────────────┐
        │              │              │
        ▼              ▼              ▼
   ┌────────┐    ┌────────┐    ┌────────┐
   │5V Rail │    │3.3V    │    │VBAT    │
   │(Hub)   │    │(Logic) │    │(Phones)│
   └───┬────┘    └───┬────┘    └───┬────┘
       │             │             │
       ▼             ▼             ▼
   Controller    I2C/GPIO    Phone Power
                            (per-phone
                             current
                             limiting)
```

### Data Bus Architecture

#### Star Topology (Recommended)

```
                  Hub Controller
                       │
           ┌───────────┼───────────┐
           │           │           │
        USB Hub    Ethernet     I2C Bus
           │        Switch         │
    ┌──────┼──────┐    │    ┌──────┼──────┐
    │      │      │    │    │      │      │
  Phone1 Phone2 Phone3 │  Phone1 Phone2 Phone3
                       │  (mod ID)(mod ID)(mod ID)
                       │
                   Router/
                   Network
```

### Communication Layers

1. **Physical Layer**: POGO pins or USB-C
2. **Transport**: USB 2.0/3.0 or Ethernet
3. **Network**: IP networking (WiFi/Ethernet)
4. **Orchestration**: Kubernetes (k3s), Docker Swarm, or custom

### Bill of Materials (Prototype)

| Component | Quantity | Est. Cost |
|-----------|----------|-----------|
| Custom PCB (backplane) | 1 | $20-50 |
| POGO pin connectors (16-pin) | 4 | $40-80 |
| Raspberry Pi 4 | 1 | $55 |
| USB Hub (7-port powered) | 1 | $25 |
| 5V/10A Power Supply | 1 | $20 |
| Buck converters (3.3V, VBAT) | 4 | $10 |
| 3D printed enclosure | 1 | $10-30 |
| Misc (cables, screws, etc.) | - | $20 |
| **Total** | | **~$200-300** |

---

## Part 2: Ghidra Automation for NixOS

### NixOS Reverse Engineering Environment

#### Nix Flake for RE Tools

```nix
# re-environment.nix
{
  description = "Reverse Engineering Environment for Moto Z Research";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            # Disassemblers
            ghidra
            radare2
            
            # Binary analysis
            binutils
            file
            hexdump
            xxd
            
            # ARM specific
            arm-none-eabi-gdb
            qemu
            
            # Android tools
            android-tools  # adb, fastboot
            apktool
            jadx
            dex2jar
            
            # Python for scripting
            (python3.withPackages (ps: with ps; [
              pwntools
              capstone
              keystone-engine
              unicorn
              frida-tools
              pyusb
              construct
              pycryptodome
            ]))
            
            # Network analysis
            wireshark
            mitmproxy
            
            # Documentation
            pandoc
            graphviz
          ];
          
          shellHook = ''
            echo "🔬 Reverse Engineering Environment Loaded"
            echo "   Ghidra: $(ghidra --version 2>/dev/null || echo 'available')"
            echo "   Radare2: $(r2 -v 2>/dev/null | head -1)"
            echo ""
            echo "Quick commands:"
            echo "   ghidra           - Launch Ghidra GUI"
            echo "   analyzeHeadless  - Headless analysis"
            echo "   r2 <binary>      - Radare2 analysis"
          '';
        };
      }
    );
}
```

### Ghidra Headless Analysis

#### Setup Script

```bash
#!/usr/bin/env bash
# ghidra-analyze.sh - Automated Ghidra analysis for Moto Z binaries

GHIDRA_HOME="${GHIDRA_HOME:-$(dirname $(which ghidra))/..}"
PROJECT_DIR="${PROJECT_DIR:-$HOME/ghidra-projects}"
PROJECT_NAME="moto-z-research"

# Create project directory
mkdir -p "$PROJECT_DIR"

# Run headless analysis
analyzeHeadless() {
    local binary="$1"
    local script="${2:-}"
    
    "$GHIDRA_HOME/support/analyzeHeadless" \
        "$PROJECT_DIR" \
        "$PROJECT_NAME" \
        -import "$binary" \
        -processor ARM:LE:32:v8 \
        -cspec default \
        ${script:+-postScript "$script"} \
        -scriptPath "$HOME/ghidra-scripts" \
        -log "$PROJECT_DIR/analysis.log"
}

# Usage
if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <binary> [script.py]"
    exit 1
fi

analyzeHeadless "$@"
```

#### Python Analysis Script (Ghidra)

```python
# find_unlock_functions.py
# Run with: analyzeHeadless ... -postScript find_unlock_functions.py

from ghidra.program.model.symbol import SourceType
from ghidra.app.decompiler import DecompInterface

def find_unlock_references():
    """Find all references to unlock-related strings and functions"""
    
    # Strings to search for
    search_strings = [
        "unlock",
        "verify",
        "signature",
        "oem",
        "bootloader",
        "fastboot",
        "secure",
        "key",
        "rsa",
        "sha256"
    ]
    
    results = []
    
    # Get defined strings
    strings = currentProgram.getListing().getDefinedData(True)
    
    for string in strings:
        if string.hasStringValue():
            value = string.getValue()
            if isinstance(value, str):
                for search in search_strings:
                    if search.lower() in value.lower():
                        results.append({
                            'type': 'string',
                            'address': string.getAddress(),
                            'value': value,
                            'match': search
                        })
                        
                        # Find references to this string
                        refs = getReferencesTo(string.getAddress())
                        for ref in refs:
                            results.append({
                                'type': 'reference',
                                'from': ref.getFromAddress(),
                                'to': string.getAddress(),
                                'string': value
                            })
    
    # Print results
    print("=" * 60)
    print("UNLOCK-RELATED FINDINGS")
    print("=" * 60)
    
    for r in results:
        if r['type'] == 'string':
            print(f"STRING @ {r['address']}: '{r['value']}'")
        elif r['type'] == 'reference':
            print(f"  -> Referenced from: {r['from']}")
    
    return results

# Main execution
if __name__ == "__main__":
    find_unlock_references()
```

### radare2 Analysis Scripts

```bash
#!/usr/bin/env bash
# r2-analyze-abl.sh - Quick ABL analysis with radare2

ABL_FILE="${1:-dumps/abl_a.img}"

r2 -q -c '
# Analyze
aaa

# ARM mode
e asm.arch=arm
e asm.bits=32

# Find unlock strings
iz~unlock
iz~verify
iz~signature

# Find function calls to those references
axt @@ str.unlock*

# Export function list
aflq > /tmp/abl_functions.txt

# Decompile interesting functions
s sym.main 2>/dev/null && pdf

# Exit
q
' "$ABL_FILE"

echo "Function list saved to /tmp/abl_functions.txt"
```

### Frida Scripts for Dynamic Analysis

```javascript
// frida-hook-unlock.js
// Hook Motorola unlock verification functions

Java.perform(function() {
    console.log("[*] Frida script loaded");
    
    // Hook native functions
    const libc = Process.getModuleByName("libc.so");
    
    // Hook strcmp (often used in verification)
    Interceptor.attach(Module.findExportByName("libc.so", "strcmp"), {
        onEnter: function(args) {
            const str1 = Memory.readUtf8String(args[0]);
            const str2 = Memory.readUtf8String(args[1]);
            
            if (str1.includes("unlock") || str2.includes("unlock")) {
                console.log("[strcmp] " + str1 + " vs " + str2);
            }
        }
    });
    
    // Hook SHA256 (signature verification)
    const sha256_funcs = ["SHA256_Init", "SHA256_Update", "SHA256_Final"];
    sha256_funcs.forEach(function(func) {
        const addr = Module.findExportByName(null, func);
        if (addr) {
            Interceptor.attach(addr, {
                onEnter: function(args) {
                    console.log("[" + func + "] called");
                }
            });
        }
    });
});
```

---

## Part 3: Documentation Indexing for Cursor

### Recommended Documentation Sources

#### Add to `.cursor/docs/` or Index

| Source | URL | Content |
|--------|-----|---------|
| **Greybus Kernel Docs** | https://www.kernel.org/doc/html/latest/driver-api/greybus/ | Protocol spec |
| **ARM Architecture** | https://developer.arm.com/documentation | ARM32 reference |
| **Qualcomm Security** | https://www.qualcomm.com/company/product-security | Security bulletins |
| **Android Source** | https://source.android.com/docs/core/bootloader | Bootloader docs |
| **XDA Moto Z** | https://xdaforums.com/c/moto-z4.8910/ | Community knowledge |

#### Create `.cursor/docs/moto-z-research.md`

```markdown
# Moto Z Research Documentation Index

## Primary References

### Bootloader & Security
- [Android Verified Boot](https://source.android.com/docs/security/features/verifiedboot)
- [Qualcomm Secure Boot](https://www.qualcomm.com/media/documents/files/secure-boot-and-image-authentication-technical-overview-v2-0.pdf)

### Greybus Protocol
- [Kernel Documentation](https://www.kernel.org/doc/html/latest/driver-api/greybus/)
- [GitHub: Greybus Driver](https://github.com/torvalds/linux/tree/master/drivers/greybus)

### Reverse Engineering
- [Ghidra SRE](https://ghidra-sre.org/)
- [Radare2 Book](https://book.rada.re/)
- [ARM Assembly Basics](https://azeria-labs.com/writing-arm-assembly-part-1/)

### Moto Mods
- [Archived MDK Documentation] - (Wayback Machine)
- [iFixit Teardowns](https://www.ifixit.com/Search?query=moto+z)
```

### Cursor Rules for Moto Z Development

Create `.cursor/rules/moto-z-development.mdc`:

```markdown
# Moto Z Development Rules

## When Analyzing Binaries

1. Always load ARM 32-bit Little Endian
2. Check for Qualcomm-specific structures
3. Look for TrustZone SCM calls (0x02000000 base)
4. Certificate chains start with "Motorola Root CA"

## When Writing Analysis Scripts

1. Use Python 3 with Ghidra's Jython bridge
2. Export findings to JSON for cross-tool compatibility
3. Document all function signatures found
4. Track certificate and hash patterns

## When Building Mods

1. POGO pin voltage: 3.7-4.2V (VBAT), 3.3V (logic)
2. I2C address space: Research required
3. USB is limited to 2.0 (480 Mbps)
4. Power budget: ~15W max per mod

## Safety Rules

1. Never flash modified ABL without EDL backup
2. Test power circuits before connecting phones
3. Verify voltage levels before POGO connection
4. Keep original firmware dumps
```

---

## Part 4: Automation Workflow

### Makefile for Analysis Pipeline

```makefile
# Makefile for Moto Z reverse engineering

DUMPS_DIR := dumps
SCRIPTS_DIR := scripts
OUTPUT_DIR := analysis_output
GHIDRA_PROJECT := ghidra_project

# Binaries to analyze
BINARIES := abl_a xbl_a tz_a keymaster_a

.PHONY: all analyze strings functions clean

all: analyze strings functions

# Create output directory
$(OUTPUT_DIR):
	mkdir -p $(OUTPUT_DIR)

# Run Ghidra headless analysis on all binaries
analyze: $(OUTPUT_DIR)
	@for bin in $(BINARIES); do \
		echo "Analyzing $$bin..."; \
		./scripts/ghidra-analyze.sh $(DUMPS_DIR)/$$bin.img; \
	done

# Extract strings from all binaries
strings: $(OUTPUT_DIR)
	@for bin in $(BINARIES); do \
		echo "Extracting strings from $$bin..."; \
		strings -n 8 $(DUMPS_DIR)/$$bin.img > $(OUTPUT_DIR)/$$bin_strings.txt; \
	done

# Find unlock-related functions
functions: $(OUTPUT_DIR)
	@echo "Searching for unlock functions..."
	@grep -r -i "unlock\|verify\|signature" $(OUTPUT_DIR)/*_strings.txt > $(OUTPUT_DIR)/unlock_refs.txt || true
	@echo "Results in $(OUTPUT_DIR)/unlock_refs.txt"

# Clean up
clean:
	rm -rf $(OUTPUT_DIR)
	rm -rf $(GHIDRA_PROJECT)
```

### Nushell Script for Analysis

```nu
#!/usr/bin/env nu
# analyze-moto-dumps.nu - Analysis pipeline in Nushell

let dumps_dir = "dumps"
let output_dir = "analysis_output"

# Create output directory
mkdir $output_dir

# Analyze each dump file
def analyze-binary [file: string] {
    let basename = ($file | path basename | str replace ".img" "")
    
    print $"Analyzing ($basename)..."
    
    # Extract strings
    strings -n 8 $file | save $"($output_dir)/($basename)_strings.txt"
    
    # Find unlock-related strings
    let unlock_strings = (strings -n 8 $file | lines | where {|line| 
        $line =~ "(?i)unlock|verify|signature|bootloader|oem"
    })
    
    $unlock_strings | save $"($output_dir)/($basename)_unlock_refs.txt"
    
    print $"  Found ($unlock_strings | length) unlock-related strings"
}

# Main execution
def main [] {
    ls $"($dumps_dir)/*.img" | each {|file|
        analyze-binary $file.name
    }
    
    print "Analysis complete!"
}

main
```

---

## Part 5: Project Structure

### Recommended Repository Layout

```
moto-z-research/
├── README.md
├── flake.nix                    # NixOS development environment
├── Makefile                     # Build automation
│
├── docs/
│   ├── HUB_MOD_DESIGN.md
│   ├── BOOTLOADER_ANALYSIS.md
│   ├── GREYBUS_PROTOCOL.md
│   └── POGO_PIN_SPECS.md
│
├── hardware/
│   ├── hub-mod/
│   │   ├── schematic.kicad_sch
│   │   ├── pcb.kicad_pcb
│   │   └── bom.csv
│   └── pogo-adapter/
│       └── 3d-models/
│
├── firmware/
│   ├── hub-controller/          # STM32/ESP32 firmware
│   └── test-mod/                # Simple test mod
│
├── analysis/
│   ├── ghidra-scripts/
│   │   ├── find_unlock_funcs.py
│   │   └── extract_certs.py
│   ├── r2-scripts/
│   └── frida-scripts/
│
├── tools/
│   ├── unlock-data-parser.py
│   ├── pogo-pin-tester.py
│   └── mod-simulator.py
│
├── dumps/                       # (gitignored - local only)
│   ├── abl_a.img
│   ├── xbl_a.img
│   └── ...
│
└── .cursor/
    └── rules/
        └── moto-z-development.mdc
```

---

## Next Steps

### Immediate (This Week)

1. [ ] Set up Nix flake for RE environment
2. [ ] Install Ghidra on Obsidian
3. [ ] Run initial string analysis on ABL dump
4. [ ] Create Cursor rules file

### Short Term (This Month)

1. [ ] Document POGO pin voltages with multimeter
2. [ ] Capture I2C traffic during mod attachment
3. [ ] Find and archive MDK documentation
4. [ ] Build simple test mod (LED + I2C)

### Medium Term (3 Months)

1. [ ] Design hub mod PCB
2. [ ] Prototype with breadboard
3. [ ] Write Greybus analysis tools
4. [ ] Create open-source mod SDK

### Long Term (6+ Months)

1. [ ] Release hub mod design
2. [ ] Build community around project
3. [ ] Document unlock research findings
4. [ ] Open-source all tools and knowledge

---

*Document created: 2025-12-15*
*This is a living document - will be updated as research progresses*
