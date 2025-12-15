{
  description = "Moto Z Research - Bootloader unlock & Mods reverse engineering";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          config.allowUnfree = true;  # For some RE tools
        };
        
        # Python environment with RE packages
        pythonEnv = pkgs.python312.withPackages (ps: with ps; [
          # Binary analysis
          capstone           # Disassembly framework
          keystone-engine    # Assembler framework
          unicorn            # CPU emulator
          pwntools           # CTF/exploit toolkit
          
          # USB/Hardware
          pyusb              # USB communication
          pyserial           # Serial communication
          
          # Crypto analysis
          pycryptodome       # Crypto primitives
          
          # Data handling
          construct          # Binary parsing
          hexdump            # Hex utilities
          
          # Automation
          requests           # HTTP
          beautifulsoup4     # Web scraping (for docs)
          
          # Development
          ipython            # Interactive shell
          rich               # Pretty printing
          typer              # CLI framework
        ]);
        
      in {
        # Development shell
        devShells.default = pkgs.mkShell {
          name = "moto-z-research";
          
          buildInputs = with pkgs; [
            # === Reverse Engineering ===
            ghidra              # NSA's RE tool
            radare2             # Alternative RE framework
            rizin               # Radare2 fork
            iaito               # Rizin GUI
            
            # === Binary Analysis ===
            binutils            # objdump, readelf, etc.
            file                # File type detection
            hexyl               # Hex viewer (better than xxd)
            binwalk             # Firmware extraction
            
            # === ARM Development ===
            gcc-arm-embedded    # ARM GCC toolchain
            # arm-none-eabi-gdb   # ARM debugger (if available)
            qemu                # Emulation
            
            # === Android Tools ===
            android-tools       # adb, fastboot
            apktool             # APK decompilation
            jadx                # DEX decompiler
            # dex2jar           # DEX to JAR (if available)
            
            # === Python Environment ===
            pythonEnv
            
            # === Network Analysis ===
            wireshark           # Packet capture GUI
            tshark              # CLI packet analysis
            mitmproxy           # HTTPS interception
            
            # === USB/Hardware ===
            usbutils            # lsusb
            libusb1             # USB library
            openocd             # On-chip debugger
            
            # === Build Tools ===
            gnumake
            cmake
            ninja
            
            # === Documentation ===
            pandoc              # Document conversion
            graphviz            # Diagrams
            
            # === Utilities ===
            jq                  # JSON processing
            yq                  # YAML processing
            ripgrep             # Fast search
            fd                  # Fast find
            tree                # Directory tree
            bat                 # Better cat
            eza                 # Better ls
          ];
          
          shellHook = ''
            echo ""
            echo "╔══════════════════════════════════════════════════════════════╗"
            echo "║       🔬 Moto Z Research Environment                          ║"
            echo "║       Bootloader Unlock & Mods Reverse Engineering           ║"
            echo "╠══════════════════════════════════════════════════════════════╣"
            echo "║                                                              ║"
            echo "║  Tools available:                                            ║"
            echo "║    ghidra        - Launch Ghidra GUI                         ║"
            echo "║    r2 <file>     - Radare2 analysis                          ║"
            echo "║    iaito         - Rizin GUI                                 ║"
            echo "║    adb/fastboot  - Android device tools                      ║"
            echo "║    mitmproxy     - HTTP/S interception                       ║"
            echo "║                                                              ║"
            echo "║  Quick commands:                                             ║"
            echo "║    make analyze  - Run analysis pipeline                     ║"
            echo "║    make strings  - Extract strings from dumps                ║"
            echo "║    ./scripts/ghidra-headless.sh <binary>                    ║"
            echo "║                                                              ║"
            echo "╚══════════════════════════════════════════════════════════════╝"
            echo ""
            
            # Set up paths
            export PROJECT_ROOT="$(pwd)"
            export GHIDRA_SCRIPTS="$PROJECT_ROOT/src/analysis/ghidra"
            export DUMPS_DIR="$PROJECT_ROOT/dumps"
            
            # Create dumps directory if missing
            mkdir -p "$DUMPS_DIR"
            
            # Aliases
            alias ll='eza -la'
            alias analyze='make analyze'
            alias strings-all='make strings'
          '';
        };
        
        # Packages we might want to build
        packages = {
          # Our analysis tools
          moto-unlock-analyzer = pkgs.writeShellScriptBin "moto-unlock-analyzer" ''
            ${pythonEnv}/bin/python $PROJECT_ROOT/src/tools/unlock_analyzer.py "$@"
          '';
        };
      }
    );
}
