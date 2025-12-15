# Moto Z Research - Common Operations

.PHONY: help dev clean analyze strings dump test docs

# Default target
help:
	@echo "╔══════════════════════════════════════════════════════════════╗"
	@echo "║              Moto Z Research - Make Targets                  ║"
	@echo "╠══════════════════════════════════════════════════════════════╣"
	@echo "║                                                              ║"
	@echo "║  Development:                                                ║"
	@echo "║    make dev        - Enter nix development shell             ║"
	@echo "║    make test       - Run test suite                          ║"
	@echo "║    make clean      - Clean build artifacts                   ║"
	@echo "║                                                              ║"
	@echo "║  Analysis:                                                   ║"
	@echo "║    make analyze    - Run full analysis pipeline              ║"
	@echo "║    make strings    - Extract strings from all dumps          ║"
	@echo "║    make functions  - List interesting functions              ║"
	@echo "║                                                              ║"
	@echo "║  Device:                                                     ║"
	@echo "║    make status     - Check device connection                 ║"
	@echo "║    make dump       - Dump device partitions (careful!)       ║"
	@echo "║    make info       - Get device info                         ║"
	@echo "║                                                              ║"
	@echo "║  Documentation:                                              ║"
	@echo "║    make docs       - Build documentation                     ║"
	@echo "║                                                              ║"
	@echo "╚══════════════════════════════════════════════════════════════╝"

# Enter development shell
dev:
	nix develop

# Run tests
test:
	@echo "Running tests..."
	python -m pytest src/tests/ -v

# Clean artifacts
clean:
	rm -rf result result-*
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true

# ═══════════════════════════════════════════════════════════
# Analysis Targets
# ═══════════════════════════════════════════════════════════

# Full analysis pipeline
analyze:
	@echo "Running analysis pipeline..."
	@if [ ! -d "dumps" ] || [ -z "$$(ls -A dumps 2>/dev/null)" ]; then \
		echo "⚠️  No dumps found in dumps/ directory"; \
		echo "   Use 'make dump' first (with device connected)"; \
		exit 1; \
	fi
	./src/scripts/analyze_all.nu

# Extract strings from dumps
strings:
	@echo "Extracting strings from dumps..."
	@mkdir -p analysis_output
	@for f in dumps/*.img dumps/*.bin dumps/*.elf 2>/dev/null; do \
		if [ -f "$$f" ]; then \
			echo "Processing: $$f"; \
			strings -n 8 "$$f" > "analysis_output/$$(basename $$f).strings"; \
		fi \
	done
	@echo "Strings saved to analysis_output/"

# Find interesting functions in strings
functions:
	@echo "Searching for interesting patterns..."
	@grep -rhiE "(verify|unlock|sign|cert|key|oem|boot|trust)" analysis_output/*.strings 2>/dev/null | sort -u | head -100

# ═══════════════════════════════════════════════════════════
# Device Targets
# ═══════════════════════════════════════════════════════════

# Check device status
status:
	@echo "Checking device status..."
	@echo ""
	@echo "=== ADB Devices ==="
	@adb devices 2>/dev/null || echo "ADB not available"
	@echo ""
	@echo "=== Fastboot Devices ==="
	@fastboot devices 2>/dev/null || echo "Fastboot not available"
	@echo ""
	@lsusb | grep -i "motorola\|qualcomm" || echo "No Motorola/Qualcomm USB devices"

# Get device info
info:
	@echo "Getting device info..."
	@if adb devices | grep -q "device$$"; then \
		echo "=== ADB Info ==="; \
		adb shell getprop ro.product.model; \
		adb shell getprop ro.product.device; \
		adb shell getprop ro.build.fingerprint; \
	elif fastboot devices | grep -q "fastboot"; then \
		echo "=== Fastboot Info ==="; \
		fastboot getvar product 2>&1 || true; \
		fastboot getvar serialno 2>&1 || true; \
		fastboot getvar version-bootloader 2>&1 || true; \
		fastboot getvar securestate 2>&1 || true; \
	else \
		echo "No device detected"; \
	fi

# Dump partitions (CAREFUL!)
dump:
	@echo "⚠️  PARTITION DUMP - This requires device in fastboot mode"
	@echo "⚠️  Ensure you understand what you're doing!"
	@echo ""
	@read -p "Device in fastboot and ready? (yes/no): " confirm; \
	if [ "$$confirm" = "yes" ]; then \
		./src/scripts/dump_partitions.nu; \
	else \
		echo "Aborted"; \
	fi

# ═══════════════════════════════════════════════════════════
# Documentation
# ═══════════════════════════════════════════════════════════

docs:
	@echo "Building documentation..."
	@mkdir -p docs/_build
	@pandoc README.md -o docs/_build/README.html 2>/dev/null || echo "pandoc not available"
	@echo "Documentation built in docs/_build/"
