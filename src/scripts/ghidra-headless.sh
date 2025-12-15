#!/usr/bin/env bash
# Run Ghidra in headless mode with our scripts

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
GHIDRA_PROJECTS="$PROJECT_ROOT/ghidra_projects"
GHIDRA_SCRIPTS="$PROJECT_ROOT/src/analysis/ghidra"

# Create projects directory
mkdir -p "$GHIDRA_PROJECTS"

usage() {
    echo "Usage: $0 <binary> [script.py]"
    echo ""
    echo "Analyze binary with Ghidra in headless mode"
    echo ""
    echo "Arguments:"
    echo "  binary     Path to binary file to analyze"
    echo "  script.py  Optional: Ghidra Python script to run"
    exit 1
}

if [ $# -lt 1 ]; then
    usage
fi

BINARY="$1"
BINARY_NAME=$(basename "$BINARY" | sed 's/\.[^.]*$//')

if [ ! -f "$BINARY" ]; then
    echo "Error: Binary not found: $BINARY"
    exit 1
fi

echo "═══════════════════════════════════════════════════════════"
echo "🔬 Ghidra Headless Analysis"
echo "═══════════════════════════════════════════════════════════"
echo "Binary: $BINARY"
echo "Project: $GHIDRA_PROJECTS/moto-z"
echo ""

if [ $# -ge 2 ]; then
    SCRIPT="$2"
    echo "Script: $SCRIPT"
    analyzeHeadless "$GHIDRA_PROJECTS" "moto-z" \
        -import "$BINARY" \
        -processor ARM:LE:32:v8 \
        -scriptPath "$GHIDRA_SCRIPTS" \
        -postScript "$SCRIPT" \
        -deleteProject
else
    echo "Running auto-analysis only..."
    analyzeHeadless "$GHIDRA_PROJECTS" "moto-z" \
        -import "$BINARY" \
        -processor ARM:LE:32:v8 \
        -deleteProject
fi

echo ""
echo "✅ Analysis complete"
