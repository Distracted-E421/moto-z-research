#!/usr/bin/env python3
"""
Moto Z Unlock Analyzer - Parse and analyze unlock data.

This tool parses the unlock data from `fastboot oem get_unlock_data`
and provides analysis of its structure.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


@dataclass
class UnlockData:
    """Parsed unlock data structure."""
    
    raw: str
    lines: list[str]
    combined: str
    
    # Parsed fields (best-effort)
    hwid: Optional[bytes] = None
    serial_hash: Optional[bytes] = None
    device_data: Optional[bytes] = None
    
    @classmethod
    def from_fastboot_output(cls, output: str) -> UnlockData:
        """Parse raw fastboot oem get_unlock_data output."""
        lines = []
        
        for line in output.strip().split('\n'):
            # Strip (bootloader) prefix
            if '(bootloader)' in line:
                data = line.split('(bootloader)')[-1].strip()
                lines.append(data)
            else:
                lines.append(line.strip())
        
        # Filter empty lines
        lines = [l for l in lines if l]
        
        # Combine all lines (the unlock code is split across multiple lines)
        combined = ''.join(lines)
        
        return cls(
            raw=output,
            lines=lines,
            combined=combined
        )
    
    def analyze(self) -> dict:
        """Analyze the unlock data structure."""
        analysis = {
            'total_length': len(self.combined),
            'line_count': len(self.lines),
            'line_lengths': [len(l) for l in self.lines],
            'charset': set(self.combined),
            'is_hex': all(c in '0123456789ABCDEFabcdef' for c in self.combined),
        }
        
        if analysis['is_hex'] and len(self.combined) % 2 == 0:
            try:
                raw_bytes = bytes.fromhex(self.combined)
                analysis['byte_length'] = len(raw_bytes)
                
                # Try to identify structure
                # Motorola unlock data is typically: HWID + Serial Hash + Device Data + Signature
                analysis['possible_structure'] = {
                    'hwid': raw_bytes[:16].hex() if len(raw_bytes) >= 16 else None,
                    'data': raw_bytes[16:].hex() if len(raw_bytes) > 16 else None,
                }
            except ValueError:
                pass
        
        return analysis


def display_analysis(data: UnlockData, analysis: dict) -> None:
    """Display analysis results."""
    
    console.print(Panel("[bold cyan]Moto Z Unlock Data Analysis[/bold cyan]"))
    console.print()
    
    # Basic info table
    table = Table(title="Basic Information")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Total Length", str(analysis['total_length']))
    table.add_row("Line Count", str(analysis['line_count']))
    table.add_row("Is Hex", "✅ Yes" if analysis['is_hex'] else "❌ No")
    
    if 'byte_length' in analysis:
        table.add_row("Byte Length", str(analysis['byte_length']))
    
    console.print(table)
    console.print()
    
    # Line breakdown
    line_table = Table(title="Line Breakdown")
    line_table.add_column("#", style="dim")
    line_table.add_column("Length", style="cyan")
    line_table.add_column("Content (truncated)", style="yellow")
    
    for i, (line, length) in enumerate(zip(data.lines, analysis['line_lengths'])):
        line_table.add_row(
            str(i + 1),
            str(length),
            line[:50] + ('...' if len(line) > 50 else '')
        )
    
    console.print(line_table)
    console.print()
    
    # Structure analysis
    if 'possible_structure' in analysis:
        struct_table = Table(title="Possible Structure")
        struct_table.add_column("Field", style="cyan")
        struct_table.add_column("Hex Value (truncated)", style="green")
        
        for field, value in analysis['possible_structure'].items():
            if value:
                struct_table.add_row(field, value[:64] + ('...' if len(value) > 64 else ''))
        
        console.print(struct_table)


def main():
    parser = argparse.ArgumentParser(
        description="Analyze Moto Z unlock data"
    )
    parser.add_argument(
        'input',
        nargs='?',
        help="File containing unlock data or '-' for stdin"
    )
    parser.add_argument(
        '--raw',
        action='store_true',
        help="Input is raw hex string (not fastboot output)"
    )
    
    args = parser.parse_args()
    
    # Read input
    if args.input == '-' or args.input is None:
        console.print("[dim]Reading from stdin...[/dim]")
        input_data = sys.stdin.read()
    else:
        input_path = Path(args.input)
        if not input_path.exists():
            console.print(f"[red]Error: File not found: {args.input}[/red]")
            sys.exit(1)
        input_data = input_path.read_text()
    
    # Parse
    if args.raw:
        # Treat as raw hex string
        data = UnlockData(
            raw=input_data,
            lines=[input_data.strip()],
            combined=input_data.strip()
        )
    else:
        data = UnlockData.from_fastboot_output(input_data)
    
    # Analyze
    analysis = data.analyze()
    
    # Display
    display_analysis(data, analysis)
    
    # Output combined code for easy copying
    console.print()
    console.print(Panel(
        f"[bold]Combined Unlock Code:[/bold]\n\n{data.combined}",
        title="For Motorola Portal",
        border_style="green"
    ))


if __name__ == "__main__":
    main()
