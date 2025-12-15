# MCP Configuration Notes

## Active Servers

### filesystem
Access to:
- Project directory: `/home/e421/moto-z-research`
- Config: `~/.config`  
- Temp: `/tmp`

### memory
Persistent knowledge storage for:
- Analysis findings
- Device specifications
- Research progress

### github
Repository operations for this project.

## Potential Additional Servers

### For Enhanced RE Workflow

1. **disassembly-mcp** (if available)
   - Direct radare2/Ghidra integration
   - Would need to be custom built

2. **device-mcp** (potential custom build)
   - ADB/fastboot wrapper
   - Device state monitoring

3. **documentation-mcp**
   - Auto-generate docs from analysis
   - Markdown rendering

### For Hardware Research

1. **schematic-mcp** (if available)
   - KiCad integration
   - Component lookup

## Custom MCP Ideas for This Project

### moto-z-mcp (concept)

Would provide:
```json
{
  "tools": [
    "device_status",      // ADB/fastboot detection
    "dump_partition",     // Safe partition dumps  
    "analyze_binary",     // Run Ghidra scripts
    "search_patterns",    // Pattern search in dumps
    "document_finding"    // Auto-create analysis docs
  ]
}
```

This could be built as a Python MCP server using:
- `mcp` package
- Android tools subprocess wrappers
- Ghidra headless integration

See: https://github.com/modelcontextprotocol/python-sdk
