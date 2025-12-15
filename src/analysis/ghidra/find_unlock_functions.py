# Ghidra Script: Find potential bootloader unlock verification functions
# @category Moto Z Research
# @author Moto Z Research Project

from ghidra.program.model.listing import Function
from ghidra.program.model.symbol import SourceType
import re

def find_strings_containing(patterns):
    """Find all strings containing any of the given patterns."""
    results = []
    string_data = currentProgram.getListing().getDefinedData(True)
    
    for data in string_data:
        if data.hasStringValue():
            value = data.getValue()
            if value:
                for pattern in patterns:
                    if pattern.lower() in str(value).lower():
                        results.append({
                            'address': data.getAddress(),
                            'value': str(value),
                            'pattern': pattern
                        })
                        break
    return results

def find_xrefs_to_strings(string_results):
    """Find all cross-references to the found strings."""
    xref_results = []
    ref_manager = currentProgram.getReferenceManager()
    
    for string_info in string_results:
        refs = ref_manager.getReferencesTo(string_info['address'])
        for ref in refs:
            func = getFunctionContaining(ref.getFromAddress())
            if func:
                xref_results.append({
                    'function': func,
                    'from_addr': ref.getFromAddress(),
                    'string': string_info['value'],
                    'pattern': string_info['pattern']
                })
    return xref_results

def analyze_function(func):
    """Analyze a function for unlock-related behavior."""
    analysis = {
        'name': func.getName(),
        'address': func.getEntryPoint(),
        'size': func.getBody().getNumAddresses(),
        'calls': [],
        'strings': [],
        'interesting_ops': []
    }
    
    # Get all calls from this function
    ref_manager = currentProgram.getReferenceManager()
    for ref in ref_manager.getReferencesFrom(func.getEntryPoint()):
        if ref.getReferenceType().isCall():
            called_func = getFunctionAt(ref.getToAddress())
            if called_func:
                analysis['calls'].append(called_func.getName())
    
    return analysis

def main():
    print("=" * 60)
    print("Moto Z Research - Bootloader Unlock Function Finder")
    print("=" * 60)
    print("")
    
    # Patterns to search for
    patterns = [
        "unlock",
        "verify",
        "signature",
        "oem",
        "bootloader",
        "fastboot",
        "devinfo",
        "securestate",
        "frp",
        "RSA",
        "SHA",
        "hash"
    ]
    
    print("[*] Searching for strings containing:", patterns)
    strings = find_strings_containing(patterns)
    print("[*] Found {} matching strings".format(len(strings)))
    print("")
    
    # Group by pattern
    by_pattern = {}
    for s in strings:
        pattern = s['pattern']
        if pattern not in by_pattern:
            by_pattern[pattern] = []
        by_pattern[pattern].append(s)
    
    for pattern, items in sorted(by_pattern.items()):
        print("[{}] {} occurrences".format(pattern, len(items)))
        for item in items[:5]:  # Show first 5
            print("    {} - {}".format(item['address'], item['value'][:60]))
        if len(items) > 5:
            print("    ... and {} more".format(len(items) - 5))
    
    print("")
    print("[*] Finding functions that reference these strings...")
    xrefs = find_xrefs_to_strings(strings)
    
    # Deduplicate by function
    unique_funcs = {}
    for xref in xrefs:
        func_addr = str(xref['function'].getEntryPoint())
        if func_addr not in unique_funcs:
            unique_funcs[func_addr] = {
                'function': xref['function'],
                'patterns': set(),
                'strings': []
            }
        unique_funcs[func_addr]['patterns'].add(xref['pattern'])
        unique_funcs[func_addr]['strings'].append(xref['string'])
    
    print("[*] Found {} unique functions referencing interesting strings".format(len(unique_funcs)))
    print("")
    
    # Rank functions by number of patterns they reference
    ranked = sorted(unique_funcs.values(), 
                   key=lambda x: len(x['patterns']), 
                   reverse=True)
    
    print("=" * 60)
    print("Top 10 Most Interesting Functions (by pattern diversity)")
    print("=" * 60)
    
    for i, func_info in enumerate(ranked[:10]):
        func = func_info['function']
        patterns = func_info['patterns']
        
        print("")
        print("#{}: {} @ {}".format(i+1, func.getName(), func.getEntryPoint()))
        print("    Patterns: {}".format(", ".join(sorted(patterns))))
        print("    Size: {} bytes".format(func.getBody().getNumAddresses()))
        
        # Get caller count
        ref_manager = currentProgram.getReferenceManager()
        callers = list(ref_manager.getReferencesTo(func.getEntryPoint()))
        print("    Callers: {}".format(len(callers)))
        
        # Sample strings
        print("    Sample strings:")
        for s in func_info['strings'][:3]:
            print("      - {}".format(s[:50]))
    
    print("")
    print("=" * 60)
    print("Analysis complete. Review functions above for unlock logic.")
    print("=" * 60)

if __name__ == "__main__":
    main()
