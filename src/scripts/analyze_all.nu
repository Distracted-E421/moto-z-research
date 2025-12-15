#!/usr/bin/env nu
# Comprehensive analysis of all dumps

def main [] {
    let project_root = ($env.PWD)
    let dumps_dir = ($project_root | path join "dumps")
    let output_dir = ($project_root | path join "analysis_output")
    
    print "╔══════════════════════════════════════════════════════════════╗"
    print "║              Moto Z Research - Full Analysis                 ║"
    print "╚══════════════════════════════════════════════════════════════╝"
    print ""
    
    # Create output directory
    mkdir $output_dir
    
    # Find all binary files
    let files = (ls ($dumps_dir | path join "*.{img,bin,elf,mbn}") | get name)
    
    if ($files | length) == 0 {
        print "⚠️  No dump files found in dumps/"
        return
    }
    
    print $"Found ($files | length) files to analyze"
    print ""
    
    for file in $files {
        print $"═══════════════════════════════════════════════════════════"
        print $"📁 Analyzing: ($file)"
        print $"═══════════════════════════════════════════════════════════"
        
        let basename = ($file | path basename)
        
        # File info
        print "📊 File Information:"
        ^file $file
        
        # Extract strings
        print ""
        print "📝 Extracting strings..."
        let strings_file = ($output_dir | path join $"($basename).strings")
        ^strings -n 8 $file | save -f $strings_file
        
        # Count interesting patterns
        let unlock_count = (open $strings_file | lines | where {|l| $l =~ "(?i)unlock"} | length)
        let verify_count = (open $strings_file | lines | where {|l| $l =~ "(?i)verify"} | length)
        let cert_count = (open $strings_file | lines | where {|l| $l =~ "(?i)cert"} | length)
        
        print $"   Found: ($unlock_count) 'unlock', ($verify_count) 'verify', ($cert_count) 'cert' references"
        
        # Check for known patterns
        print ""
        print "🔍 Checking for known patterns..."
        
        # Binwalk analysis
        print ""
        print "🔧 Binwalk analysis:"
        ^binwalk $file | head -20
        
        print ""
    }
    
    print "═══════════════════════════════════════════════════════════"
    print "✅ Analysis complete! Results in analysis_output/"
    print "═══════════════════════════════════════════════════════════"
}

main
