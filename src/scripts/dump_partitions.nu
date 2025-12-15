#!/usr/bin/env nu
# Dump critical partitions from device in fastboot mode

def main [] {
    let project_root = ($env.PWD)
    let dumps_dir = ($project_root | path join "dumps")
    
    print "╔══════════════════════════════════════════════════════════════╗"
    print "║              Moto Z Research - Partition Dump                ║"
    print "╚══════════════════════════════════════════════════════════════╝"
    print ""
    
    # Check fastboot
    let devices = (^fastboot devices | str trim)
    if ($devices | str length) == 0 {
        print "❌ No device in fastboot mode!"
        print "   1. Connect device"
        print "   2. adb reboot bootloader"
        print "   3. Run this script again"
        return
    }
    
    print $"✅ Device detected: ($devices)"
    print ""
    
    # Create dumps directory with timestamp
    let timestamp = (date now | format date "%Y%m%d_%H%M%S")
    let dump_path = ($dumps_dir | path join $timestamp)
    mkdir $dump_path
    
    print $"📁 Saving to: ($dump_path)"
    print ""
    
    # Critical partitions to dump
    let partitions = [
        "abl_a"      # Android Bootloader (primary)
        "xbl_a"      # eXtensible Bootloader
        "tz_a"       # TrustZone
        "devinfo"    # Device info (unlock status)
        "frp"        # Factory Reset Protection
        "persistent" # Persistent data
    ]
    
    for part in $partitions {
        print $"📦 Dumping: ($part)"
        
        let outfile = ($dump_path | path join $"($part).img")
        
        # Use fastboot to dump
        try {
            ^fastboot getvar $"partition-size:($part)" 2>&1 | print
            # Note: Standard fastboot can't dump, need EDL or special method
            print $"   ⚠️  Standard fastboot dump not supported"
            print $"   📝 Need to use EDL mode for actual dump"
        } catch {
            print $"   ❌ Failed to get partition info"
        }
    }
    
    print ""
    print "═══════════════════════════════════════════════════════════"
    print "⚠️  Note: Standard fastboot cannot dump partitions!"
    print ""
    print "For actual dumps, use EDL mode:"
    print "  1. Boot to EDL: adb reboot edl"
    print "  2. Use edl tool: edl r abl_a abl_a.img"
    print ""
    print "Or extract from full OTA/factory image."
    print "═══════════════════════════════════════════════════════════"
}

main
