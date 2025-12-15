# Vector B: Firmware Downgrade Attack Analysis

**Risk Level**: MEDIUM-HIGH  
**Technical Difficulty**: Intermediate-Advanced  
**Probability of Success**: Low (5-15%)  
**Probability of Brick**: Medium (20-40%)

---

## Executive Summary

A firmware downgrade attack attempts to flash an older version of the bootloader/firmware that contains a known vulnerability. If successful, the vulnerability could then be exploited to unlock the bootloader.

**Verdict**: LIKELY BLOCKED by anti-rollback fuses, but worth investigating.

---

## Technical Background

### Anti-Rollback Protection (ARB)

Qualcomm devices implement **Anti-Rollback Protection** using eFuses:

```
QFPROM (Qualcomm Fuse Programmable Read-Only Memory)
├── ARB Version (blown fuses)
├── Secure Boot Keys
├── Debug Disable fuses
└── Other security fuses
```

**How it works:**
1. Each firmware has an ARB version number
2. When flashed, the ARB version is checked against fuses
3. If firmware ARB < fuse ARB → **REJECTED**
4. If firmware ARB ≥ fuse ARB → Allowed
5. On first boot, new ARB version may be blown into fuses

### Moto Z4 Firmware History

| Build | Date | Android | ARB | Known Issues |
|-------|------|---------|-----|--------------|
| PPFS29.55-36-10 | 2019-06 | 9.0 | Unknown | Launch firmware |
| QPFS30.XXX | 2019-XX | 10 | Unknown | Multiple builds |
| QPFS30.130-15-11-23 | 2021-10 | 10 | Unknown | **Current (your device)** |

---

## Checking Anti-Rollback Status

### Via Fastboot

```bash
# Get current ARB version (if exposed)
fastboot getvar anti-rollback
fastboot getvar arb-version
fastboot getvar rollback-index

# Note: Motorola may not expose these
```

### Via Dumped Firmware

Anti-rollback info may be embedded in:
- `xbl_a.img` - Primary bootloader
- `abl_a.img` - Android bootloader
- `tz_a.img` - TrustZone firmware

Look for version strings:
```bash
strings dumps/xbl_a.img | grep -i "rollback\|version\|arb"
strings dumps/abl_a.img | grep -i "rollback\|version\|arb"
```

---

## Firmware Sources

### Official Sources (Limited)

Motorola doesn't provide direct firmware downloads. Options:

1. **Motorola Rescue & Smart Assistant (MRSA)**
   - Official tool for recovery
   - Only offers latest firmware
   - May work for stock restore

2. **Lenovo/Motorola Support**
   - Contact for specific firmware requests
   - Rarely provides older versions

### Third-Party Firmware Mirrors

⚠️ **WARNING**: Verify SHA256 hashes of all downloaded firmware!

| Source | Reliability | Notes |
|--------|-------------|-------|
| firmware.center | Medium | Collection of stock firmwares |
| lolinet mirrors | Medium | European mirrors |
| XDA Forums | Variable | User-uploaded, verify hashes |
| Android File Host | Variable | Community uploads |

### Search Query for Firmware

```
"XT1980" OR "foles" firmware download
Moto Z4 stock ROM QPFS30 full firmware
Motorola foles_retail fastboot flash files
```

---

## Known Qualcomm/Motorola Vulnerabilities

### CVE Database Search Results

| CVE | Affected | Description | Exploitable? |
|-----|----------|-------------|--------------|
| CVE-2020-11292 | Various QC | QSEE trustlet memory corruption | Requires specific TA |
| CVE-2021-1905 | Various QC | Use-after-free in graphics | Not bootloader-related |
| CVE-2021-1906 | Various QC | GPU driver vulnerability | Not bootloader-related |
| CVE-2022-33213 | SDM/SM chipsets | Memory corruption in modem | Not bootloader-related |

**SM6150-Specific**: No public bootloader exploits found as of December 2024.

### Historical Motorola Exploits

| Device | Year | Method | Status |
|--------|------|--------|--------|
| Moto X (2013) | 2013 | Dan Rosenberg kexec exploit | Patched |
| Moto G | 2014 | Trusted boot bypass | Patched |
| Moto Z/Z2 | 2017-18 | Various EDL methods | Mostly patched |
| Moto G7/G8 | 2019-20 | Official unlock issues | Similar to Z4 |

---

## Downgrade Attack Procedure (Theoretical)

### Step 1: Identify Target Firmware

Find oldest available firmware for `foles` device:

```bash
# Search firmware databases
# Target: Pre-ARB-bump versions
# Look for: PPFS29.* (Android 9) or early QPFS30.*
```

### Step 2: Extract and Compare

```bash
# Extract target firmware
unzip firmware_old.zip

# Compare XBL/ABL versions
strings xbl_old.img | head -50
strings dumps/xbl_a.img | head -50

# Look for version indicators
```

### Step 3: Check ARB Compatibility

```bash
# In fastboot mode
fastboot flash xbl_a xbl_old.img 2>&1
# Watch for "anti-rollback" or "version" errors
```

### Step 4: If Allowed - Flash Complete Set

```bash
# Critical boot chain (must be consistent)
fastboot flash xbl_a xbl_old.img
fastboot flash xbl_config_a xbl_config_old.img
fastboot flash abl_a abl_old.img
fastboot flash tz_a tz_old.img
# ... other boot partitions
```

### Step 5: Exploit Vulnerability

If older firmware has known vuln:
- Research specific exploit
- Execute exploit code
- Achieve bootloader unlock

---

## EDL Downgrade (Alternative)

EDL mode might bypass some ARB checks:

```bash
# Enter EDL
adb reboot edl

# Flash older firmware via EDL
edl w xbl_a xbl_old.img --memory=UFS
edl w abl_a abl_old.img --memory=UFS

# Reboot
edl reset
```

**Risks:**
- May still fail ARB check on boot
- Could cause boot loop
- Potential permanent brick

---

## Anti-Rollback Bypass Attempts

### Theory 1: Fuse Read Protection

Some devices have bugs where:
- Fuse value can be misread
- Causing ARB check to pass incorrectly

**Status for SM6150**: Unknown

### Theory 2: Unsigned Loader

Using an unsigned or leaked signed loader might:
- Bypass ARB in download mode
- Allow older firmware flash

**Status**: Motorola loaders are all signed, no leaks known

### Theory 3: eFuse Reset

Physical attack to reset fuses:
- Requires specialized equipment
- Destructive to device
- Not practical

---

## Recovery Procedures

### If Downgrade Fails (Boot Loop)

1. **Enter EDL Mode**
   - Vol Down + Vol Up while plugging USB
   - OR use test points on PCB

2. **Flash Known Working Firmware**
   ```bash
   cd ~/homelab/devices/moto-z4-project/edl
   edl w xbl_a dumps/xbl_a.img --memory=UFS
   edl w abl_a dumps/abl_a.img --memory=UFS
   edl w tz_a dumps/tz_a.img --memory=UFS
   # ... all boot partitions
   edl reset
   ```

3. **Full Factory Flash (if available)**
   - Use MRSA tool
   - Or complete firmware package

### Prevention

Before attempting downgrade:
- [ ] Full EDL backup completed
- [ ] Verified EDL flashing works
- [ ] Have working firmware set
- [ ] Document current partition hashes

---

## Conclusion

Firmware downgrade attack is **unlikely to succeed** on Moto Z4 because:

1. **Anti-rollback protection** via QFPROM fuses
2. **No known vulnerabilities** in older foles firmware
3. **Signed bootloaders** prevent arbitrary flashing
4. **Motorola security patches** closed known exploits

### When Downgrade Might Work

- If you have a device with very old firmware (never updated)
- If anti-rollback wasn't implemented for certain versions
- If a new vulnerability is discovered

### Recommendation

1. First, check current ARB version via fastboot
2. Search for pre-ARB firmware for foles
3. Verify firmware authenticity before flashing
4. Have full EDL backup ready
5. Accept risk of brick before attempting

---

## Resources

### Firmware Search

- [firmware.center](https://firmware.center/) - Firmware mirror
- XDA Forums Moto Z4 section
- [GetDroidTips](https://www.getdroidtips.com/) - Firmware guides

### Security Research

- [Qualcomm Security Bulletins](https://www.qualcomm.com/company/product-security/bulletins)
- [Android Security Bulletins](https://source.android.com/security/bulletin)
- [Aleph Security](https://alephsecurity.com/) - Mobile security research

---

*Document generated: 2025-12-15*
*Status: Research compilation - downgrade unlikely to succeed*

