# Deep Technical Analysis: Attacking Motorola's Unlock System

**Classification**: Advanced Reverse Engineering  
**Skill Level Required**: Expert  
**Legal Status**: Gray area - you own the device, but ToS violations possible

---

## Executive Summary

This document analyzes what would be required to either:
- **A**: Access/replicate Motorola's server-side key generation
- **B**: Brute-force the unlock key
- **C**: Bypass the verification entirely

**TL;DR**: Cryptographically secure, but not impossible with significant effort.

---

## Part 1: Understanding the Unlock Data Format

### The `fastboot oem get_unlock_data` Output

```
(bootloader) 3A25511600380271#5A593232373236
(bootloader) 4E3535006D6F746F207A340000#4D38
(bootloader) AEA4AAF9508DE3F053885F670949C92
(bootloader) 7183F#3013659300000000000000000
(bootloader) 0000000
```

### Decoded Structure

The unlock data contains **device-specific identifiers** that Motorola uses to:
1. Verify device eligibility
2. Generate a device-unique unlock key

#### Field Analysis

| Offset | Data | Decoded | Meaning |
|--------|------|---------|---------|
| 0-16 | `3A25511600380271` | Hex bytes | **HWID** (Hardware ID) |
| 17 | `#` | Delimiter | Field separator |
| 18-33 | `5A5932323732364E3535` | `ZY22726N55` (ASCII) | **Serial Number** |
| 34-49 | `006D6F746F207A3400` | `moto z4` (ASCII) | **Device Name** |
| 50 | `#` | Delimiter | Field separator |
| 51-82 | `4D38AEA4AAF9...` | Hex bytes | **Secure Hash** (likely SHA-256 based) |
| 83 | `#` | Delimiter | Field separator |
| 84-95 | `301365930000...` | Unknown | **Device-specific data** (fuses/config) |

### What the Server Does

```
Client sends: HWID + Serial + DeviceName + SecureHash + DeviceData

Server verifies:
1. HWID matches known device type (foles)
2. Serial is in database (not blocklisted)
3. CID is on allowed list
4. SecureHash validates device integrity
5. Device hasn't been previously unlocked

If all pass:
  Generate RSA signature over device data
  Return as unlock key
```

---

## Part 2: The Cryptographic Challenge

### Motorola's Signing Infrastructure

From our ABL analysis, we found:

```
Certificate Chain:
├── Motorola Root CA 708
│   ├── Algorithm: RSA-2048 or RSA-4096
│   └── Motorola Attestation CA 708-10
│       └── Device Certificate (708-1-14)
```

### Key Generation Theory

The unlock key is likely:

```
UnlockKey = RSA_Sign(PrivateKey, Hash(HWID || Serial || CID || Nonce))
```

Where:
- `PrivateKey` = Motorola's server-side private key (NEVER leaves their HSM)
- `Hash` = SHA-256 or similar
- `Nonce` = Time-based or random component (prevents replay)

### Why Direct Cracking is Infeasible

| Attack | Complexity | Time Required |
|--------|------------|---------------|
| Factor RSA-2048 | 2^112 operations | ~10^25 years |
| Factor RSA-4096 | 2^156 operations | Heat death of universe |
| SHA-256 collision | 2^128 operations | ~10^25 years |
| Brute-force keyspace | Depends on key length | See below |

---

## Part 3: Brute Force Analysis

### The Unlock Key Format

From observed Motorola unlock keys, they appear to be:

```
Format: XXXX-XXXX-XXXX-XXXX-XXXX (20 chars + 4 dashes)
-or-
Format: 20-24 character alphanumeric string
```

### Keyspace Calculation

If the key is:
- **20 alphanumeric characters** (A-Z, 0-9 = 36 options)
- Keyspace = 36^20 = **1.33 × 10^31 possibilities**

| Attempts/sec | Time to Exhaust |
|--------------|-----------------|
| 1,000 | 4.2 × 10^20 years |
| 1,000,000 | 4.2 × 10^17 years |
| 1,000,000,000 | 4.2 × 10^14 years |

**Verdict**: Pure brute force is **computationally infeasible**.

### BUT: What If the Keyspace is Reduced?

Historical vulnerabilities:

1. **Weak RNG** - If Motorola uses predictable random generation
2. **Time-based seeds** - Key based on timestamp
3. **Device-based derivation** - Key derived only from known device data
4. **Limited character set** - Fewer than 36 characters

#### Potential Research Vectors

```python
# If we can find a pattern...
# Example: Key derived from HWID + timestamp
import hashlib
import time

def theoretical_key_derivation(hwid, serial, timestamp):
    """
    THEORETICAL - Not real Motorola algorithm
    Shows what we'd look for in reverse engineering
    """
    data = f"{hwid}{serial}{timestamp}".encode()
    hash_val = hashlib.sha256(data).hexdigest()
    # Take first 20 chars, convert to Base36
    key = base36_encode(int(hash_val[:16], 16))[:20]
    return key
```

---

## Part 4: Attack Vectors

### Vector A: Server-Side Attack

**Goal**: Access Motorola's key generation API directly

#### Subvector A1: API Reverse Engineering

The unlock portal makes HTTP requests. Analyze:

```bash
# Capture portal traffic
mitmproxy --mode transparent

# Or browser developer tools
# Network tab → Look for API calls when submitting unlock data
```

**What to look for**:
- API endpoint URLs
- Authentication tokens
- Request/response format
- Rate limiting behavior
- Error messages that reveal information

#### Subvector A2: Server Vulnerability

Search for:
- SQL injection in unlock data field
- Authentication bypass
- Session hijacking
- IDOR (Insecure Direct Object Reference)

**Reality check**: Motorola likely uses enterprise-grade security. Low probability.

#### Subvector A3: Insider Access

- Leaked API credentials
- Former employee dumps
- Service center tools

**Search targets**:
- GitHub for leaked Motorola tools
- Dark web markets
- XDA archives
- Pastebin dumps

### Vector B: Key Derivation Analysis

**Goal**: Determine how keys are generated from device data

#### Step 1: Collect Multiple Unlock Data Samples

Gather unlock data from:
- Multiple Moto Z4 devices
- Different models (Z2, Z3, G series, etc.)
- Devices that WERE successfully unlocked

```python
# Build a dataset
samples = [
    {"model": "foles", "hwid": "3A25511600380271", "serial": "ZY22726N55", "key": "????"},
    {"model": "foles", "hwid": "...", "serial": "...", "key": "????"},
    # Need devices with KNOWN unlock keys
]
```

#### Step 2: Differential Analysis

Compare samples to find patterns:
- Which bytes change between devices?
- Which stay constant for same model?
- Is there correlation between HWID and key?

#### Step 3: Known-Plaintext Attack

If we have:
- Multiple (device_data, unlock_key) pairs
- We might find the derivation function

```python
# Pseudocode for analysis
for sample in samples:
    # Try various hash combinations
    for hash_func in [sha256, sha1, md5, hmac_sha256]:
        for combination in permutations(sample['hwid'], sample['serial'], sample['cid']):
            candidate = hash_func(combination)
            if matches_key_format(candidate, sample['key']):
                print(f"FOUND DERIVATION: {hash_func} on {combination}")
```

### Vector C: Bypass Verification Entirely

**Goal**: Make ABL accept any key or no key

#### C1: ABL Binary Patching (Covered in VECTOR_A doc)

Summary: Blocked by secure boot signature verification

#### C2: TrustZone Exploit

The unlock verification runs in TrustZone (secure world):

```
Normal World (Android)     Secure World (TrustZone)
      │                           │
      ▼                           ▼
   fastboot  ───SCM Call───►  tz_unlock_verify()
      │                           │
      │                           ▼
      │                    Verify RSA signature
      │                           │
      ◄────Result────────────────┘
```

**Required**: Find a TrustZone vulnerability for SM6150

**Research targets**:
- CVE database for Qualcomm TZ
- Aleph Security research
- Check Point research
- Google Project Zero

#### C3: Downgrade to Vulnerable Firmware

**Goal**: Flash firmware with known TZ/bootloader vulnerability

**Blocked by**: Anti-rollback fuses (covered in VECTOR_B doc)

#### C4: Hardware Glitching

Physical attack on the verification process:

```
During signature check:
  └── Inject voltage/clock glitch
      └── Cause instruction skip
          └── Verification returns "success"
```

**Required equipment**:
- ChipWhisperer or similar glitching platform
- Oscilloscope
- Fine soldering skills
- Device you're willing to destroy

---

## Part 5: Practical Research Plan

### Phase 1: Information Gathering (Low Risk)

1. **Collect unlock data samples**
   - Post on XDA asking for device data (no keys needed yet)
   - Different models, carriers, regions

2. **Analyze portal traffic**
   ```bash
   # Set up mitmproxy
   mitmproxy -p 8080
   # Configure browser to use proxy
   # Submit unlock data, capture requests
   ```

3. **Search for leaks**
   - GitHub: `motorola unlock key generator`
   - GitHub: `motorola bootloader tool`
   - XDA: Old threads from 2012-2018 when Moto was more vulnerable

### Phase 2: Reverse Engineering (Medium Risk)

1. **Disassemble ABL**
   ```bash
   # Load in Ghidra
   ghidra
   # File → Import → abl_a.img
   # Analyze → Auto Analysis
   # Search for strings: "unlock", "verify", "signature"
   ```

2. **Find the verification function**
   - Look for SCM call setup
   - Trace back from error strings
   - Identify signature verification routine

3. **Document the protocol**
   - What data goes to TZ?
   - What response comes back?
   - Can we fake the response?

### Phase 3: Exploitation Attempts (High Risk)

1. **Test for API vulnerabilities**
   - Rate limiting bypass
   - Input validation issues
   - Authentication flaws

2. **Search for TZ exploits**
   - SM6150 specific CVEs
   - Generic Qualcomm TZ issues
   - Check if patched in your firmware version

3. **Hardware attacks (last resort)**
   - Requires specialized equipment
   - High brick risk
   - May destroy device

---

## Part 6: Carrier-Locked Device Considerations

### Why Carrier Locks Are Different

| Aspect | Retail Device | Carrier Device |
|--------|---------------|----------------|
| CID | Unlockable (0x0032) | Locked (varies) |
| Database | Should work | Blocklisted |
| Carrier agreement | N/A | Contractual |

### Attacking Carrier Locks

The carrier lock is enforced by:
1. **CID in device** - Burned into fuses or secure storage
2. **Server-side blocklist** - IMEI/serial in carrier database
3. **Firmware variant** - Different build without unlock code

#### Potential Approaches

1. **CID Modification** (Very difficult)
   - CID may be in QFPROM (one-time programmable)
   - If in RPMB, requires TrustZone exploit

2. **IMEI Change** (Illegal in many countries)
   - ⚠️ **DO NOT DO THIS** - Serious legal consequences
   - IMEI modification is federal crime in US

3. **Firmware Conversion** (Complex)
   - Flash retail firmware on carrier device
   - Requires matching hardware
   - May fail due to carrier-specific partitions

4. **Wait for Contract Fulfillment**
   - Some carriers unlock after contract period
   - Verizon: 60 days active service
   - AT&T: Varies by device

---

## Part 7: Tools and Resources

### Reverse Engineering Tools

| Tool | Purpose | Install |
|------|---------|---------|
| **Ghidra** | Disassembler/Decompiler | `nix-env -iA nixpkgs.ghidra` |
| **IDA Pro** | Industry standard RE | Commercial |
| **Binary Ninja** | Alternative RE tool | Commercial |
| **radare2** | CLI RE framework | `nix-env -iA nixpkgs.radare2` |
| **Frida** | Dynamic instrumentation | `pip install frida-tools` |
| **mitmproxy** | HTTP/S interception | `nix-env -iA nixpkgs.mitmproxy` |

### Qualcomm-Specific Tools

| Tool | Purpose |
|------|---------|
| **edl** | EDL mode communication |
| **emmcdl** | eMMC download mode |
| **QFIL** | Qualcomm Flash Image Loader |
| **QPST** | Qualcomm Product Support Tools |

### Research Resources

- [Aleph Security](https://alephsecurity.com/) - TrustZone research
- [Check Point Research](https://research.checkpoint.com/) - Mobile security
- [Quarkslab](https://blog.quarkslab.com/) - Qualcomm research
- [XDA Developers](https://xdaforums.com/) - Community knowledge
- [Qualcomm Security Bulletins](https://www.qualcomm.com/company/product-security/bulletins)

---

## Part 8: Realistic Assessment

### Probability of Success

| Approach | Effort | Success Chance | Risk |
|----------|--------|----------------|------|
| Forum/Support | Low | 30% | None |
| Paid Service | Low | 50% | Financial |
| API Analysis | Medium | 5% | ToS violation |
| Key Derivation | High | 2% | Wasted time |
| ABL Patching | Very High | 1% | Brick |
| TZ Exploit | Very High | 0.5% | Brick |
| Hardware Glitch | Extreme | 0.1% | Device destruction |

### Recommendation

**For your Moto Z4 specifically**:

1. **Wait for forum response** (48 hours)
2. **Try paid service** if forum fails (~$40)
3. **Consider the device usable as-is** for emulation
4. **Save deep RE for learning**, not as primary unlock strategy

**For broader research**:
- The techniques here are valuable for security research
- Could be published/shared to help community
- May lead to discoveries that benefit many devices
- Educational value regardless of immediate success

---

## Appendix: Code Snippets for Research

### Unlock Data Parser

```python
#!/usr/bin/env python3
"""Parse Motorola unlock data for analysis"""

def parse_unlock_data(raw_data: str) -> dict:
    """
    Parse the fastboot oem get_unlock_data output
    """
    # Remove (bootloader) prefixes and join
    clean = raw_data.replace("(bootloader)", "").replace("\n", "").replace(" ", "")
    
    # Split by delimiter
    parts = clean.split("#")
    
    return {
        "hwid": parts[0] if len(parts) > 0 else None,
        "serial_hex": parts[1][:20] if len(parts) > 1 else None,
        "serial_ascii": bytes.fromhex(parts[1][:20]).decode('ascii', errors='ignore') if len(parts) > 1 else None,
        "secure_hash": parts[2] if len(parts) > 2 else None,
        "device_data": parts[3] if len(parts) > 3 else None,
        "raw": clean
    }

# Example usage
raw = """3A25511600380271#5A5932323732364E3535006D6F746F207A340000#4D38AEA4AAF9508DE3F053885F670949C927183F#30136593000000000000000000000000"""

parsed = parse_unlock_data(raw)
print(f"HWID: {parsed['hwid']}")
print(f"Serial: {parsed['serial_ascii']}")
print(f"Hash: {parsed['secure_hash']}")
```

### Portal Traffic Capture Script

```python
#!/usr/bin/env python3
"""
Capture and analyze Motorola unlock portal traffic
Run mitmproxy first: mitmproxy -p 8080
"""

from mitmproxy import http

def request(flow: http.HTTPFlow) -> None:
    if "motorola" in flow.request.host:
        print(f"[REQUEST] {flow.request.method} {flow.request.url}")
        print(f"[HEADERS] {dict(flow.request.headers)}")
        if flow.request.content:
            print(f"[BODY] {flow.request.content.decode()}")

def response(flow: http.HTTPFlow) -> None:
    if "motorola" in flow.request.host:
        print(f"[RESPONSE] {flow.response.status_code}")
        print(f"[BODY] {flow.response.content.decode()[:500]}")
```

---

*Document created: 2025-12-15*
*Classification: Research Notes*
*Disclaimer: For educational purposes. Respect applicable laws.*
