# Forum Post Draft - Motorola Developer Community

**Forum URL**: https://forums.lenovo.com/t5/MOTOROLA-Android-Developer-Community/bd-p/Android_developer
**Reference**: Case ID 251216-000447

---

## Post Title

**Bootloader Unlock Portal Rejects Eligible Retail Moto Z4 (CID 0x0032) - Portal Bug?**

---

## Post Body

Hello Motorola Developer Community,

I'm experiencing an issue with the bootloader unlock portal that appears to be a server-side problem rather than a device eligibility issue. I've done extensive technical verification and would appreciate clarification on why this is happening.

### Device Information

| Property | Value |
|----------|-------|
| **Model** | XT1980-3 |
| **Codename** | foles |
| **Build Variant** | foles_retail |
| **Carrier ID** | retus (Retail US) |
| **Current Build** | QPFS30.130-15-11-23 |
| **Android Version** | 10 |
| **Baseband** | M6150_11.95.01.07R FOLES_USARETUS_CUST |

### Bootloader Information (from fastboot)

```
(bootloader) version: 0.5
(bootloader) slot-count: 2
(bootloader) max-download-size: 536870912
(bootloader) serialno: ZY22726N55
(bootloader) version-bootloader: MBM-3.0-foles_retail-7077649e4b3-211025
(bootloader) cid: 0x0032
(bootloader) securestate: oem_locked
(bootloader) iswarrantyvoid: no
(bootloader) unlocked: no
(bootloader) isstorageflashall: no
```

### The Problem

When I submit my unlock data to the official portal (motorola-global-portal.custhelp.com), I receive the error:

> **"Your device does not qualify for bootloader unlocking."**

### Why This Appears to Be a Portal Error

1. **CID 0x0032 is on the unlockable list** - This CID is documented as eligible for bootloader unlocking in Motorola's own resources.

2. **Device is retail, not carrier-locked** - Build variant is `foles_retail` and carrier is `retus` (Retail US). This is NOT a Verizon or carrier-branded device.

3. **OEM Unlocking is enabled** - The toggle is on in Developer Options, and the device doesn't show "contact your carrier" messaging.

4. **No FRP lock** - Device shows `frp: no protection`

5. **Device is not warranty voided** - Shows `iswarrantyvoid: no`

6. **Unlock data format is correct** - I've verified the string has no extra spaces, line breaks, or formatting issues.

### Troubleshooting Steps Completed

- ✅ Verified OEM unlock toggle is enabled
- ✅ Confirmed device is retail (not carrier-branded)
- ✅ Checked CID against Motorola's eligible device list
- ✅ Tried multiple browsers (Chrome, Firefox, Edge)
- ✅ Tried incognito/private browsing mode
- ✅ Tried different Motorola/Google accounts
- ✅ Verified unlock data string formatting
- ✅ Waited 72+ hours after enabling OEM unlock
- ✅ Factory reset and re-enabled OEM unlock
- ✅ Tried regional portal variants (US, UK)

### Technical Analysis

I performed additional diagnostics via fastboot and found:

- `unlock_ability: 1` - Device reports it CAN be unlocked
- `securestate: oem_locked` - Currently locked (expected)
- `frp: no protection` - No Factory Reset Protection active
- CID `0x0032` matches the retail unlockable category

The device itself confirms it should be unlockable. The rejection appears to be happening at the portal/server level, not based on device characteristics.

### My Questions

1. **Is there a known issue with the unlock portal for foles_retail devices?**

2. **Why would a retail device with CID 0x0032 be rejected when this CID is documented as unlockable?**

3. **Can the developer team manually verify my device's eligibility and provide an unlock key?**

4. **Is there a database or whitelist issue that could explain this mismatch?**

### Context

I'm a developer looking to use this device for Android development and testing. The official bootloader unlock process is exactly the right approach - I'm not looking for workarounds, just trying to use the documented feature that should work for this device.

This device has been in my family since purchase and is now being repurposed for development work. I understand bootloader unlocking voids warranty, which is acceptable for my use case.

### Request

Could the Motorola Developer Community team please:

1. Verify the device eligibility based on the technical details provided
2. Explain why the portal is rejecting an eligible device
3. If possible, manually generate an unlock key or resolve whatever is blocking the portal

I'm happy to provide any additional technical information needed. Thank you for your time and assistance.

---

**Case Reference**: 251216-000447  
**Device Serial**: ZY22726N55

---
