# Documentation Index for Cursor

This file lists external documentation sources that should be indexed for AI assistance.

## 🔬 Reverse Engineering Resources

### Ghidra

- **Official Docs**: https://ghidra-sre.org/
- **Ghidra Scripting**: https://ghidra.re/ghidra_docs/api/
- **Python (Jython) API**: https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/package-summary.html

### Radare2

- **Official Book**: https://book.rada.re/
- **r2pipe Python**: https://github.com/radareorg/radare2-r2pipe
- **Command Reference**: https://r2wiki.readthedocs.io/

### Frida

- **JavaScript API**: https://frida.re/docs/javascript-api/
- **Android Examples**: https://frida.re/docs/android/

## 📱 Android & Bootloader

### Android Bootloader

- **AOSP Boot Image**: https://source.android.com/docs/core/architecture/bootloader
- **ABL (Android Bootloader)**: https://source.android.com/docs/core/architecture/bootloader/partitions
- **Fastboot Protocol**: https://android.googlesource.com/platform/system/core/+/refs/heads/master/fastboot/

### Qualcomm EDL

- **bkerler/edl**: https://github.com/bkerler/edl (Primary EDL tool)
- **Qualcomm Firehose**: https://alephsecurity.com/2018/01/22/qualcomm-edl-1/
- **EDL Exploitation**: https://alephsecurity.com/2018/01/22/qualcomm-edl-2/

### Motorola Specific

- **Motorola Developer**: https://developer.motorola.com/
- **Bootloader Unlock Portal**: https://motorola-global-portal.custhelp.com/app/standalone/bootloader/unlock-your-device-a
- **Moto Mods Developer**: https://developer.motorola.com/build/moto-mods-development-kit/ (archived)

## 🔧 Moto Mods / Greybus

### Greybus Protocol

- **Linux Greybus**: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/greybus
- **Greybus Spec**: https://github.com/projectara/greybus-spec
- **UniPro**: https://www.mipi.org/specifications/unipro

### Project Ara (Historical)

- **Ara Module Developer Kit**: https://web.archive.org/web/20160304000000*/developer.projectara.com
- **Ara Hardware Guide**: https://web.archive.org/web/20160311234711/http://www.projectara.com/mdk/

## 🔐 Security Research

### ARM TrustZone

- **ARM TrustZone**: https://developer.arm.com/ip-products/security-ip/trustzone
- **QSEE (Qualcomm)**: https://bits-please.blogspot.com/2016/04/exploring-qualcomms-trustzone.html
- **TZ Exploitation**: https://www.blackhat.com/docs/us-15/materials/us-15-Shen-Attacking-Your-Trusted-Core-Exploiting-Trustzone-On-Android.pdf

### Mobile Security

- **Android Security**: https://source.android.com/docs/security
- **Verified Boot**: https://source.android.com/docs/security/features/verifiedboot
- **dm-verity**: https://source.android.com/docs/security/features/verifiedboot/dm-verity

## 🐍 Python RE Libraries

### Capstone

- **Docs**: https://www.capstone-engine.org/lang_python.html
- **Tutorial**: https://www.capstone-engine.org/tutorial.html

### Unicorn

- **Docs**: https://www.unicorn-engine.org/docs/
- **Python Bindings**: https://github.com/unicorn-engine/unicorn/wiki/Tutorial-for-Python

### Pwntools

- **Docs**: https://docs.pwntools.com/en/stable/
- **Tutorials**: https://github.com/Gallopsled/pwntools-tutorial

## 📚 NixOS / Nix

### Nix Flakes

- **Wiki**: https://nixos.wiki/wiki/Flakes
- **Reference**: https://nixos.org/manual/nix/stable/command-ref/new-cli/nix3-flake.html

### NixOS Modules

- **Options Search**: https://search.nixos.org/options
- **Package Search**: https://search.nixos.org/packages

## 🌐 Community Resources

### XDA Developers

- **Moto Z4 Forum**: https://xdaforums.com/c/motorola-moto-z4.8958/
- **Moto Z Forums**: https://xdaforums.com/f/motorola-moto-z.5503/
- **Bootloader Unlock Threads**: Search "bootloader unlock" in device forums

### GitHub Repositories

- **bkerler/edl**: https://github.com/bkerler/edl - Qualcomm EDL tool
- **nicene-ubuntu/abl**: https://github.com/nicene-ubuntu/abl - ABL analysis
- **AnyKernel3**: https://github.com/osm0sis/AnyKernel3 - Kernel flashing

### Discord/IRC

- **Mobile Security Discord**: Various servers dedicated to mobile RE
- **XDA Developers Discord**: https://discord.gg/xda

---

## Usage Notes

To add these to Cursor's documentation index:
1. Open Cursor Settings
2. Navigate to AI → Documentation
3. Add URLs from this list as needed

Priority URLs for this project:
1. Ghidra API docs
2. bkerler/edl README
3. Qualcomm EDL articles (Aleph Security)
4. Linux Greybus docs
