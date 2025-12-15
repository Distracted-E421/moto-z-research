# Moto Z4 Emulation Performance Guide

**Device**: Motorola Moto Z4 + Moto Gamepad Mod  
**SoC**: Qualcomm Snapdragon 675 (SM6150)  
**Status**: Works great even WITHOUT bootloader unlock!

---

## 📊 Hardware Specifications

### Snapdragon 675 Performance Profile

| Component | Specification | Gaming Impact |
|-----------|---------------|---------------|
| **CPU** | 2x Kryo 460 Gold @ 2.0GHz + 6x Kryo 460 Silver @ 1.7GHz | Strong single-thread |
| **GPU** | Adreno 612 | Mid-range, OpenGL ES 3.2 |
| **RAM** | 4GB LPDDR4X | Adequate for most emulators |
| **Storage** | 128GB UFS 2.1 | Fast ROM loading |
| **Display** | 6.4" 1080x2340 OLED | Excellent for gaming |

### Moto Gamepad Mod

- D-Pad + Dual Analog Sticks
- A/B/X/Y Face Buttons
- L/R Shoulder Buttons + L3/R3
- 1035mAh Additional Battery
- USB-C Passthrough Charging

---

## 🎮 Emulator Compatibility Matrix

### Tier 1: Perfect Performance (60 FPS stable)

| System | Emulator | Performance | Notes |
|--------|----------|-------------|-------|
| **NES** | RetroArch/Mesen | ⭐⭐⭐⭐⭐ | All games perfect |
| **SNES** | RetroArch/bsnes | ⭐⭐⭐⭐⭐ | All games perfect |
| **Genesis/MD** | RetroArch/Genesis Plus GX | ⭐⭐⭐⭐⭐ | All games perfect |
| **Game Boy/Color** | RetroArch/Gambatte | ⭐⭐⭐⭐⭐ | All games perfect |
| **GBA** | mGBA / MyBoy | ⭐⭐⭐⭐⭐ | All games perfect |
| **Master System** | RetroArch/Genesis Plus GX | ⭐⭐⭐⭐⭐ | All games perfect |
| **TurboGrafx-16** | RetroArch/Beetle PCE | ⭐⭐⭐⭐⭐ | All games perfect |

### Tier 2: Excellent Performance (Most games 60 FPS)

| System | Emulator | Performance | Notes |
|--------|----------|-------------|-------|
| **PlayStation 1** | ePSXe / DuckStation | ⭐⭐⭐⭐⭐ | All games perfect |
| **Nintendo DS** | DraStic | ⭐⭐⭐⭐⭐ | Excellent, $4.99 |
| **N64** | Mupen64Plus FZ | ⭐⭐⭐⭐ | Most games full speed |
| **PSP** | PPSSPP | ⭐⭐⭐⭐ | Most games at 2x resolution |
| **Arcade** | MAME4droid/FBN | ⭐⭐⭐⭐ | Pre-2000 games excellent |
| **Neo Geo** | NEO.emu | ⭐⭐⭐⭐⭐ | All games perfect |

### Tier 3: Good Performance (Some games need tweaking)

| System | Emulator | Performance | Notes |
|--------|----------|-------------|-------|
| **Dreamcast** | Redream/Flycast | ⭐⭐⭐⭐ | Most 3D games playable |
| **Saturn** | Yaba Sanshiro 2 | ⭐⭐⭐ | 2D games good, 3D variable |
| **3DS** | Citra MMJ | ⭐⭐⭐ | Select games, slow |

### Tier 4: Limited Performance (Light games only)

| System | Emulator | Performance | Notes |
|--------|----------|-------------|-------|
| **GameCube** | Dolphin | ⭐⭐ | 2D/simple 3D games |
| **Wii** | Dolphin | ⭐⭐ | 2D/simple 3D games |
| **PS2** | AetherSX2 | ⭐⭐ | 2D games, some 3D |

---

## 📱 Detailed System Guides

### PlayStation 1

**Best Emulator**: DuckStation (free) or ePSXe ($3.75)

**Settings for Moto Z4**:
```
Internal Resolution: 2x Native (640x480)
Texture Filtering: Bilinear
PGXP Geometry Correction: ON
CPU Overclock: 2x (for demanding games)
Renderer: OpenGL ES (Vulkan may have issues)
```

**Recommended Games**:
- Final Fantasy VII-IX ✅
- Crash Bandicoot series ✅
- Spyro series ✅
- Tony Hawk's Pro Skater 2 ✅
- Metal Gear Solid ✅
- All 2D RPGs ✅

### Nintendo 64

**Best Emulator**: Mupen64Plus FZ (free with Pro version)

**Settings for Moto Z4**:
```
Video Plugin: GLideN64 (most compatible)
Resolution: 640x480 or 960x720
Emulation Speed: Frame limiter ON
Audio: sles (low latency)
```

**Performance by Game**:
| Game | Performance |
|------|-------------|
| Super Mario 64 | ✅ Full speed |
| Ocarina of Time | ✅ Full speed |
| Majora's Mask | ✅ Full speed |
| Mario Kart 64 | ✅ Full speed |
| GoldenEye 007 | ⚠️ Minor slowdowns |
| Perfect Dark | ⚠️ Some slowdowns |
| Conker's Bad Fur Day | ⚠️ Some slowdowns |

### PlayStation Portable (PSP)

**Best Emulator**: PPSSPP (free)

**Settings for Moto Z4**:
```
Backend: Vulkan (preferred) or OpenGL
Rendering Resolution: 2x PSP (960x544)
Hardware Transform: ON
Software Skinning: OFF
Vertex Cache: ON
Fast Memory: ON
Frame Skipping: OFF (or 1 if needed)
Audio Latency: Low
```

**Performance by Game Category**:
| Category | Performance |
|----------|-------------|
| 2D Games | ✅ 2x-3x resolution |
| Light 3D | ✅ 2x resolution |
| Heavy 3D (God of War) | ⚠️ 1x-2x resolution |
| Racing (Ridge Racer) | ✅ 2x resolution |

### Dreamcast

**Best Emulator**: Redream (free tier) or Flycast

**Settings for Moto Z4**:
```
Resolution: 1280x960 (2x)
Cable Type: VGA
Renderer: Per-triangle sorting
Synchronous: ON
Audio Buffer: Medium
```

**Performance by Game**:
| Game | Performance |
|------|-------------|
| Sonic Adventure | ✅ Full speed |
| Soul Calibur | ✅ Full speed |
| Marvel vs Capcom 2 | ✅ Full speed |
| Crazy Taxi | ✅ Full speed |
| Shenmue | ⚠️ Minor slowdowns |
| Jet Set Radio | ✅ Full speed |

### GameCube/Wii (Dolphin)

**Best Emulator**: Dolphin (official or MMJ)

**Reality Check**: Snapdragon 675 is **NOT** a GameCube/Wii powerhouse. Set expectations accordingly.

**Settings for Moto Z4**:
```
Backend: OpenGL ES
Internal Resolution: 1x (480p)
Synchronize GPU Thread: ON
Skip EFB Access from CPU: ON
Store EFB Copies to Texture: ON
Ignore Format Changes: ON
Accuracy: Fast
```

**Playable Games** (at 1x native, some slowdowns):
| Game | Status |
|------|--------|
| Super Mario Sunshine | ⚠️ 20-30 FPS outside |
| Wind Waker | ⚠️ 20-30 FPS |
| Paper Mario TTYD | ✅ Mostly full speed |
| Melee | ⚠️ 30-45 FPS |
| Animal Crossing | ✅ Playable |
| Wii Sports | ⚠️ 20-30 FPS |
| New Super Mario Bros Wii | ✅ Mostly playable |

**2D/Light Games** (better performance):
| Game | Status |
|------|--------|
| Mega Man Collection | ✅ Full speed |
| Kirby's Return to Dream Land | ⚠️ Mostly playable |
| Sonic Colors | ⚠️ 2D sections good |

---

## 🕹️ Controller Setup

### Moto Gamepad Mapping

The Moto Gamepad is automatically detected by most emulators with standard Android controller mapping:

| Gamepad Button | Android Key | Emulator Function |
|----------------|-------------|-------------------|
| D-Pad | DPAD_UP/DOWN/LEFT/RIGHT | D-Pad |
| Left Stick | AXIS_X, AXIS_Y | Analog stick |
| Right Stick | AXIS_Z, AXIS_RZ | Camera/C-stick |
| A/B/X/Y | BUTTON_A/B/X/Y | Face buttons |
| L1/R1 | BUTTON_L1/R1 | Shoulder buttons |
| L3/R3 | BUTTON_THUMBL/R | Stick clicks |

### Per-Emulator Controller Notes

**RetroArch**: Auto-configured, works perfectly

**PPSSPP**: May need manual mapping of L/R to correspond to PSP layout

**Dolphin**: Requires manual GameCube/Wii controller configuration

**Mupen64Plus**: N64 controller mapped automatically, C-buttons to right stick

---

## 📂 ROM Organization

### Recommended Structure

```
/sdcard/Roms/
├── Arcade/
├── Dreamcast/
├── GameBoy/
├── GameBoyAdvance/
├── GameBoyColor/
├── GameCube/
├── Genesis/
├── N64/
├── NDS/
├── NES/
├── PS1/
├── PSP/
├── SNES/
└── Wii/
```

### Storage Notes

- 128GB internal storage is generous
- PSP/PS2/GameCube games can be large (1-4GB each)
- Recommend keeping most-played ROMs locally
- Use microSD for backup storage

---

## ⚡ Performance Optimization Tips

### General Android Tips

1. **Enable Game Mode** (if available)
2. **Disable battery optimization** for emulators
3. **Use airplane mode + WiFi** to reduce background processes
4. **Close other apps** before intensive emulation
5. **Keep device cool** - thermal throttling affects performance

### Emulator-Specific Tips

**PPSSPP**:
- Enable "Ignore problems reported by games"
- Try Vulkan backend first
- Disable "Lazy texture caching" for some games

**Dolphin**:
- Don't enable "Compile Shaders Before Starting"
- Use OpenGL ES (Vulkan has issues on Adreno 612)
- Skip intro videos when possible

**RetroArch**:
- Use performance cores (GL driver)
- Enable threaded video
- Use frame limiter

---

## 🔥 Best Games for Moto Z4 + Gamepad

### "Perfect" Experience (60 FPS, no issues)

| Game | System | Why It's Great |
|------|--------|----------------|
| Super Mario World | SNES | Perfect with D-pad |
| Chrono Trigger | SNES | RPG masterpiece |
| Final Fantasy VI | SNES | Best version |
| Pokemon FireRed | GBA | Full experience |
| Castlevania: SOTN | PS1 | Metroidvania |
| Crash Bandicoot | PS1 | Classic platformer |
| God of War: Chains of Olympus | PSP | Impressive portable |
| Patapon | PSP | Rhythm game |
| Metal Gear Solid | PS1 | Stealth classic |
| Sonic Adventure 2 | Dreamcast | Fast and fun |

### "Near Perfect" Experience (Minor issues)

| Game | System | Notes |
|------|--------|-------|
| The Legend of Zelda: OOT | N64 | Perfect with FZ |
| Mario 64 | N64 | Perfect |
| Monster Hunter Freedom Unite | PSP | Great on Gamepad |
| Crisis Core: Final Fantasy VII | PSP | 2x resolution works |
| Marvel vs Capcom 2 | Dreamcast | Fighting on the go |

---

## 📝 Conclusion

The Moto Z4 + Gamepad Mod is an **excellent** handheld emulation device for:

- ✅ 8-bit systems (NES, SMS, GB)
- ✅ 16-bit systems (SNES, Genesis, TG-16)
- ✅ 32-bit systems (PS1, Saturn 2D)
- ✅ Handhelds (GBA, DS, PSP)
- ✅ N64 (most games)
- ⚠️ Dreamcast (most games)
- ⚠️ GameCube/Wii (limited selection)

**Even without bootloader unlock**, you have access to a massive library through Play Store emulators.

**With bootloader unlock**, you could potentially:
- Use custom kernels for better performance
- Install optimized ROMs
- Remove bloatware for more RAM
- Use AetherSX2 more effectively

---

*Guide created: 2025-12-15*
