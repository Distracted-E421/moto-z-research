# Moto Z Ecosystem Deep Dive & Future Vision

**Project Goal**: Reverse engineer Moto Mods system, unlock carrier-locked devices, repurpose as servers/compute nodes  
**Vision**: Open-source the knowledge to enable community hardware development

---

## Part 1: Complete Moto Z Device Lineup

### Generation 1 (2016)

| Model | Codename | SoC | RAM | Storage | Carrier Variants |
|-------|----------|-----|-----|---------|------------------|
| **Moto Z** | griffin | SD 820 | 4GB | 32/64GB | Verizon (XT1650-01), Unlocked (XT1650-03) |
| **Moto Z Droid** | griffin | SD 820 | 4GB | 32GB | Verizon exclusive |
| **Moto Z Force** | griffin | SD 820 | 4GB | 32/64GB | Verizon (XT1650-02) |
| **Moto Z Force Droid** | griffin | SD 820 | 4GB | 32GB | Verizon exclusive |
| **Moto Z Play** | addison | SD 625 | 3GB | 32/64GB | Verizon, Unlocked |
| **Moto Z Play Droid** | addison | SD 625 | 3GB | 32GB | Verizon exclusive |

### Generation 2 (2017)

| Model | Codename | SoC | RAM | Storage | Carrier Variants |
|-------|----------|-----|-----|---------|------------------|
| **Moto Z2 Force** | nash | SD 835 | 4/6GB | 64/128GB | Verizon, AT&T, T-Mobile, Sprint, Unlocked |
| **Moto Z2 Play** | albus | SD 626 | 3/4GB | 32/64GB | Verizon, Unlocked, International |

### Generation 3 (2018)

| Model | Codename | SoC | RAM | Storage | Carrier Variants |
|-------|----------|-----|-----|---------|------------------|
| **Moto Z3** | messi | SD 835 | 4GB | 64GB | Verizon exclusive (5G Moto Mod capable) |
| **Moto Z3 Play** | beckham | SD 636 | 4GB | 32/64GB | Unlocked, International |

### Generation 4 (2019)

| Model | Codename | SoC | RAM | Storage | Carrier Variants |
|-------|----------|-----|-----|---------|------------------|
| **Moto Z4** | foles | SD 675 | 4GB | 128GB | Verizon, Unlocked (XT1980-3, XT1980-4) |

---

## Part 2: Moto Mods Technical Specifications

### The POGO Pin Interface

The Moto Z series uses a **16-pin POGO connector** on the back of the device.

#### Known Pin Configuration

| Pin | Function | Notes |
|-----|----------|-------|
| 1-2 | Power (VBAT) | Direct battery voltage (~3.7-4.2V) |
| 3-4 | Ground | Power return |
| 5-6 | USB 2.0 D+/D- | Data transfer |
| 7-8 | I2C (SDA/SCL) | Mod identification & control |
| 9-10 | UniPro/Greybus | High-speed data (potential) |
| 11-12 | GPIO/INT | Interrupt lines |
| 13-14 | Reserved/NFC? | Unknown function |
| 15-16 | Aux Power/Ground | Additional power rail |

**⚠️ NOTE**: This is partially reverse-engineered. Official pinout never publicly released.

### Power Delivery Specifications

| Parameter | Value | Notes |
|-----------|-------|-------|
| **Max Power Output** | ~15W (estimated) | For charging mods |
| **Max Power Input** | ~15W (estimated) | From battery mods |
| **Voltage (VBAT)** | 3.7V-4.35V | Direct battery |
| **Voltage (Regulated)** | 3.3V, 1.8V | For logic |
| **Current Limit** | ~3-4A (estimated) | Total mod power |

### Data Interface: Greybus Protocol

Moto Mods use **Greybus**, a protocol originally developed for Google's Project Ara.

#### Greybus Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Moto Z Phone                             │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │                   Linux Kernel                          │ │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐ │ │
│  │  │ USB Driver  │  │ I2C Driver  │  │ Greybus Driver  │ │ │
│  │  └──────┬──────┘  └──────┬──────┘  └────────┬────────┘ │ │
│  │         │                │                   │          │ │
│  │         └────────────────┼───────────────────┘          │ │
│  │                          │                              │ │
│  └──────────────────────────┼──────────────────────────────┘ │
│                             │                                │
│  ┌──────────────────────────┼──────────────────────────────┐ │
│  │                    POGO Connector                        │ │
│  │          Power | USB | I2C | UniPro | GPIO              │ │
│  └──────────────────────────┼──────────────────────────────┘ │
└─────────────────────────────┼───────────────────────────────┘
                              │
┌─────────────────────────────┼───────────────────────────────┐
│                        Moto Mod                              │
│  ┌──────────────────────────┼──────────────────────────────┐ │
│  │                   Mod Controller                         │ │
│  │         (STM32 or similar microcontroller)              │ │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐ │ │
│  │  │ USB Device  │  │ I2C Slave   │  │ Greybus Stack   │ │ │
│  │  └─────────────┘  └─────────────┘  └─────────────────┘ │ │
│  └─────────────────────────────────────────────────────────┘ │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │                   Mod Hardware                           │ │
│  │         (Battery, Speaker, Camera, Projector, etc.)     │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

#### Greybus Protocol Layers

1. **Physical Layer**: UniPro or USB (over POGO pins)
2. **Transport Layer**: Greybus SVC (Supervisory Controller)
3. **Protocol Layer**: Greybus Bundles (Camera, Audio, Power, etc.)
4. **Application Layer**: Vendor-specific protocols

### Greybus Linux Kernel Source

The Greybus driver is in the Linux kernel:
```bash
# Kernel source locations
drivers/staging/greybus/
drivers/greybus/

# Key files
greybus_manifest.h   # Manifest format for mod discovery
greybus_protocols.h  # Protocol definitions
connection.c         # Connection management
```

**GitHub**: https://github.com/torvalds/linux/tree/master/drivers/greybus

---

## Part 3: Known Moto Mods Hardware

### Official Moto Mods (Released)

| Mod | Function | Internal Hardware |
|-----|----------|-------------------|
| **JBL SoundBoost** | Speaker | TI TPA3128D2 amp, 2x3W speakers |
| **JBL SoundBoost 2** | Speaker | Updated amp, better sound |
| **Insta-Share Projector** | DLP projector | TI DLP2000, 50 lumens |
| **TurboPower Pack** | Battery | 3490mAh Li-Po, Qualcomm QC |
| **Incipio offGRID** | Battery | 2220mAh Li-Po |
| **Mophie Juice Pack** | Battery | 3000mAh Li-Po |
| **Incipio Vehicle Dock** | Car mount | Wireless charging coil |
| **Style Shells** | Cases | NFC chip for identification |
| **Hasselblad True Zoom** | Camera | 10x optical zoom, Xenon flash |
| **Polaroid Insta-Share** | Printer | ZINK printing technology |
| **Motorola 360 Camera** | Camera | Dual 150° lenses, 4K |
| **Moto GamePad** | Controller | D-pad, analog sticks, 1035mAh |
| **5G Moto Mod** | 5G radio | Qualcomm X50 modem |
| **Amazon Alexa Speaker** | Smart speaker | 4-mic array, speaker |
| **Lenovo VitalMoto** | Health monitor | Heart rate, SpO2, temp sensors |
| **Livermorium Keyboard** | QWERTY keyboard | Mechanical keys |

### Third-Party / DIY Mods

| Project | Creator | What It Did |
|---------|---------|-------------|
| **DIY E-Ink Display** | Various | E-paper second screen |
| **Custom Battery Mod** | XDA users | Higher capacity |
| **Raspberry Pi Mod** | Makers | Attached Pi to back (display only) |

---

## Part 4: Research Required

### Unknown Technical Details

1. **Exact pin voltage levels** - Need oscilloscope measurements
2. **I2C addresses for mod identification** - Need logic analyzer
3. **Greybus manifest format for custom mods** - Partially documented
4. **Power negotiation protocol** - How mods request power
5. **High-speed data throughput** - Max UniPro bandwidth
6. **Authentication/signing** - Are mods cryptographically verified?

### Research Equipment Needed

| Tool | Purpose | Est. Cost |
|------|---------|-----------|
| Logic analyzer | Protocol capture | $20-200 |
| Oscilloscope | Voltage/timing | $100-500 |
| POGO pin test fixture | Physical interface | DIY or $50 |
| STM32 dev board | Mod controller prototype | $15-50 |
| 3D printer | Mod enclosure | $200+ or library |
| Multimeter | Basic measurements | $20-50 |

### Research Methodology

1. **Teardown existing mods** - Document internal components
2. **Probe POGO pins** - Identify voltages and protocols
3. **Capture I2C traffic** - During mod attach/detach
4. **Analyze kernel drivers** - Greybus source code
5. **Build simple test mod** - LED + I2C EEPROM
6. **Iterate to complex mods** - USB device, compute module

---

## Part 5: Custom Mod Possibilities

### Tier 1: Feasible Now

| Mod Idea | Complexity | Requirements |
|----------|------------|--------------|
| **Battery Pack** | Low | Li-Po cell, charge controller |
| **LED Notification Light** | Low | MCU, RGB LEDs, I2C |
| **Custom Style Shell** | Low | 3D printing, NFC tag |
| **USB Hub** | Medium | USB hub IC, POGO adapter |
| **Wireless Charging Receiver** | Medium | Qi coil, rectifier |

### Tier 2: Challenging but Possible

| Mod Idea | Complexity | Requirements |
|----------|------------|--------------|
| **E-Ink Display** | High | E-paper module, SPI driver |
| **SDR Radio Module** | High | RTL-SDR, USB passthrough |
| **LoRa Transceiver** | High | LoRa module, antenna |
| **Environmental Sensors** | Medium | BME680, I2C connection |
| **Hardware Crypto Wallet** | High | Secure element, display |

### Tier 3: Ambitious (Your Vision!)

| Mod Idea | Complexity | Challenges |
|----------|------------|------------|
| **Compute Module (RAM expansion)** | Extreme | No bus for external memory |
| **Raspberry Pi CM4 Dock** | Very High | Power, data bandwidth |
| **GPU Accelerator** | Extreme | Bandwidth, power, heat |
| **External Storage Array** | High | USB bandwidth limit |

### Reality Check: Compute Module

**Why it's hard:**
- Phone RAM is on SoC die (not expandable)
- POGO pins provide USB 2.0 (~480Mbps max)
- No PCIe or high-speed memory bus exposed
- Power budget limited (~15W max)

**What IS possible:**
- USB peripheral compute (limited bandwidth)
- Offload processing to mod, return results
- Think "co-processor" not "RAM expansion"

---

## Part 6: Phone Farm / Server Use Case

### Moto Z as Kubernetes Node

| Aspect | Feasibility | Notes |
|--------|-------------|-------|
| **Processing Power** | Good | SD 835 is capable |
| **Memory** | Limited | 4-6GB, no expansion |
| **Storage** | OK | microSD + internal |
| **Networking** | Good | WiFi 5, Gigabit (USB-C adapter) |
| **Power Efficiency** | Excellent | ~5W idle, ~15W load |
| **Density** | Very High | Thin, stackable |

### Software Stack

```yaml
# PostmarketOS or LineageOS for mainline kernel
# K3s (lightweight Kubernetes)
# Or Docker Swarm

Potential Uses:
- CI/CD runners
- Build nodes
- Web servers (low traffic)
- IoT gateways
- Home automation hubs
- Network monitoring
- Ad blocking (Pi-hole equivalent)
```

### Challenges

1. **Bootloader unlock** - Required for custom ROM
2. **Thermal management** - Need airflow for server use
3. **USB networking** - May need hub for wired Ethernet
4. **Reliability** - Phone hardware not designed for 24/7

---

## Part 7: Carrier Unlock Project

### Scale of the Problem

Millions of Verizon-locked Moto Z phones exist:
- Original owners upgraded
- Phones end up in drawers
- Resale value tanked due to lock
- E-waste potential

### Liberation Strategy

| Phase | Goal | Method |
|-------|------|--------|
| **1** | Document all variants | Gather CIDs, build numbers |
| **2** | Find unlock patterns | Analyze successful unlocks |
| **3** | Server-side research | API analysis, vulnerability scan |
| **4** | Client-side research | ABL/TZ reverse engineering |
| **5** | Community exploit** | If found, share responsibly |

### Ethical Considerations

- **Own devices only** - Don't unlock stolen phones
- **Responsible disclosure** - Report vulns before exploit
- **Right to repair** - You own the hardware
- **E-waste reduction** - Environmental benefit

---

## Part 8: Community Building

### Proposed Open Source Projects

1. **moto-mods-sdk** - Open source mod development kit
2. **greybus-tools** - Testing and debugging utilities
3. **moto-z-unlock** - Bootloader unlock research (legal)
4. **moto-z-server** - Kubernetes/Docker on Moto Z
5. **moto-z-mods** - Community-designed mods

### Platforms

- **GitHub organization** - Code and documentation
- **XDA subforum** - Community discussion
- **Discord/Matrix** - Real-time collaboration
- **Wiki** - Comprehensive documentation

---

## Part 9: Immediate Next Steps

### For You

1. **Inventory your devices** - List all Moto Z phones you have
2. **Document each one** - Model, carrier, unlock status, condition
3. **Get one unlocked** - Try paid service or forum response
4. **Start mod research** - Teardown a simple mod

### Research Tasks

1. **Get Greybus kernel docs** - Linux kernel documentation
2. **Find MDK information** - Search for archived Motorola developer content
3. **Teardown JBL SoundBoost** - Document internal design
4. **Probe POGO pins** - Voltage levels, idle state
5. **Capture mod attachment** - Logic analyzer on I2C

### Hardware Shopping List

```
□ USB logic analyzer (8ch+) - ~$20
□ POGO pin connector (matching) - DIY or scavenge
□ STM32 Blue Pill - ~$5
□ Breadboard + jumpers - ~$10
□ Multimeter (if not owned) - ~$20
□ 3D printer access - varies
```

---

## Appendix: Resources

### Official Documentation (Archived)

- Motorola MDK site (archived on Wayback Machine)
- Indiegogo Moto Mods campaigns
- Lenovo developer forums

### Linux Kernel

- https://github.com/torvalds/linux/tree/master/drivers/greybus
- https://www.kernel.org/doc/html/latest/driver-api/greybus/

### Community Resources

- XDA Moto Z forums
- /r/Moto_Z subreddit
- iFixit teardowns

### Related Projects

- Project Ara documentation
- Google ATAP papers
- UniPro specifications (MIPI Alliance)

---

*Document created: 2025-12-15*
*Status: Research in progress*
*This is a living document - will be updated as research progresses*
