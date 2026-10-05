# RTL8712U / RTL8188SU — Linux Wi-Fi Driver

[![License: GPL v2](https://img.shields.io/badge/License-GPL--2.0-blue.svg)](LICENSE)
![Linux kernel module](https://img.shields.io/badge/Linux-kernel%20module-555555)
![DKMS](https://img.shields.io/badge/DKMS-supported-2ea44f)
![Status](https://img.shields.io/badge/Status-experimental-orange)
[![Support on PayPal](https://img.shields.io/badge/Buy%20me%20a%20coffee-PayPal-0070ba)](https://www.paypal.me/firdausaziz)

**Giving older Realtek RTL8188SU USB Wi-Fi adapters another chance on modern Linux.** ☕ 🐧

This project adapts the Linux **v6.12 staging `rtl8712` driver** for newer kernels, adds defensive parsing and teardown fixes, and provides a reproducible **DKMS** source package. It began as a working port for the **LevelOne WUA-0624** (`0bda:8171`) on Ubuntu 26.04.

> [!IMPORTANT]
> **Experimental, not an upstream or universally tested driver.** Keep an alternate means of network access and a working backup. A successful build is not proof that every USB adapter, access point or kernel configuration works.

## ✨ What's included

- **Modern-kernel compatibility:** validated builds against `7.0.0-34-generic` and `7.0.0-38-generic`.
- **Legacy WPA2 interoperability:** tested WPA2-PSK/CCMP on an access point advertising mixed WPA2/WPA3 modes. **No claim of WPA3/SAE support.**
- **Safer IE handling:** validation of malformed and truncated RSN, WMM and selected 802.11n HT elements.
- **Driver lifecycle improvements:** USB disconnect, workqueue, timer and thread-shutdown hardening.
- **DKMS packaging and parser tests** included in the source tree.

## 🧩 Tested environment

| Component | Tested configuration |
| --- | --- |
| USB adapter | LevelOne WUA-0624 — Realtek RTL8188SU |
| USB ID | `0bda:8171` |
| Distribution | Ubuntu 26.04 |
| Kernel | `7.0.0-34-generic` (live-tested) |
| Additional build | `7.0.0-38-generic` (compile/DKMS only) |
| Wireless network | TP-Link AX73, mixed WPA2/WPA3 SSID |
| Authentication | WPA2-PSK / CCMP |

Live checks included association and DHCP, router connectivity and internet traffic. **Not yet broadly qualified:** suspend/resume, roaming, extended uptime, repeated unplug cycles, other USB IDs, other AP configurations, and station-reuse timer concurrency. Kernel updates may need further work.

## 🚀 Quick start

Make sure matching Linux headers, GCC, make, DKMS (if wanted), and the separate `rtlwifi/rtl8712u.bin` firmware are installed on your machine. Firmware is **not included** in this repository.

### Build against your running kernel

```bash
git clone https://github.com/RattanCandy/rtl8712u-linux-driver.git
cd rtl8712u-linux-driver
make -C /lib/modules/$(uname -r)/build M="$PWD" CONFIG_R8712U=m modules
modinfo -F vermagic ./r8712u.ko
```

This generates `r8712u.ko` for **that exact kernel**. Loading or swapping a Wi-Fi module can disconnect you; do not do this over your sole remote connection without recovery access.

### Optional DKMS installation

`dkms.conf` defines `r8712u/6.12-compat2`. After reviewing the source and verifying a recovery path:

```bash
sudo mkdir -p /usr/src/r8712u-6.12-compat2
sudo cp ./*.c ./*.h Makefile dkms.conf /usr/src/r8712u-6.12-compat2/
sudo dkms add -m r8712u -v 6.12-compat2
sudo dkms build -m r8712u -v 6.12-compat2 -k "$(uname -r)"
sudo dkms install -m r8712u -v 6.12-compat2 -k "$(uname -r)"
dkms status -m r8712u
```

This installs a kernel-specific module for subsequent normal loads; it does **not** guarantee compatibility with future kernel changes. Secure Boot systems may additionally require module signing and key enrollment.

## 🧪 Testing and limitations

- Sanitizer-backed parser tests cover RSN handling, PMKID parsing, IE traversal, and malformed-input cases. Test generators are in `tests/`.
- The maintained adapter completed a WPA2 handshake, associated with `Prometheus`, received an IP address and passed LAN/internet traffic checks.
- Known unresolved review area: **station-reuse timer concurrency**. Treat the port as experimental until additional race and lifecycle testing is done.

Found an issue? Please include your adapter **USB ID**, distribution/kernel, AP security configuration (without passwords), reproduction steps, and relevant kernel log excerpts. Avoid posting private keys, passwords, or personal identifiers.

## 📜 License and attribution

**GNU General Public License, version 2 (`GPL-2.0`).** See the repository [LICENSE](LICENSE) and the SPDX notices in individual source files.

The driver is derived from Linux **v6.12**, `drivers/staging/rtl8712`. Original authors' notices and the original licensing terms remain applicable. This is an independent compatibility-maintenance effort; it is **not affiliated with or endorsed by Realtek, LevelOne or the Linux kernel maintainers**. This repo does not distribute proprietary firmware.

## ☕ Support

**If this is useful, buy me a coffee!**

[**Support this project on PayPal**](https://www.paypal.me/firdausaziz)

Contributions, useful bug reports and compatibility test results are welcome, too.
