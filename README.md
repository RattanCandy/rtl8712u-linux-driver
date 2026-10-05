# RTL8712U / RTL8188SU Linux kernel driver port

Experimental maintenance of the Linux staging `rtl8712` driver from upstream Linux **v6.12**, adapted for newer Linux kernels. Initial working target: **LevelOne WUA-0624**, USB `0bda:8171` (Realtek RTL8188SU), Ubuntu 26.04, kernels `7.0.0-34-generic` and `7.0.0-38-generic`.

## Status

- Compiles for both tested Ubuntu kernel headers.
- Runtime-tested on `7.0.0-34-generic`: Wi-Fi association to a mixed WPA2/WPA3 TP-Link AX73 SSID using the legacy **WPA2-PSK / CCMP** path, DHCP, LAN and internet ICMP connectivity.
- Includes bounded parsing for RSN, WMM, and selected HT information elements, along with USB/timer/workqueue teardown changes.
- This is experimental driver maintenance, **not** a general-purpose supported Wi-Fi driver. Long-duration use, suspend/resume, disconnect/reconnect cycles, different APs and all supported USB IDs are not fully qualified. An outstanding station-reuse timer concurrency risk needs additional review.

## Build

Install your matching Linux kernel headers, GCC, make and firmware, then run:

```sh
make -C /lib/modules/$(uname -r)/build M="$PWD" CONFIG_R8712U=m modules
```

The output is `r8712u.ko`, specific to the **kernel it was built against**. Never load a build for another kernel. The firmware `rtlwifi/rtl8712u.bin` is supplied separately by the system's firmware package and is **not distributed** here.

## DKMS

`dkms.conf` declares package name `r8712u`, version `6.12-compat2`. For a controlled installation, copy this source into `/usr/src/r8712u-6.12-compat2/`, then (as root):

```sh
dkms add -m r8712u -v 6.12-compat2
dkms build -m r8712u -v 6.12-compat2 -k "$(uname -r)"
dkms install -m r8712u -v 6.12-compat2 -k "$(uname -r)"
```

Module installs and updates can interrupt networking: use another connection for recovery, preserve a tested backup, and do not substitute this driver for a kernel-provided one without testing. Secure Boot signing may require separate configuration.

## Validation

The source tree is used by the standalone parser harness in `tests/` (the sanitizers do not replace runtime driver testing). Development harnesses and install scripts are documented separately from the minimum DKMS source bundle.

## Provenance and license

The starting point is `drivers/staging/rtl8712` in Linux v6.12, copyright and per-file notices retained. Source is licensed **GPL-2.0** under its original SPDX declarations. Redistribution must retain the original copyright and license notices. No firmware or third-party proprietary binary is included.
