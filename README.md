# libfprint — Blestech Betterlife 347d:0302

Linux fingerprint support for the **Blestech Betterlife Fingerprint (USB ID `347d:0302`)**, created as a fork of [libfprint](https://gitlab.freedesktop.org/libfprint/libfprint). This sensor ships in some laptops and had no Linux driver before this.

Works with fprintd and anything else built on libfprint (KDE/GNOME fingerprint login, `fprintd-enroll`, …).

## Check compatibility

```sh
lsusb | grep 347d
```

A supported device shows up as:

```text
Bus 005 Device 003: ID 347d:0302 Blestech Betterlife Fingerprint
```

Only `347d:0302` is supported here. For the sibling device `347d:0304`, see [betterlife-347d-0304-fingerprint-linux](https://github.com/Light-log/betterlife-347d-0304-fingerprint-linux).

## Install

A PKGBUILD is provided in [`aur/`](aur/) for arch based distros:

```sh
cd aur
makepkg -si
```

Other distros can build it like stock libfprint (meson).

## Credits

- **SIGFM matching algorithm** — [libfprint MR !418](https://gitlab.freedesktop.org/libfprint/libfprint/-/merge_requests/418). Classic minutiae matching (NBIS/bozorth3) is unreliable on small sensors like this one; SIGFM is what makes recognition work here.
- **Protocol reference** — [Light-log/betterlife-347d-0304-fingerprint-linux](https://github.com/Light-log/betterlife-347d-0304-fingerprint-linux), an LGPL-2.1 driver for the sibling `347d:0304` device.

## Status

Tested on **one machine only: Machenike L16A** with the `347d:0302` sensor (enroll + verify through fprintd). No other hardware has been tested.

## License

[LGPL-2.1-or-later](COPYING) — same as libfprint. The SIGFM algorithm and the `347d:0304` reference driver are LGPL-2.1; reused code keeps its original copyright headers.
