# Fingerprint login on KDE Plasma: PAM, SDDM and KWallet

How to wire the VeriMark into a KDE desktop so the lock screen and login can use it, and the
traps we fell into getting there. Tested on Kubuntu 26.04 (Plasma 6.6.6, SDDM 0.21) with this
repo's `driver/`; see [ubuntu-26.04.md](ubuntu-26.04.md). The behaviour described is a property
of Plasma, SDDM and PAM, not of Ubuntu, but the **exact PAM lines are not portable**: see
[Adapting the jump counts](#adapting-the-jump-counts). We did not test Fedora or any other distro.

## What you get

| Where | Works | Needs PAM changes? |
|---|---|---|
| Plasma lock screen | Yes, touch the sensor | **No** |
| SDDM login screen | Yes, but only via an empty-password Enter (below) | Yes |
| `sudo`, `su`, TTY login | Not tested here (passwordless sudo on the test machine) | |

Before touching PAM, check the driver itself works: `fprintd-list "$USER"` should show the
Kensington device and `fprintd-verify` should print `verify-match` after a touch.

## 1. Lock screen: nothing to do

Plasma ships a dedicated fingerprint-only PAM service, `kde-fingerprint` (on Debian-family
systems in `/usr/lib/pam.d/kde-fingerprint`; it contains `auth required pam_fprintd.so`). The
lock screen runs it alongside the normal password prompt and shows its own hint. With a working
`fprintd` and an enrolled finger it just works, and typing a password still works instantly.

## 2. Do not enable the distro's global fprintd PAM profile

Debian/Ubuntu's `pam-auth-update --enable fprintd` (and similar "enable fingerprint" switches on
other distros) puts `pam_fprintd` at the top of the shared `common-auth` stack. Every password
check then waits for a finger before it even looks at the password you typed: up to the
module's timeout (10 s in Ubuntu's profile; `pam_fprintd`'s own default is longer). That
affects the lock screen's password path, polkit prompts and TTY
logins, and it is unnecessary for the lock screen (section 1). Leave it disabled and add
fingerprint only where it is needed.

## 3. SDDM

### The limit

SDDM's greeter collects the username **and** password, and only starts PAM when you press Enter.
So the login screen can never show a fingerprint prompt or light the reader on its own; there
is no way for the greeter to ask for a finger while idle. This is a property of SDDM, not of the
driver.

What does work: type your username, **leave the password empty, press Enter**, then touch the
sensor when the reader lights up. PAM runs `pam_fprintd` for the empty password and logs you in on
a match. It is not intuitive, but it is reliable.

### The stack

A naive "put `pam_fprintd` first" breaks typed passwords (they wait for a finger). Instead, check
the typed password first, then the fingerprint, both jumping past the rest of `common-auth` on
success so the `pam_kwallet5` / `pam_gnome_keyring` lines after it still run. In `/etc/pam.d/sddm`,
immediately before `@include common-auth`:

```
auth    [success=3 default=ignore]      pam_unix.so try_first_pass
auth    [success=2 default=ignore]      pam_fprintd.so max-tries=1 timeout=10
@include common-auth
```

Result: a typed password logs in immediately; an empty password falls through to the fingerprint;
a wrong password waits out the fingerprint timeout once and is then denied by the normal stack.

### Adapting the jump counts

`success=N` means "on success, skip the next N modules". The targets above assume Debian's
`common-auth`, which contains exactly:

```
auth  [success=1 default=ignore]  pam_unix.so nullok
auth  requisite                   pam_deny.so
auth  required                    pam_permit.so
auth  optional                    pam_cap.so
```

We want a success to land on `pam_permit.so`, skipping the `pam_unix` and `pam_deny` lines. So
the fingerprint line skips **2** (unix, deny), and the password line skips **3** (the fingerprint
line plus those two). If your `common-auth` (or `system-auth` / `authselect` output) has a
different layout, or other modules, recount: **the number must equal the modules between the
line and the `pam_permit`-equivalent**. This is the part that is not portable, and it can change
whenever `pam-auth-update` or `authselect` regenerates the stack, so re-check after any such
change. Getting it wrong can lock you out of the login screen.

### Do it safely

- Back up first: `sudo cp -a /etc/pam.d /etc/pam.d.bak.$(date +%Y%m%d)`.
- Keep a text console available (Ctrl+Alt+F3) and **a second logged-in session or root shell open
  while editing**. TTY login uses a different stack, so it is your way back in if the SDDM stack is
  wrong. Restore with `sudo cp /etc/pam.d.bak.*/sddm /etc/pam.d/sddm`.
- Test by logging out and trying both paths (typed password, then empty-Enter + touch).

## What we tried first, so you don't have to

1. **`pam_fprintd` before the password** (what the distro profile does). Typing a password and
   pressing Enter lit the reader and waited for a touch before the password was even checked.
2. **`[success=done ...]` on the fingerprint/password lines.** `done` ends the whole `auth`
   stack, which skipped the `pam_kwallet5` / `pam_gnome_keyring` lines after `common-auth`, so
   typed-password logins would no longer unlock the wallet. Jump counts avoid that.

## KWallet

A fingerprint login never supplies the account password, and KWallet derives its key from that
password, so a fingerprint login leaves the wallet locked and you get its own prompt (a KWallet
dialog, not PAM, so the reader is not involved).

Be careful before "fixing" this: Chromium-family browsers and Electron apps keep their "Safe
Storage" key in KWallet. Disabling the wallet subsystem makes their saved data unreadable. You can
see what a wallet holds without opening it: `~/.local/share/kwalletd/kdewallet_attributes.json`
lists entry names such as `Chrome Safe Storage`. Options:

- Keep the wallet password and use the password path at login when you want the wallet unlocked.
- Set an **empty** wallet password in KWalletManager (Change Password, leave the new one blank).
  This removes the prompt and loses nothing, but those keys are then stored without a wallet
  password. That matters if the disk is not encrypted and someone can read it.
- Disabling the wallet is the most destructive option.

## Troubleshooting

- `journalctl -u fprintd` shows what the device and PAM actually asked for. For driver detail, put
  `Environment=G_MESSAGES_DEBUG=all` and `Environment=LIBFPRINT_DEBUG=5` in a drop-in under
  `/etc/systemd/system/fprintd.service.d/` and remove it afterwards (it is very verbose).
- If `fprintd-list` says "No devices available" after installing the driver, check
  `systemctl show fprintd -p Environment`: another drop-in sorting after
  `10-verimark-libfprint.conf` can replace `LD_LIBRARY_PATH` without any error.
- Nothing happens at the lock screen: check `/usr/lib/pam.d/kde-fingerprint` exists and
  `fprintd-verify` works from a terminal first.
