# copyfail-check

> Shell scripts to detect Linux kernel vulnerabilities, check mitigation status, and guide remediation — designed to run locally or across fleets via SSH, Ansible, or pssh.

---

## CVE-2026-31431 — Copy Fail

**Copy Fail** is a high-severity local privilege escalation (LPE) vulnerability in the Linux kernel's `algif_aead` cryptographic module. A logic flaw introduced in 2017 allows any unprivileged local user to write 4 controlled bytes into the page cache of any readable file — enough to overwrite a setuid binary and obtain root. A working 732-byte Python proof-of-concept exists and is publicly available.

| | |
|---|---|
| **CVE** | CVE-2026-31431 |
| **CVSS** | 7.8 (High) |
| **Disclosed** | April 29, 2026 |
| **Affected** | Linux kernels 4.13 – 6.x (2017–2026) |
| **Distributions** | Ubuntu, RHEL, SUSE, Debian, Amazon Linux, and most others |
| **Remotely exploitable** | No — local access required |
| **Patch available** | Partial — check your distro's advisories |

### What the script checks

| Check | Needs root? |
|---|---|
| Kernel version — whether you're in the affected range (≥ 4.13) | No |
| `algif_aead` module — loaded, present on disk, or blacklisted | No |
| Boot parameters — `initcall_blacklist=algif_aead_init` presence | No |
| AF_ALG socket reachability — whether the exploit path is open | No |
| SELinux status | No |
| AppArmor status | **Yes** — partial output only without root |
| Distro patch status — CVE listed in kernel changelog | No |

> **Root is not required** to run the script — all checks except AppArmor status work as a regular user. Running with `sudo` is recommended for complete results, and is the safer choice when piping from `curl`.

### Compatibility

The script is designed to work across all major Linux distributions:

| Distribution family | Package manager check | Module path |
|---|---|---|
| Debian, Ubuntu | `dpkg` + kernel changelog | `/lib/modules/` |
| RHEL, CentOS, Amazon Linux | `rpm` (`kernel`, `kernel-rt`) | `/lib/modules/` |
| SUSE, openSUSE | `rpm` (`kernel-default`) | `/lib/modules/` |
| Arch Linux | `pacman` + advisory link | `/usr/lib/modules/` |
| Fedora | `rpm` + `/usr/lib/modules/` fallback | `/usr/lib/modules/` |

> **Requires `bash`** — the script uses bash-specific syntax and will not run under `sh`, `ash`, or `dash`. On Alpine Linux (which uses busybox ash by default), install bash first:
> ```bash
> apk add bash
> ```

### Quick run (single server)

Without root — most checks work:
```bash
curl -fsSL https://raw.githubusercontent.com/codesource/copyfail-check/main/check_copyfail.sh | bash
```

With root — full results including AppArmor status:
```bash
curl -fsSL https://raw.githubusercontent.com/codesource/copyfail-check/main/check_copyfail.sh | sudo bash
```

> **Tip:** Pin to a specific commit SHA in production so the script cannot change under you:
> ```bash
> curl -fsSL https://raw.githubusercontent.com/codesource/copyfail-check/COMMIT_SHA/check_copyfail.sh | sudo bash
> ```

### Download and inspect first (recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/codesource/copyfail-check/main/check_copyfail.sh -o check_copyfail.sh
less check_copyfail.sh
bash check_copyfail.sh        # without root
sudo bash check_copyfail.sh   # full results
```

### Run across a fleet

**SSH loop**
```bash
for HOST in server1 server2 server3; do
  echo "=== $HOST ==="
  ssh "$HOST" "curl -fsSL https://raw.githubusercontent.com/codesource/copyfail-check/main/check_copyfail.sh | sudo bash"
done
```

**Ansible**
```yaml
- name: Check Copy Fail vulnerability
  hosts: all
  tasks:
    - name: Run check script
      script: check_copyfail.sh
      become: yes
```

**Parallel SSH**
```bash
pssh -h hosts.txt -i \
  "curl -fsSL https://raw.githubusercontent.com/codesource/copyfail-check/main/check_copyfail.sh | sudo bash"
```

### Example output

```
============================================================
  Copy Fail CVE-2026-31431 – Vulnerability Check
============================================================

>>> Kernel Version
  [INFO]  Running kernel: 5.15.0-107-generic
  [WARN]  Kernel 5.15.0-107-generic is in the affected range (4.13 – 6.x).

>>> algif_aead Module Status
  [WARN]  algif_aead module is currently LOADED — system is exploitable.
  [WARN]  Module file found at: /lib/modules/5.15.0-107-generic/kernel/crypto/algif_aead.ko
  [WARN]  algif_aead is NOT blacklisted — it can be loaded on demand.

>>> Kernel Boot Parameter Mitigation
  [WARN]  initcall_blacklist=algif_aead_init is NOT set in boot parameters.

>>> AF_ALG Socket Reachability
  [WARN]  AF_ALG sockets are reachable by this user — exploit path is open.

>>> Mandatory Access Control (SELinux / AppArmor)
  [WARN]  Neither SELinux nor AppArmor tools detected — no MAC layer present.

>>> Distribution Patch Status
  [WARN]  Could not confirm CVE-2026-31431 is listed as fixed in running kernel's changelog.

============================================================
  SUMMARY
============================================================
  !! LIKELY VULNERABLE — No confirmed mitigation detected.

  Recommended actions (in order of preference):
  1. Apply your distro's kernel update as soon as available.
  2. Add to /etc/modprobe.d/copyfail.conf:
       blacklist algif_aead
       install algif_aead /bin/true
     Then run: sudo depmod -a && sudo update-initramfs -u
  3. Add to kernel boot parameters (grub):
       initcall_blacklist=algif_aead_init
  4. Immediately unload the module if loaded:
       sudo rmmod algif_aead
============================================================
```

### Mitigations

Apply these in order of preference:

**1. Patch your kernel** *(best fix)*
```bash
# Debian / Ubuntu
sudo apt update && sudo apt upgrade linux-image-$(uname -r)

# RHEL / CentOS / Amazon Linux
sudo yum update kernel

# SUSE
sudo zypper update kernel-default
```

**2. Blacklist the module** *(immediate, persistent)*
```bash
sudo tee /etc/modprobe.d/copyfail.conf << 'EOF'
blacklist algif_aead
install algif_aead /bin/true
EOF

sudo depmod -a

# Debian/Ubuntu
sudo update-initramfs -u

# RHEL/Fedora
sudo dracut -f
```

**3. Unload the module now** *(immediate, not persistent across reboots)*
```bash
sudo rmmod algif_aead
```

**4. Kernel boot parameter** *(alternative to blacklist)*

Add `initcall_blacklist=algif_aead_init` to your GRUB config and reboot.

---

## References

- [copy.fail](https://copy.fail/) — official vulnerability page
- [Xint/Theori writeup](https://xint.io/blog/copy-fail-linux-distributions)
- [NVD — CVE-2026-31431](https://nvd.nist.gov/vuln/detail/CVE-2026-31431)
- [CERT-EU Advisory 2026-005](https://cert.europa.eu/publications/security-advisories/2026-005/)
- [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/05/01/cve-2026-31431-copy-fail-vulnerability-enables-linux-root-privilege-escalation/)
- [The Hacker News](https://thehackernews.com/2026/04/new-linux-copy-fail-vulnerability.html)

## License

MIT — use freely, no warranty implied. Always review scripts before running them as root.
