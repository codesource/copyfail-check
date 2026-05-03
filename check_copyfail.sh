#!/usr/bin/env bash
# ============================================================
#  Copy Fail (CVE-2026-31431) – Vulnerability Check Script
#  Checks whether a Linux system is vulnerable or mitigated.
# ============================================================

RED='\033[0;31m'
YEL='\033[1;33m'
GRN='\033[0;32m'
CYN='\033[0;36m'
BLD='\033[1m'
RST='\033[0m'

VULNERABLE=0
MITIGATED=0

banner() {
  echo -e "${CYN}"
  echo "============================================================"
  echo "  Copy Fail CVE-2026-31431 – Vulnerability Check"
  echo "  Checks kernel version, module state, and mitigations"
  echo "============================================================"
  echo -e "${RST}"
}

section() { echo -e "\n${BLD}>>> $1${RST}"; }

pass()  { echo -e "  ${GRN}[SAFE]${RST}  $1"; }
warn()  { echo -e "  ${YEL}[WARN]${RST}  $1"; VULNERABLE=1; }
info()  { echo -e "  ${CYN}[INFO]${RST}  $1"; }
mitig() { echo -e "  ${GRN}[MITIGATED]${RST}  $1"; MITIGATED=1; }

# ── Privilege check ───────────────────────────────────────────
check_privileges() {
  if [ "$(id -u)" -eq 0 ]; then
    info "Running as root — all checks will have full visibility."
  else
    echo -e "  ${YEL}[NOTE]${RST}  Running as non-root user '$(id -un)'."
    echo -e "         Most checks will still work. For full accuracy, consider:"
    echo -e "         ${BLD}sudo bash $0${RST}"
    echo ""
  fi
}

# ── 1. Kernel version ────────────────────────────────────────
check_kernel() {
  section "Kernel Version"
  KVER=$(uname -r)
  info "Running kernel: $KVER"

  # The bug was introduced in August 2017 (commit 72548b093ee3).
  # Fixed in mainline on 1 April 2026.
  # Extract major.minor for a rough check; distro patches vary.
  KMAJ=$(echo "$KVER" | cut -d. -f1)
  KMIN=$(echo "$KVER" | cut -d. -f2)

  # Kernels before 4.13 don't have the bad commit
  if [ "$KMAJ" -lt 4 ] || { [ "$KMAJ" -eq 4 ] && [ "$KMIN" -lt 13 ]; }; then
    pass "Kernel $KVER predates the vulnerable commit (< 4.13) — likely not affected."
  else
    warn "Kernel $KVER is in the affected range (4.13 – 6.x). Check module & patches below."
  fi
}

# ── 2. algif_aead module ─────────────────────────────────────
check_module() {
  section "algif_aead Module Status"

  # Check if module is currently loaded
  if lsmod 2>/dev/null | grep -q '^algif_aead'; then
    warn "algif_aead module is currently LOADED — system is exploitable."
  else
    pass "algif_aead module is NOT currently loaded."
  fi

  # Check if the module exists on disk (could be loaded on demand)
  # Some distros use /usr/lib/modules (Arch, newer Fedora), others /lib/modules (Debian, RHEL)
  MOD_PATH=$(find /lib/modules/"$(uname -r)" /usr/lib/modules/"$(uname -r)" \
             -name 'algif_aead.ko*' 2>/dev/null | head -1)
  if [ -n "$MOD_PATH" ]; then
    warn "Module file found at: $MOD_PATH — it can be auto-loaded unless blacklisted."
  else
    pass "Module file not found on disk — may have been removed or not compiled."
  fi

  # Check blacklist
  if grep -rq 'blacklist algif_aead' /etc/modprobe.d/ 2>/dev/null; then
    mitig "algif_aead is blacklisted in /etc/modprobe.d/ — auto-load is prevented."
  else
    warn "algif_aead is NOT blacklisted — it can be loaded on demand."
  fi
}

# ── 3. Kernel boot parameter mitigation ──────────────────────
check_boot_param() {
  section "Kernel Boot Parameter Mitigation"
  CMDLINE=$(cat /proc/cmdline 2>/dev/null)
  info "Kernel cmdline: $CMDLINE"

  if echo "$CMDLINE" | grep -q 'initcall_blacklist=algif_aead_init'; then
    mitig "initcall_blacklist=algif_aead_init is set — module cannot initialize."
  else
    warn "initcall_blacklist=algif_aead_init is NOT set in boot parameters."
  fi
}

# ── 4. AF_ALG socket reachability ────────────────────────────
check_afalg_socket() {
  section "AF_ALG Socket Reachability"
  # Try to open an AF_ALG socket (type 38 = AF_ALG, SOCK_SEQPACKET=5)
  # We use Python if available for a clean test
  if command -v python3 &>/dev/null; then
    RESULT=$(python3 -c "
import socket, sys
try:
    s = socket.socket(38, socket.SOCK_SEQPACKET, 0)
    s.close()
    print('reachable')
except Exception as e:
    print('blocked: ' + str(e))
" 2>/dev/null)
    if echo "$RESULT" | grep -q 'reachable'; then
      warn "AF_ALG sockets are reachable by this user — exploit path is open."
    else
      mitig "AF_ALG sockets are NOT reachable: $RESULT"
    fi
  else
    info "python3 not found — skipping AF_ALG socket reachability test."
  fi
}

# ── 5. SELinux / AppArmor ────────────────────────────────────
check_mac() {
  section "Mandatory Access Control (SELinux / AppArmor)"

  if command -v getenforce &>/dev/null; then
    SELINUX=$(getenforce 2>/dev/null)
    info "SELinux status: $SELINUX"
    if [ "$SELINUX" = "Enforcing" ]; then
      info "SELinux is Enforcing — may limit exploit IF AF_ALG is confined. Verify policy."
    else
      warn "SELinux is not Enforcing — no MAC protection against this exploit."
    fi
  fi

  if command -v aa-status &>/dev/null || command -v apparmor_status &>/dev/null; then
    AA_CMD=$(command -v aa-status || command -v apparmor_status)
    if [ "$(id -u)" -eq 0 ]; then
      if "$AA_CMD" --enabled 2>/dev/null; then
        info "AppArmor is enabled — only mitigates Copy Fail if AF_ALG is explicitly denied in active profiles."
      else
        info "AppArmor is installed but not enabled."
      fi
    else
      info "AppArmor detected but full status requires root — re-run with sudo for accurate results."
    fi
  fi

  if ! command -v getenforce &>/dev/null && ! command -v aa-status &>/dev/null && ! command -v apparmor_status &>/dev/null; then
    warn "Neither SELinux nor AppArmor tools detected — no MAC layer present."
  fi
}

# ── 6. Distribution patch status ─────────────────────────────
check_distro_patch() {
  section "Distribution Patch Status"

  if [ -f /etc/os-release ]; then
    . /etc/os-release
    info "Distribution: ${PRETTY_NAME:-$ID}"
  fi

  # Check if any kernel changelog / package mentions the CVE
  PATCHED=0
  if command -v rpm &>/dev/null; then
    # RHEL/CentOS/Fedora/Amazon Linux use 'kernel'; SUSE uses 'kernel-default'
    for KPKG in kernel kernel-default kernel-rt; do
      if rpm -q --changelog "$KPKG" 2>/dev/null | grep -q 'CVE-2026-31431'; then
        pass "CVE-2026-31431 appears in the installed $KPKG RPM changelog — likely patched."
        PATCHED=1
        break
      fi
    done
  fi
  if command -v dpkg &>/dev/null; then
    CHANGES=$(zcat /usr/share/doc/linux-image-"$(uname -r)"/changelog.Debian.gz 2>/dev/null \
              || cat /usr/share/doc/linux-image-"$(uname -r)"/changelog* 2>/dev/null)
    if echo "$CHANGES" | grep -q 'CVE-2026-31431'; then
      pass "CVE-2026-31431 appears in the installed kernel's Debian changelog — likely patched."
      PATCHED=1
    fi
  fi
  if command -v pacman &>/dev/null; then
    if pacman -Qi linux 2>/dev/null | grep -q 'CVE-2026-31431'; then
      pass "CVE-2026-31431 appears in the Arch linux package info — likely patched."
      PATCHED=1
    else
      info "Arch Linux detected — check https://security.archlinux.org/ for patch status."
    fi
  fi
  if [ $PATCHED -eq 0 ]; then
    warn "Could not confirm CVE-2026-31431 is listed as fixed in the running kernel's changelog."
    info "Check your vendor's security advisories and apply the latest kernel update."
  fi
}

# ── Summary ──────────────────────────────────────────────────
summary() {
  echo ""
  echo -e "${BLD}============================================================${RST}"
  echo -e "${BLD}  SUMMARY${RST}"
  echo -e "${BLD}============================================================${RST}"

  if [ $VULNERABLE -eq 1 ] && [ $MITIGATED -eq 0 ]; then
    echo -e "${RED}  !! LIKELY VULNERABLE — No confirmed mitigation detected.${RST}"
    echo ""
    echo "  Recommended actions (in order of preference):"
    echo "  1. Apply your distro's kernel update as soon as available."
    echo "  2. Add to /etc/modprobe.d/copyfail.conf:"
    echo "       blacklist algif_aead"
    echo "       install algif_aead /bin/true"
    echo "     Then run: sudo depmod -a && sudo update-initramfs -u  (Debian/Ubuntu)"
    echo "            or: sudo dracut -f  (RHEL/Fedora)"
    echo "  3. Add to kernel boot parameters (grub):"
    echo "       initcall_blacklist=algif_aead_init"
    echo "  4. Immediately unload the module if loaded:"
    echo "       sudo rmmod algif_aead"
  elif [ $MITIGATED -eq 1 ]; then
    echo -e "${YEL}  ~ MITIGATED — At least one mitigation is active.${RST}"
    echo "    Still recommended to apply the official kernel patch."
  else
    echo -e "${GRN}  ✓ No obvious vulnerability indicators found.${RST}"
    echo "    Continue to monitor your vendor's security advisories."
  fi
  echo -e "${BLD}============================================================${RST}"
  echo ""
  echo "  References:"
  echo "  - CVE: https://nvd.nist.gov/vuln/detail/CVE-2026-31431"
  echo "  - Writeup: https://xint.io/blog/copy-fail-linux-distributions"
  echo "  - CERT-EU: https://cert.europa.eu/publications/security-advisories/2026-005/"
  echo ""
}

# ── Main ─────────────────────────────────────────────────────
banner
check_privileges
check_kernel
check_module
check_boot_param
check_afalg_socket
check_mac
check_distro_patch
summary
