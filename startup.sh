#!/usr/bin/env bash
# =============================================================================
# ubuntu24-initial-setup.sh
# =============================================================================
#
# First-boot hardening for a fresh Ubuntu 24.04 LTS box.
#
# What it does:
#   1. apt update/upgrade everything
#   2. Create a sudo user (you pick the name + password at runtime)
#   3. Lock down SSH (no more root login)
#   4. Turn on UFW — deny inbound except SSH, allow outbound
#   5. fail2ban, auto security updates, sysctl hardening, etc.
#
# How to run:
#   chmod +x ubuntu24-initial-setup.sh
#   ./ubuntu24-initial-setup.sh          # must be root
#
# Heads up:
#   - Don't close your root SSH session until this finishes.
#   - The script asks for credentials at runtime so nothing
#     sensitive ends up in the file. Safe to commit to git.
#   - The very last thing it does is restart sshd, which will
#     boot you out. It pauses and warns you before that happens.
#
# Author: Brent
# Date:   2026-03-31
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

SSH_PORT=22   # bump this if you move SSH to a non-standard port

# -----------------------------------------------------------------------------
# Gotta be root
# -----------------------------------------------------------------------------

if [[ "$(id -u)" -ne 0 ]]; then
    echo "Nope — run this as root." >&2
    exit 1
fi

# Sanity check the OS
if ! grep -q "24.04" /etc/os-release 2>/dev/null; then
    echo "Heads up: this was written for Ubuntu 24.04."
    echo "You're running: $(grep PRETTY_NAME /etc/os-release | cut -d= -f2)"
    read -rp "Keep going anyway? [y/N]: " CONTINUE
    [[ "$CONTINUE" =~ ^[Yy]$ ]] || exit 1
fi

# -----------------------------------------------------------------------------
# Get the username and password up front
# -----------------------------------------------------------------------------

echo ""
echo "==========================================="
echo "  Ubuntu 24.04 — Initial Server Setup"
echo "==========================================="
echo ""

read -rp "Pick a username for your new sudo user: " NEW_USER

if [[ -z "${NEW_USER}" ]]; then
    echo "Username can't be blank." >&2
    exit 1
fi

# Linux username rules: lowercase/digits/hyphens/underscores
if [[ ! "${NEW_USER}" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
    echo "Bad username format. Stick to lowercase letters, numbers, hyphens, underscores." >&2
    exit 1
fi

while true; do
    read -rsp "Password for '${NEW_USER}': " NEW_USER_PASSWORD
    echo ""
    read -rsp "One more time: " NEW_USER_PASSWORD_CONFIRM
    echo ""

    if [[ -z "${NEW_USER_PASSWORD}" ]]; then
        echo "Can't be empty. Try again."
        continue
    fi
    if [[ "${NEW_USER_PASSWORD}" != "${NEW_USER_PASSWORD_CONFIRM}" ]]; then
        echo "Didn't match. Try again."
        continue
    fi
    if [[ ${#NEW_USER_PASSWORD} -lt 8 ]]; then
        echo "Too short — need at least 8 characters. Try again."
        continue
    fi
    break
done

echo ""
echo "  User:     ${NEW_USER}"
echo "  SSH port: ${SSH_PORT}"
echo ""
read -rp "Look good? [Y/n]: " CONFIRM_SETUP
if [[ "${CONFIRM_SETUP}" =~ ^[Nn]$ ]]; then
    echo "Bailed."
    exit 0
fi
echo ""

# =============================================================================
# 1) Update & upgrade
# =============================================================================
# Standard first move on any fresh box. noninteractive keeps apt from
# asking dumb questions mid-run.

echo "--- [1/11] Updating and upgrading packages..."

export DEBIAN_FRONTEND=noninteractive

apt-get update -y
apt-get upgrade -y
apt-get dist-upgrade -y
apt-get autoremove -y
apt-get autoclean -y

echo "    Done."
echo ""

# =============================================================================
# 2) Install the stuff we need
# =============================================================================
# Some of these might already be there, but minimal cloud images skip a lot.
# fail2ban and ufw are the important ones for security. The rest is just
# stuff you'll want eventually anyway.

echo "--- [2/11] Installing packages..."

apt-get install -y \
    ufw \
    fail2ban \
    unattended-upgrades \
    apt-listchanges \
    logwatch \
    curl \
    wget \
    git \
    net-tools \
    sudo

echo "    Done."
echo ""

# =============================================================================
# 3) Create the sudo user
# =============================================================================

echo "--- [3/11] Creating user '${NEW_USER}'..."

if id "${NEW_USER}" &>/dev/null; then
    echo "    Already exists — skipping."
else
    useradd --create-home --shell /bin/bash --groups sudo "${NEW_USER}"
    echo "${NEW_USER}:${NEW_USER_PASSWORD}" | chpasswd
    echo "    Created."
fi

# Make sure sudo actually stuck
if groups "${NEW_USER}" | grep -qw sudo; then
    echo "    Confirmed in sudo group."
else
    echo "    Something went wrong — user isn't in sudo. Bailing." >&2
    exit 1
fi
echo ""

# =============================================================================
# 4) Harden SSH
# =============================================================================
# Kill root login, tighten timeouts, disable stuff we don't need.
# The actual sshd restart happens at the very end (step 11) so we don't
# nuke this session before everything else finishes.

echo "--- [4/11] Hardening SSH config..."

SSHD_CONFIG="/etc/ssh/sshd_config"

# back up the original, just in case
cp "${SSHD_CONFIG}" "${SSHD_CONFIG}.bak.$(date +%Y%m%d%H%M%S)"

# helper to set a value (replaces existing line or appends if missing)
sshd_set() {
    local key="$1" value="$2"
    if grep -qE "^\s*#?\s*${key}\s" "${SSHD_CONFIG}"; then
        sed -i "s|^\s*#\?\s*${key}\s.*|${key} ${value}|" "${SSHD_CONFIG}"
    else
        echo "${key} ${value}" >> "${SSHD_CONFIG}"
    fi
}

sshd_set "PermitRootLogin"        "no"
sshd_set "PasswordAuthentication" "yes"    # leave on until you set up SSH keys
sshd_set "PermitEmptyPasswords"   "no"
sshd_set "MaxAuthTries"           "4"
sshd_set "LoginGraceTime"         "30"
sshd_set "X11Forwarding"          "no"
sshd_set "ClientAliveInterval"    "300"
sshd_set "ClientAliveCountMax"    "2"

# validate syntax now, restart later
if sshd -t; then
    echo "    Config looks good. (sshd restart deferred to the end.)"
else
    echo "    sshd config test failed — restoring backup." >&2
    cp "${SSHD_CONFIG}.bak."* "${SSHD_CONFIG}" 2>/dev/null
    exit 1
fi
echo ""

# =============================================================================
# 5) Firewall (UFW)
# =============================================================================
# Deny everything inbound except SSH. Allow all outbound — trying to
# whitelist outbound on a general-purpose box is a nightmare (apt, DNS,
# NTP, HTTPS APIs, etc.) and the real threat surface is inbound anyway.
# You can always tighten outbound later if you need to.

echo "--- [5/11] Setting up UFW..."

ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow "${SSH_PORT}/tcp" comment "SSH"
ufw --force enable

echo ""
ufw status verbose
echo ""
echo "    Firewall is up."
echo ""

# =============================================================================
# 6) fail2ban
# =============================================================================
# Watches SSH auth logs, bans IPs after too many failed attempts.
# We write a jail.local so our settings survive package upgrades
# (jail.conf gets overwritten, jail.local doesn't).

echo "--- [6/11] Configuring fail2ban..."

cat > /etc/fail2ban/jail.local << 'EOF'
# jail.local — local overrides, won't get clobbered by apt

[DEFAULT]
bantime  = 1800    # 30 min ban
findtime = 600     # ...after failures within 10 min
maxretry = 4

backend = systemd

[sshd]
enabled  = true
port     = ssh
filter   = sshd
logpath  = %(sshd_log)s
maxretry = 4
EOF

systemctl enable fail2ban
systemctl restart fail2ban

echo "    fail2ban running. 4 strikes and you're out for 30 min."
echo ""

# =============================================================================
# 7) Automatic security updates
# =============================================================================
# Probably the single most useful thing on a box you're not watching 24/7.
# This pulls and installs security patches every day automatically.

echo "--- [7/11] Enabling auto security updates..."

cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
EOF

systemctl enable unattended-upgrades
systemctl restart unattended-upgrades

echo "    Security patches will auto-install daily."
echo ""

# =============================================================================
# 8) Kernel / sysctl hardening
# =============================================================================
# Bog-standard CIS benchmark stuff. Protects against spoofing, ICMP
# redirect tricks, SYN floods, etc. None of this is exotic — it's just
# not on by default for some reason.

echo "--- [8/11] Applying sysctl network hardening..."

cat > /etc/sysctl.d/99-server-hardening.conf << 'EOF'
# Reverse path filtering (anti-spoofing)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Don't let outsiders tell us how to route packets
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Ignore ICMP redirects (MITM prevention)
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0

# Ignore broadcast pings (smurf attacks)
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Log martian packets so you can see weird stuff in the logs
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# SYN flood protection
net.ipv4.tcp_syncookies = 1

# Uncomment these if you're not using IPv6 at all:
# net.ipv6.conf.all.disable_ipv6 = 1
# net.ipv6.conf.default.disable_ipv6 = 1
EOF

sysctl --system > /dev/null 2>&1

echo "    Done."
echo ""

# =============================================================================
# 9) Timezone + NTP
# =============================================================================
# Accurate time matters more than you'd think — log timestamps, TLS certs,
# fail2ban timing, cron jobs. Setting to Eastern for Virginia.

echo "--- [9/11] Setting timezone and NTP..."

timedatectl set-timezone America/New_York
timedatectl set-ntp on

echo "    Timezone: America/New_York, NTP on."
echo ""

# =============================================================================
# 10) Lock down home directory permissions
# =============================================================================
# Ubuntu defaults let users browse each other's home dirs. No thanks.

echo "--- [10/11] Restricting /home/${NEW_USER} to owner-only..."

chmod 700 "/home/${NEW_USER}"

echo "    Done."
echo ""

# =============================================================================
# All done (except the sshd restart). Print the summary while the user
# can still see it — once sshd restarts, this session is toast.
# =============================================================================

echo ""
echo "==========================================="
echo "  All set. Here's what happened:"
echo "==========================================="
echo ""
echo "  User ................... ${NEW_USER} (has sudo)"
echo "  SSH root login ......... about to be disabled"
echo "  SSH port ............... ${SSH_PORT}"
echo "  Firewall ............... on (inbound: deny all except SSH)"
echo "  fail2ban ............... on (4 fails = 30 min ban)"
echo "  Auto security updates .. on (daily)"
echo "  Kernel hardening ....... applied"
echo "  Timezone ............... $(timedatectl show -p Timezone --value)"
echo ""
echo "==========================================="
echo "  What to do next (read this before you"
echo "  hit Enter — this window is about to die)"
echo "==========================================="
echo ""
echo "  1. Open a SECOND terminal and make sure you can get in:"
echo "       ssh ${NEW_USER}@<your-server-ip>"
echo ""
echo "  2. Test that sudo works:"
echo "       sudo whoami    # should say 'root'"
echo ""
echo "  3. Strongly recommended — set up SSH keys so you can"
echo "     ditch password auth entirely:"
echo "       # from your local machine:"
echo "       ssh-keygen -t ed25519"
echo "       ssh-copy-id ${NEW_USER}@<your-server-ip>"
echo ""
echo "       # then on the server:"
echo "       sudo sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config"
echo "       sudo systemctl restart sshd"
echo ""
echo "  4. Later, when you need to open more ports:"
echo "       sudo ufw allow 80/tcp comment 'HTTP'"
echo "       sudo ufw allow 443/tcp comment 'HTTPS'"
echo ""
echo "==========================================="
echo ""

# =============================================================================
# 11) Restart sshd — point of no return
# =============================================================================
# Everything above is done. Restarting sshd applies PermitRootLogin=no,
# which means this root session is about to get kicked. Pausing here so
# you have time to actually read the stuff above.

echo "--- [11/11] Ready to restart sshd and lock out root."
echo ""
echo "    This WILL kill your current session."
echo ""
read -rp "    Hit Enter when you're ready... "

systemctl restart sshd

# You'll probably never see this, but just in case (e.g., running from console):
echo ""
echo "    sshd restarted. Root login is disabled. You're good."
