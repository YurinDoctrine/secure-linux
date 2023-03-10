#!/usr/bin/env bash

# MIT License

# Copyright (c) 2020-2023 Yurin Doctrine

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

#--Required Packages: openssl earlyoom ufw fail2ban net-tools certbot iwd gnutls
which apt >/dev/null 2>&1
if [ $? -eq 0 ]; then
    sudo apt update &&
        sudo apt install -f --assume-yes --install-recommends doas
    sudo apt install -f --assume-yes --install-recommends openssl earlyoom ufw fail2ban gnome-keyring libsecret-1-0 libpam-gnome-keyring net-tools unattended-upgrades proxychains ca-certificates certbot anacron cryptsetup iwd gnutls-bin libpipeline-dev gpm xfonts-terminus usbguard clamav firejail lynis
    echo -e 'APT::Periodic::Unattended-Upgrade "1";' | sudo tee /etc/apt/apt.conf.d/50unattended-upgrades
    echo -e 'APT::Periodic::AutocleanInterval "7";' | sudo tee -a /etc/apt/apt.conf.d/50unattended-upgrades
    echo -e 'APT::Periodic::Download-Upgradeable-Packages "1";' | sudo tee -a /etc/apt/apt.conf.d/50unattended-upgrades
    echo -e 'APT::Periodic::Update-Package-Lists "1";' | sudo tee -a /etc/apt/apt.conf.d/50unattended-upgrades
    echo -e 'Unattended-Upgrade::Remove-Unused-Dependencies "true";' | sudo tee -a /etc/apt/apt.conf.d/50unattended-upgrades
    echo -e 'Unattended-Upgrade::AutoFixInterruptedDpkg "true";' | sudo tee -a /etc/apt/apt.conf.d/50unattended-upgrades
    echo -e 'Unattended-Upgrade::MinimalSteps "true";' | sudo tee -a /etc/apt/apt.conf.d/50unattended-upgrades
    sudo dpkg-reconfigure -f noninteractive unattended-upgrades
fi
which pacman >/dev/null 2>&1
if [ $? -eq 0 ]; then
    sudo pacman -Syy &&
        yay -S --needed --noconfirm openssl earlyoom ufw fail2ban gnome-keyring libsecret libgnome-keyring net-tools proxychains ca-certificates certbot doas cronie cryptsetup iwd gnutls libpipeline gpm terminus-font usbguard clamav firejail lynis
fi
which dnf >/dev/null 2>&1
if [ $? -eq 0 ]; then
    sudo dnf check-update
    sudo dnf install openssl earlyoom ufw fail2ban gnome-keyring libsecret libgnome-keyring net-tools proxychains-ng ca-certificates certbot doas cronie cryptsetup iwd gnutls libpipeline gpm terminus-fonts usbguard clamav firejail lynis -y
fi

#--Update firmware
sudo fwupdmgr get-devices
sudo fwupdmgr refresh --force
sudo fwupdmgr get-updates -y
sudo fwupdmgr update -y

clear

echo -e "Configuring vconsole.conf to set a larger font for login shell"
echo -e "FONT=ter-v22b
FONT_MAP=8859-2" | sudo tee /etc/vconsole.conf

#--Setup UFW rules
sudo ufw --force enable
sudo ufw limit 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow in on lo
sudo ufw allow out on lo
sudo systemctl enable --now ufw

#--Harden sysctl configs
echo -e "fs.file-max=100000
net.ipv6.conf.default.disable_ipv6=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.all.arp_evict_nocarrier=1
net.ipv4.conf.all.arp_ignore=1
net.ipv4.conf.all.log_martians=0
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_orphan_retries=2
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_abort_on_overflow=1
net.ipv4.tcp_tw_recycle=1
net.ipv4.tcp_retries2=5
net.ipv4.tcp_syn_retries=5
net.ipv4.tcp_fin_timeout=15
net.ipv4.tcp_fack=0
net.ipv4.tcp_dsack=0
net.ipv4.tcp_sack=0
net.ipv4.tcp_workaround_signed_windows=1
net.ipv4.tcp_ecn_fallback=0
net.ipv4.tcp_app_win=0
net.ipv4.tcp_thin_linear_timeouts=1
net.ipv4.tcp_rfc1337=1
net.ipv4.tcp_adv_win_scale=1
net.ipv4.udp_rmem_min=8192
net.ipv4.udp_wmem_min=8192
net.ipv4.udp_early_demux=1
net.ipv4.icmp_echo_ignore_all=1
net.ipv4.route.flush=1
net.ipv4.ipfrag_time=0
net.ipv4.ipfrag_secret_interval=0
net.core.default_qdisc=fq_pie
net.core.busy_read=50
net.core.high_order_alloc_disable=0
net.core.warnings=0
net.core.tstamp_allow_data=1" | sudo tee -a /etc/sysctl.d/99-swappiness.conf
sudo sysctl -p --system

#--PREVENT IP SPOOFS
echo -e "order bind,hosts
multi on" | sudo tee /etc/host.conf

#--Pacify LLMNR
sudo sed -i -e 's/#LLMNR=yes/LLMNR=no/g' /etc/systemd/resolved.conf

#--Default umask in /etc/profile or /etc/profile.d/custom.sh could be more strict
if [ $UID -gt 199 ] && [ "$(id -gn)" = "$(id -un)" ]; then
    umask 027
else
    umask 027
fi
echo -e "umask 027" | sudo tee /etc/profile.d/umask.sh

#--Configure minimum & maximum encryption algorithm rounds in /etc/login.defs
sudo sed -i -e 's/# SHA_CRYPT_MIN_ROUNDS 5000/SHA_CRYPT_MIN_ROUNDS 5000/g' /etc/login.defs
sudo sed -i -e 's/# SHA_CRYPT_MAX_ROUNDS 5000/SHA_CRYPT_MAX_ROUNDS 50000/g' /etc/login.defs

#--Configure /etc/proxychains.conf
sudo sed -i -e 's/#dynamic_chain/dynamic_chain/g' /etc/proxychains.conf
sudo sed -i -e 's/strict_chain/#strict_chain/g' /etc/proxychains.conf
sudo sed -i -e 's/#proxy_chain/proxy_chain/g' /etc/proxychains.conf

#--Harden system files
sudo chmod -R 0700 /root
sudo chmod -R 0700 /boot /etc/{iptables,arptables,nftables}
sudo chown root:root /boot/grub/grub.cfg
sudo chmod og-rwx /boot/grub/grub.cfg
#--Double check the permissions of home directories as some might be not strict enough.
sudo chmod -R 0750 /home/*

#--Remove no password sudo rights
sudo sed -i -e 's/^%wheel ALL=(ALL) NOPASSWD: ALL/# %wheel ALL=(ALL) NOPASSWD: ALL/' /etc/sudoers

#--Disable crashes
sudo sed -i -e 's/^#DumpCore=.*/DumpCore=no/' /etc/systemd/system.conf
sudo sed -i -e 's/^#CrashShell=.*/CrashShell=no/' /etc/systemd/system.conf
sudo sed -i -e 's/^#DumpCore=.*/DumpCore=no/' /etc/systemd/user.conf
sudo sed -i -e 's/^#CrashShell=.*/CrashShell=no/' /etc/systemd/user.conf

#--Fix jail.local
echo -e "[DEFAULT]
 ignoreip = 127.0.0.1/8 ::1
 bantime = 3600
 findtime = 600
 maxretry = 5
 enabled = true

[sshd]
 enabled = true" | sudo tee /etc/fail2ban/jail.local
sudo systemctl enable --now fail2ban

#--Renew certificates
sudo killall -9 httpd
sudo certbot renew
sudo killall -HUP httpd

#--Harden hosts
sudo chmod -R 0644 /etc/hosts.allow
sudo chmod -R 0644 /etc/hosts.deny

#--Limit PAM
echo -e "session required pam_limits.so" | sudo tee -a /etc/pam.d/common-session
echo -e "session required pam_limits.so" | sudo tee -a /etc/pam.d/common-session-noninteractive
echo -e "auth optional pam_faildelay.so delay=5000000" | sudo tee -a /etc/pam.d/system-login

#--Reveal boot messages
sudo sed -i -e 's/^TTYVTDisallocate=yes/TTYVTDisallocate=no/' /etc/systemd/system/getty.target.wants/getty@tty1.service

#--Disable cron
sudo systemctl mask cron.service

#--Enable MAC address randomization in NetworkManager
echo -e "[device]
wifi.scan-rand-mac-address=yes
[connection]
wifi.cloned-mac-address=random
ethernet.cloned-mac-address=random" | sudo tee /etc/NetworkManager/conf.d/mac-address-randomization.conf
#--Prevent NetworkManager handling resolv.conf
echo -e "[main]
dns=none
rc-manager=unmanaged" | sudo tee /etc/NetworkManager/conf.d/prevent-nm-handle-dns.conf
#--Disable transient hostname in NetworkManager
echo -e "[main]
hostname-mode=none" | sudo tee /etc/NetworkManager/conf.d/transient-hostname.conf
sudo hostnamectl --transient hostname ""
sudo hostnamectl hostname "localhost"
sudo service NetworkManager restart
sudo hostnamectl set-hostname localhost

#--Secure dns
if [[ -z $(grep "nameserver" /etc/resolv.conf) ]]; then
    echo -e "nameserver 9.9.9.11
nameserver 149.112.112.11
nameserver 127.0.0.1" | sudo tee -a /etc/resolv.conf
else
    sudo sed -i -e 's/^nameserver .*/nameserver 9.9.9.11/' /etc/resolv.conf
fi
echo -e "options rotate timeout:1 attempts:3 single-request-reopen no-tld-query" | sudo tee -a /etc/resolv.conf

#--Disable NTP
sudo timedatectl set-ntp 0
sudo systemctl mask systemd-timesyncd.service

#--Disable Netfilter connection tracking helper
echo -e "options nf_conntrack nf_conntrack_helper=0" | sudo tee /etc/modprobe.d/no-conntrack-helper.conf

#--Update CA certificates
sudo update-ca-trust

#--Clear the footprints
sudo rm -rfd /root/.cache ~/.bash_history ~/.sudo_as_admin_successful ~/.bash_logout /var/lib/systemd/random-seed /var/log/{.*,*} /var/backups/{.*,*} &> /dev/null
sudo rm -rfd /home/*/.local/share/Trash/*/** &> /dev/null
sudo rm -rfd /root/.local/share/Trash/*/** &> /dev/null

extra() {
    cd /tmp
    curl --tlsv1.2 -fsSL https://raw.githubusercontent.com/YurinDoctrine/pentest-base-popular/main/pentest-base-popular.sh >pentest-base-popular.sh &&
        chmod 0755 pentest-base-popular.sh &&
        ./pentest-base-popular.sh
}

final() {

    sleep 0.2 && clear
    echo -e "
###############################################################################
# All Done! Would you also mind to run the author's pentest-base-popular?
###############################################################################
"

    read -p $'yes/no >_: ' noc
    if [[ "$noc" == "yes" ]]; then
        echo -e "RUNNING ..."
        extra
    elif [[ "$noc" == "no" ]]; then
        echo -e "LEAVING ..."
        exit 0
    else
        echo -e "INVALID VALUE!"
        final
    fi
}
final
