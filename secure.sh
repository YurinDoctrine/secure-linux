#!/usr/bin/env bash

# MIT License

# Copyright (c) 2020-2021 YURIN

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

#--Required Packages: ufw fail2ban net-tools
which apt >/dev/null 2>&1
if [ $? -eq 0 ]; then
    sudo apt update &&
        sudo apt install -f --assume-yes --no-install-recommends openssl ufw fail2ban net-tools unattended-upgrades proxychains ca-certificates certbot
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
        yay -S --needed --noconfirm openssl ufw fail2ban net-tools proxychains ca-certificates certbot
fi

clear

#--Setup UFW rules
sudo ufw --force enable
sudo ufw limit 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow in on lo
sudo ufw allow out on lo
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw reload

#--Harden /etc/sysctl
echo -e "net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.tcp_mtu_probing=1" | sudo tee -a /etc/sysctl.d/99-swappiness.conf
sudo sysctl -a
sudo sysctl -A
sudo sysctl -a --pattern 'net.ipv4.conf.(eth|wlan)0.arp'

#--PREVENT IP SPOOFS
echo -e "order bind,hosts
multi on" | sudo tee -a /etc/host.conf

#--Pacify LLMNR
sudo sed -i -e 's/#LLMNR=yes/LLMNR=no/g' /etc/systemd/resolved.conf

#--Default umask in /etc/profile or /etc/profile.d/custom.sh could be more strict
if [ $UID -gt 199 ] && [ "$(id -gn)" = "$(id -un)" ]; then
    umask 027
else
    umask 027
fi

#--Configure minimum & maximum encryption algorithm rounds in /etc/login.defs
sudo sed -i -e 's/# SHA_CRYPT_MIN_ROUNDS 5000/SHA_CRYPT_MIN_ROUNDS 5000/g' /etc/login.defs
sudo sed -i -e 's/# SHA_CRYPT_MAX_ROUNDS 5000/SHA_CRYPT_MAX_ROUNDS 50000/g' /etc/login.defs

#--Configure /etc/proxychains.conf
sudo sed -i -e 's/#dynamic_chain/dynamic_chain/g' /etc/proxychains.conf
sudo sed -i -e 's/strict_chain/#strict_chain/g' /etc/proxychains.conf
sudo sed -i -e 's/#proxy_chain/proxy_chain/g' /etc/proxychains.conf

#--Consider restricting file permissions
sudo chmod og-rwx /etc/cron.*

#--Double check the permissions of home directories as some might be not strict enough.
sudo chmod 0750 /home/*

#--Remove no password sudo rights
sudo sed -i -e 's/^%wheel ALL=(ALL) NOPASSWD: ALL/# %wheel ALL=(ALL) NOPASSWD: ALL/' /etc/sudoers

#--Fix jail.local
echo -e "[DEFAULT]
 ignoreip = 127.0.0.1/8 ::1
 bantime = 3600
 findtime = 600
 maxretry = 5
 enabled = true

[sshd]
 enabled = true" | sudo tee /etc/fail2ban/jail.local

#--Renew certificates
sudo killall -9 httpd
sudo certbot renew
sudo killall -HUP httpd

#--Harden host
sudo chmod 644 /etc/hosts.allow
sudo chmod 644 /etc/hosts.deny

#--Mask apparmor
sudo systemctl mask apparmor >/dev/null 2>&1

#--Clean the logs
sudo rm -rfd ~/.bash_history /var/log/*

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
