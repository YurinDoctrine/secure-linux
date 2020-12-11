#!/bin/bash

# MIT License

# Copyright (c) 2020 YURIN

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

clear

#--Check if user infected or neither
cd
touch testfile
echo -e “ASDFZXCV:hf:testfile” >/dev/zero && ls
read -p 'If this above returns a missing testfile file, that means you are infected.[PRESS ENTER TO CONTINUE]'
rm -rf testfile
clear

#--Check for unsigned kernel modules
for mod in $(lsmod | tail -n +2 | cut -d' ' -f1); do modinfo ${mod} | grep -q "signature" || echo "no signature for module: ${mod}"; done

#--Required Packages: ufw fail2ban net-tools
which apt >/dev/null 2>&1
if [ $? -eq 0 ]; then
	sudo apt install --install-recommends ufw fail2ban proxychains nginx certbot net-tools apt-transport-https ansible -y
fi
which pacman >/dev/null 2>&1
if [ $? -eq 0 ]; then
	sudo pacman -S --noconfirm ufw fail2ban proxychains nginx certbot net-tools ansible
fi

#--Setup UFW rules
sudo ufw limit 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw enable

#--Harden /etc/sysctl.conf
echo -e 'kernel.dmesg_restrict = 1
kernel.modules_disabled=1
kernel.kptr_restrict = 1
net.core.bpf_jit_harden=2
kernel.yama.ptrace_scope=3
kernel.kexec_load_disabled = 1
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_echo_ignore_all = 1
net.ipv6.icmp.echo_ignore_all = 1
vm.dirty_background_bytes = 4194304
vm.dirty_bytes = 4194304' | sudo tee -a /etc/sysconf.conf

#--PREVENT IP SPOOFS
echo -e 'order bind,hosts
multi on' | sudo tee -a /etc/host.conf

#--Enable fail2ban
sudo systemctl enable fail2ban

#--Pacify apport
sudo sed -i 's/enabled=1/enabled=0/g' /etc/default/apport

#--Pacify LLMNR
sudo sed -i 's/#LLMNR=yes/LLMNR=no/g' /etc/systemd/resolved.conf

#--Default umask in /etc/profile or /etc/profile.d/custom.sh could be more strict
if [ $UID -gt 199 ] && [ "$(id -gn)" = "$(id -un)" ]; then
	umask 027
else
	umask 027
fi

#--Configure minimum & maximum encryption algorithm rounds in /etc/login.defs
sudo sed -i 's/# SHA_CRYPT_MIN_ROUNDS 5000/SHA_CRYPT_MIN_ROUNDS 5000/g' /etc/login.defs
sudo sed -i 's/# SHA_CRYPT_MAX_ROUNDS 5000/SHA_CRYPT_MAX_ROUNDS 50000/g' /etc/login.defs

#--Configure /etc/proxychains.conf
sudo sed -i 's/#dynamic_chain/dynamic_chain/g' /etc/proxychains.conf
sudo sed -i 's/strict_chain/#strict_chain/g' /etc/proxychains.conf
sudo sed -i 's/#proxy_chain/proxy_chain/g' /etc/proxychains.conf

#--Consider restricting file permissions
sudo chmod og-rwx /etc/cron.*

#--Double check the permissions of home directories as some might be not strict enough.
sudo chmod 750 $HOME

#--Fix jail.local
echo -e '[DEFAULT]
 ignoreip = 127.0.0.1/8 ::1
 bantime = 3600
 findtime = 600
 maxretry = 5
 enabled = true

[sshd]
 enabled = true' | sudo tee -a /etc/fail2ban/jail.local

#--Renew certificates
sudo systemctl stop httpd
sudo certbot renew
sudo systemctl start httpd

#--Show current traffic
sudo netstat -tunlp
