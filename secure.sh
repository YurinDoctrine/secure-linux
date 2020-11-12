#!/bin/bash
clear

#--Check if user infected or neither
cd
touch testfile
echo “ASDFZXCV:hf:testfile” >/dev/zero && ls
echo "if this above returns a missing testfile file, that means you're infected(Press ANY KEY)."
read -p '>: '
rm -rf testfile
clear

#--Check for unsigned kernel modules
for mod in $(lsmod | tail -n +2 | cut -d' ' -f1); do modinfo ${mod} | grep -q "signature" || echo "no signature for module: ${mod}"; done

#--Required Packages: ufw fail2ban net-tools
sudo apt install --install-recommends ufw fail2ban nginx certbot net-tools apt-transport-https ansible -y

#--Setup UFW rules
sudo ufw limit 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw enable

#--Harden /etc/sysctl.conf
sudo printf "kernel.dmesg_restrict = 1
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
vm.dirty_bytes = 4194304" >/etc/sysconf.conf

#--PREVENT IP SPOOFS
sudo cat <<EOF >/etc/host.conf
order bind,hosts
multi on
EOF

#--Enable fail2ban
sudo cp fail2ban.local /etc/fail2ban/
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

#--Pacify apport
sudo sed -i 's/enabled=1/enabled=0/g' /etc/default/apport

#--Pacify LLMNR
sudo sed -i 's/#LLMNR=yes/LLMNR=no/g' /etc/systemd/resolved.conf

#--Default umask in /etc/profile or /etc/profile.d/custom.sh could be more strict
if [ $UID -gt 199 ] && [ "`id -gn`" = "`id -un`" ]; then
    umask 027
else
    umask 027
fi

#--Configure minimum & maximum encryption algorithm rounds in /etc/login.defs
sudo sed -i 's/# SHA_CRYPT_MIN_ROUNDS 5000/SHA_CRYPT_MIN_ROUNDS 5000/g' /etc/login.defs
sudo sed -i 's/# SHA_CRYPT_MAX_ROUNDS 5000/SHA_CRYPT_MAX_ROUNDS 50000/g' /etc/login.defs

#--Harden compilers like restricting access to root user only
sudo chmod o-rx /usr/bin/gcc
sudo chmod o-rx /usr/bin/as

#--Copy /etc/fail2ban/jail.conf to jail.local to prevent it being changed by updates
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

#--Consider restricting file permissions
sudo chmod og-rwx /etc/cron.*

#--Double check the permissions of home directories as some might be not strict enough.
chmod 750 /home/$USER

#--Fix jail.local
sudo cat <<EOF >/etc/fail2ban/jail.local
[DEFAULT]
 ignoreip = 127.0.0.1/8 ::1
 bantime = 3600
 findtime = 600
 maxretry = 5
 enabled = true

[sshd]
 enabled = true
EOF

#--Renew certificates
sudo systemctl stop mini-httpd.service
sudo certbot renew
sudo systemctl start mini-httpd.service

#--Listen current traffic
echo "listening ports"
sudo netstat -tunlp
