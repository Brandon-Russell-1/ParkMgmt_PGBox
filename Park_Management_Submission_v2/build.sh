#!/usr/bin/env bash
set -e

#
# Note: It is assumed that the build script will be run as the root user.
#

echo "[+] Building Park Management"
echo "[+] OS: Ubuntu Server 20.04.06 LTS"
echo "[+] Author: Brandon Russell"
echo "[+] Date: 2024-05-06"
echo "[+] Point Value: 5"

echo "[+] Installing utilities"
apt install -y net-tools open-vm-tools

echo "[+] Configuring first vector"
echo "[+] Installing Apache, PHP, ZipArchive, Apache mod_rewrite, Curl, and GD Library"
apt install -y apache2 libapache2-mod-php php-xml php-curl php-gd php-zip
a2enmod rewrite

echo "[+] Creating vulnerable website"
rm -rf /var/www/html/index.html
tar -xvzf getsimplecms.tar.gz --directory /var/www/html
chmod -R 777 /var/www/html

echo "[+] Enabling Apache"
systemctl enable apache2
systemctl start apache2

echo "[+] Configuring second vector"

echo "[+] Creating users if they don't already exist"
id -u brandon &>/dev/null || useradd -m brandon
adduser brandon sudo

echo "[+] Copying password protected zip file into home directory"
cp parklogs.zip /home/brandon/

echo "[+] Configuring firewall"
echo "[+] Installing iptables"
echo "iptables-persistent iptables-persistent/autosave_v4 boolean false" | debconf-set-selections
echo "iptables-persistent iptables-persistent/autosave_v6 boolean false" | debconf-set-selections
apt install -y iptables-persistent

#
# Note: Unless specifically required as part of the exploitation path, please
#       ensure that inbound ICMP and SSH on port 22 are permitted.
#

echo "[+] Applying inbound firewall rules"
iptables -I INPUT 1 -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp --dport 8000 -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT
iptables -A INPUT -j DROP

#
# Note: Unless specifically required as part of the exploitation path, please
#       ensure that outbound ICMP, DNS (TCP & UDP) on port 53 and SSH on port 22
#       are permitted.
#

echo "[+] Applying outbound firewall rules"
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -p tcp --sport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p udp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --dport 8000 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 8000 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT
iptables -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT
iptables -A OUTPUT -j DROP

echo "[+] Saving firewall rules"
apt install -y netfilter-persistent
service netfilter-persistent save

echo "[+] Disabling IPv6"
echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT=""/GRUB_CMDLINE_LINUX_DEFAULT="ipv6.disable=1"/' /etc/default/grub
sed -i 's/GRUB_CMDLINE_LINUX=""/GRUB_CMDLINE_LINUX="ipv6.disable=1"/' /etc/default/grub
update-grub


echo "[+] Configuring hostname"
hostnamectl set-hostname parkmanagement
cat << EOF > /etc/hosts
127.0.0.1 localhost
127.0.0.1 parkmanagement
EOF


#
# Note: Unless specifically required as part of the exploitation path, please
#       ensure that root login via SSH is permitted.
#

echo "[+] Enabling root SSH login"
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

echo "[+] Setting passwords"
echo "root:AGreatDaytobeaParkRangerMay2023" | chpasswd
echo "brandon:ILoveParkandRecreation2024" | chpasswd

echo "[+] Dropping flags"
echo "3f56c60fd4f0315a4de12a8870f6f2d7" > /root/proof.txt
echo "d76e00fe6ea1d81112622c6bd1cb88ce" > /home/brandon/local.txt
chmod 0700 /root/proof.txt
chmod 0644 /home/brandon/local.txt
chown brandon:brandon /home/brandon/local.txt 

#
# Note: Please ensure that any artefacts and log files created by the build script or
#       while running the build script are removed afterwards.
#

echo "[+] Cleaning up"
rm -rf /root/build.sh
rm -rf /root/getsimplecms.tar.gz
rm -rf /root/parklogs.zip
rm -rf /root/.cache
rm -rf /root/.viminfo
rm -rf /home/brandon/.sudo_as_admin_successful
rm -rf /home/brandon/.cache
rm -rf /home/brandon/.viminfo
find /var/log -type f -exec sh -c "cat /dev/null > {}" \;

echo "[+] Disabling history files"
cat /dev/null > /home/brandon/.bash_history && history -c && exit
cat /dev/null > /root/.bash_history && history -c && init 0