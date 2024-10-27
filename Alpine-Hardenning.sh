#!/bin/sh
# This script is meant to be run as root
if [[ "${UID}" -ne 0 ]]; then
    echo " You need to run this script as root"
    exit 1
fi

# Update packages
apk update
apk upgrade

# Install security tools
apk add audit doas logrotate bash-completion openssh-server shadow

# Create non root user
adduser -G wheel quentin

# Setup doas
echo "permit persist :wheel" >> /etc/doas.d/doas.conf

# Setup sshd
sed -i 's/#\?\(PermitRootLogin\s*\).*$/\1no/' /etc/ssh/sshd_config
sed -i 's/#\?\(PubkeyAuthentication\s*\).*$/\1yes/' /etc/ssh/sshd_config
sed -i 's/#\?\(PermitEmptyPasswords\s*\).*$/\1no/' /etc/ssh/sshd_config
sed -i 's/#\?\(PasswordAuthentication\s*\).*$/\1no/' /etc/ssh/sshd_config
rc-service sshd restart 

# Migrate AutorizedKeys file
mkdir /home/quentin/.ssh/
cp /root/.ssh/authorized_keys /home/quentin/.ssh/
chown -R quentin /home/quentin/.ssh/

# Lock unused system accounts
for user in `awk -F: '($3 < 1000) {print $1}' /etc/passwd`; do
    if [ $user != "root" ]; then
        passwd -l $user
        chage -E 0 $user
    fi
done

# Set appropriate permissions on important directories
chmod 700 /root
chmod 600 /boot/grub/grub.cfg
chmod 600 /etc/ssh/sshd_config

# Disable unused filesystems
cat << EOF >> /etc/modprobe.d/disable-filesystems.conf
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
install vfat /bin/true
EOF

# Configure kernel parameters
cat << EOF >> /etc/sysctl.conf
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
EOF

# Set up auto updates
cat << EOF >> /etc/crontabs/root
# auto updates
0 2 * * * apk update && apk upgrade
EOF

# Review and monitor logs regularly
logrotate /etc/logrotate.conf