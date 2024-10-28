#!/bin/sh
# Based on https://wiki.alpinelinux.org/wiki/Securing_Alpine_Linux
# This script is meant to be run as root
if [ "${UID}" -ne 0 ]; then
    echo " You need to run this script as root"
    exit 1
fi

# Ask username to the user to create a non-root user
echo -n 'Username for the non-root user : '
read non_root_user
echo "You choosed to name the non-root user $non_root_user"

# Create non root user
addgroup $non_root_user
adduser -G $non_root_user $non_root_user
addgroup -S $non_root_user wheel

# Setup doas 
if ! grep -q "permit persist :wheel" /etc/doas.d/doas.conf; then
    echo "permit persist :wheel" >> /etc/doas.d/doas.conf
fi

# Migrate AutorizedKeys file
mkdir /home/$non_root_user/.ssh/
cp /root/.ssh/authorized_keys /home/$non_root_user/.ssh/
chown -R $non_root_user /home/$non_root_user/.ssh/

# Update package list and upgrade all packages
apk update
apk upgrade

# Install security tools
apk add audit doas logrotate bash-completion openssh-server shadow

# Setup sshd
sed -i 's/#\?\(PermitRootLogin\s*\).*$/\1no/' /etc/ssh/sshd_config
sed -i 's/#\?\(PubkeyAuthentication\s*\).*$/\1yes/' /etc/ssh/sshd_config
sed -i 's/#\?\(PermitEmptyPasswords\s*\).*$/\1no/' /etc/ssh/sshd_config
sed -i 's/#\?\(PasswordAuthentication\s*\).*$/\1no/' /etc/ssh/sshd_config
rc-service sshd restart 

# Ensure password complexity
if ! grep -q "minlen = 14" /etc/security/pwquality.conf; then
    echo "minlen = 14" >> /etc/security/pwquality.conf
fi

if ! grep -q "dcredit = -1" /etc/security/pwquality.conf; then
    echo "dcredit = -1" >> /etc/security/pwquality.conf
fi

if ! grep -q "ucredit = -1" /etc/security/pwquality.conf; then
    echo "ucredit = -1" >> /etc/security/pwquality.conf
fi

if ! grep -q "ocredit = -1" /etc/security/pwquality.conf; then
    echo "ocredit = -1" >> /etc/security/pwquality.conf
fi

if ! grep -q "lcredit = -1" /etc/security/pwquality.conf; then
    echo "lcredit = -1" >> /etc/security/pwquality.conf
fi

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
if ! grep -q "install cramfs /bin/true" /etc/modprobe.d/disable-filesystems.conf; then
    echo "install cramfs /bin/true" >> /etc/modprobe.d/disable-filesystems.conf
fi

if ! grep -q "install freevxfs /bin/true" /etc/modprobe.d/disable-filesystems.conf; then
    echo "install freevxfs /bin/true" >> /etc/modprobe.d/disable-filesystems.conf
fi

if ! grep -q "install jffs2 /bin/true" /etc/modprobe.d/disable-filesystems.conf; then
    echo "install jffs2 /bin/true" >> /etc/modprobe.d/disable-filesystems.conf
fi

if ! grep -q "install hfs /bin/true" /etc/modprobe.d/disable-filesystems.conf; then
    echo "install hfs /bin/true" >> /etc/modprobe.d/disable-filesystems.conf
fi

if ! grep -q "install hfsplus /bin/true" /etc/modprobe.d/disable-filesystems.conf; then
    echo "install hfsplus /bin/true" >> /etc/modprobe.d/disable-filesystems.conf
fi

if ! grep -q "install squashfs /bin/true" /etc/modprobe.d/disable-filesystems.conf; then
    echo "install squashfs /bin/true" >> /etc/modprobe.d/disable-filesystems.conf
fi

if ! grep -q "install udf /bin/true" /etc/modprobe.d/disable-filesystems.conf; then
    echo "install udf /bin/true" >> /etc/modprobe.d/disable-filesystems.conf
fi

if ! grep -q "install vfat /bin/true" /etc/modprobe.d/disable-filesystems.conf; then
    echo "install vfat /bin/true" >> /etc/modprobe.d/disable-filesystems.conf
fi

# Configure kernel parameters
if ! grep -q "net.ipv6.conf.all.disable_ipv6 = 1" /etc/sysctl.conf; then
    echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
fi

if ! grep -q "net.ipv4.ip_forward = 0" /etc/sysctl.conf; then
    echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf
fi

if ! grep -q "net.ipv4.conf.all.accept_source_route = 0" /etc/sysctl.conf; then
    echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
fi

if ! grep -q "net.ipv4.conf.all.accept_redirects = 0" /etc/sysctl.conf; then
    echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
fi

if ! grep -q "net.ipv4.conf.all.secure_redirects = 0" /etc/sysctl.conf; then
    echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf
fi

if ! grep -q "net.ipv4.conf.all.log_martians = 1" /etc/sysctl.conf; then
    echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
fi

if ! grep -q "net.ipv4.conf.default.log_martians = 1" /etc/sysctl.conf; then
    echo "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.conf
fi

if ! grep -q "net.ipv4.icmp_echo_ignore_broadcasts = 1" /etc/sysctl.conf; then
    echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
fi

if ! grep -q "net.ipv4.icmp_ignore_bogus_error_responses = 1" /etc/sysctl.conf; then
    echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf
fi

if ! grep -q "net.ipv4.tcp_syncookies = 1" /etc/sysctl.conf; then
    echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
fi

if ! grep -q "net.ipv4.conf.all.send_redirects = 0" /etc/sysctl.conf; then
    echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
fi

if ! grep -q "net.ipv4.conf.default.send_redirects = 0" /etc/sysctl.conf; then
    echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
fi

# Set up auto updates
if ! grep -q "apk update && apk upgrade" /etc/crontabs/root; then
    echo "# auto updates" >> /etc/crontabs/root
    echo "0 2 * * * apk update && apk upgrade" >> /etc/crontabs/root
fi

# Review and monitor logs regularly
logrotate /etc/logrotate.conf