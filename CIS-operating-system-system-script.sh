#!/bin/sh

sudo su

### Initial installations
yum update
yum -y install policycoreutils-python
semanage port --add -t ssh_port_t -p tcp 22345


### 3.2: CIS Operating System Security Configuration Benchmarks-1.0
echo "tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> /etc/fstab
echo "tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0" >> /etc/fstab
echo "install cramfs /bin/true" >> /etc/modprobe.d/cramfs.conf
echo "install hfs /bin/true" >> /etc/modprobe.d/hfs.conf
echo "install hfsplus /bin/true" > /etc/modprobe.d/hfsplus.conf
echo "install squashfs /bin/true" > /etc/modprobe.d/squashfs.conf
echo "install udf /bin/true" > /etc/modprobe.d/udf.conf
yum install aide
aide --init -V231
crontab -u root -e
/bin/bash -c  'echo "0 5 * * * /usr/sbin/aide --check" >> /etc/crontab'
chown root:root /boot/grub2/grub.cfg
chmod og-rwx /boot/grub2/grub.cfg
echo "* hard core 0" > /etc/security/limits.conf
echo "fs.suid_dumpable = 0" > /etc/sysctl.d/restrict-core-dumps.conf
sysctl -w fs.suid_dumpable=0
echo "kernel.randomize_va_space = 2" > /etc/sysctl.d/address-space-layout.conf
sysctl -w kernel.randomize_va_space=2
echo "WELCOME TO THIS MACHINE!" > /etc/update-motd.d/30-banner
echo "WELCOME TO THIS MACHINE!" > /etc/motd
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net
echo "net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0" > /etc/sysctl.d/ip-forwarding.conf
sysctl -w net.ipv4.ip_forward=0
sysctl -w net.ipv6.conf.all.forwarding=0
sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv6.route.flush=1
echo "net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0" > /etc/sysctl.d/packet-redirect.conf
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
sysctl -w net.ipv4.route.flush=1
echo "net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0" > /etc/sysctl.d/source-routed-packet.conf
sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv4.conf.default.accept_source_route=0
sysctl -w net.ipv6.conf.all.accept_source_route=0
sysctl -w net.ipv6.conf.default.accept_source_route=0
sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv6.route.flush=1
echo "net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0" > /etc/sysctl.d/ICMP-redirects.conf
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv6.conf.all.accept_redirects=0
sysctl -w net.ipv6.conf.default.accept_redirects=0
sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv6.route.flush=1
echo "net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0" > secure-ICMP-redirects.conf
echo "net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1" > suspicious-packets-logged.conf
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" > broadcast-ICMP-request.conf
echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" > bogus-ICMP.conf
echo "net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1" > reverse-path-filtering.conf
echo "net.ipv4.tcp_syncookies = 1" > TCP_SYN-cookies.conf
echo "net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0" > ipv6-router-advertisements.conf
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1
sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
sysctl -w net.ipv4.route.flush=
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1
sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv6.conf.all.accept_ra=0
sysctl -w net.ipv6.conf.default.accept_ra=0
sysctl -w net.ipv6.route.flush=1
echo "install dccp /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install sctp /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install rds /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install tipc /bin/true" >> /etc/modprobe.d/CIS.conf
find /var/log -type f -exec chmod g-wx,o-rwx {} +
echo "# Ensure rsyslog default file permissions configured
\$FileCreateMode 0640" >> rsyslog.conf
echo "*.* @@loghost.example.com" >> /etc/rsyslog.conf
echo "*.* @@loghost.example.com" > /etc/rsyslog.d/logs-to-remote-log-host.conf
echo "auth required pam_wheel.so use_uid" >> /etc/pam.d/su
echo "wheel:x:10:root,< user list>"
chown root:root /etc/crontab
chmod og-rwx /etc/crontab
chown root:root /etc/crontab
chmod og-rwx /etc/crontab
chown root:root /etc/cron.hourly
chmod og-rwx /etc/cron.hourly
chown root:root /etc/cron.daily
chmod og-rwx /etc/cron.daily
chown root:root /etc/cron.weekly
chmod og-rwx /etc/cron.weekly
chown root:root /etc/cron.monthly
chmod og-rwx /etc/cron.monthly
chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d
rm /etc/cron.deny
rm /etc/at.deny
touch /etc/cron.allow
touch /etc/at.allow
chmod og-rwx /etc/cron.allow
chmod og-rwx /etc/at.allow
chown root:root /etc/cron.allow
chown root:root /etc/at.allow
sed -i -e 's/#LogLevel INFO/LogLevel INFO/' /etc/ssh/sshd_config
sed -i -e 's/#MaxAuthTries 6/MaxAuthTries 4/' /etc/ssh/sshd_config
sed -i -e 's/#IgnoreRhosts no/IgnoreRHosts yes/' /etc/ssh/sshd_config
sed -i -e 's/#PermitRootLogin \(no\|yes\)/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i -e 's/#PermitEmptyPasswords \(no\|yes\)/PermitEmptyPasswords no/' /etc/ssh/sshd_config
sed -i -e 's/#PermitUserEnvironment \(no\|yes\)/PermitUserEnvironment no/' /etc/ssh/sshd_config
sed -i -e 's/# Ciphers and keying/# Ciphers and keying \nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ct r,aes128-ctr/' test_config
sed -i -e 's/#ClientAliveInterval 300/ClientAliveInterval 300/' test_config
sed -i -e 's/#ClientAliveCountMax 0/ClientAliveCountMax 0/' test_config
sed -i -e 's/#Banner none/Banner \/etc\/issue.net/' test_config
echo "password requisite pam_pwquality.so try_first_pass retry=3" >> /etc/pam.d/password-auth
echo "password requisite pam_pwquality.so try_first_pass retry=3" >> /etc/pam.d/system-auth
sed -i -e 's/minlen = [0-9]*[0-9]*/minlen = 14/' test-conf
sed -i -e 's/dcredit = [0-9]*[0-9]*/dcredit = -1/' test-conf
sed -i -e 's/ucredit = [0-9]*[0-9]*/ucredit = -1/' test-conf
sed -i -e 's/ocredit = [0-9]*[0-9]*/ocredit = -1/' test-conf
sed -i -e 's/lcredit = [0-9]*[0-9]*/lcredit = -1/' test-conf
echo "password sufficient pam_unix.so remember=5" >> /etc/pam.d/system-auth
echo "password sufficient pam_unix.so remember=5" >> /etc/pam.d/password-auth
sed -i -e 's/SELINUX=[a-z]*/SELINUX=enforcing/' config
echo "GRUB_CMDLINE_LINUX=\"audit=1\" ">> /etc/default/grub
echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change-w /etc/localtime -p wa -k time-change" >> /etc/audit/rules.d/audit.rules
echo "-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/ shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale
-w /etc/sysconfig/network-scripts/ -p wa -k system-locale" >> /etc/audit/rules.d/audit.rules
echo "-w /etc/selinux/ -p wa -k MAC-policy
-w /usr/share/selinux/ -p wa -k MAC-policy" >> /etc/audit/rules.d/audit.rules
echo "-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins" >> /etc/audit/rules.d/audit.rules
echo "-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid! =4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid! =4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid! =4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=- EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules
echo "-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope" >> /etc/audit/rules.d/audit.rules
echo "-w /var/log/sudo.log -p wa -k actions" >> /etc/audit/rules.d/audit.rules
echo "-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" >> /etc/audit/rules.d/audit.rules
echo "-e 2" >> /etc/audit/rules.d/audit.rules
sed -i '/^space_left_action/s/= .*/= emailaction_mail_acct = rootadmin_space_left_action = halt/' /etc/audit/auditd.conf
sed -i '/^max_log_file_action/s/= .*/= keep_logs/' etc/audit/auditd.conf