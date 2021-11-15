#!/bin/bash

sudo su

### Initial installations
yum update
yum -y install policycoreutils-python
semanage port --add -t ssh_port_t -p tcp 22345
sed -i -e 's/#Port [0-9]*/Port 22345/' /etc/ssh/sshd_config
systemctl restart sshd
