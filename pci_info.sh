#!/bin/bash
#-------------------------------------------------------------#
# Optiv Security, Inc.
# The information transmitted in this document is intended only for the addressee and may contain confidential and/or privileged material. Any interception, review, retransmission, dissemination or other use of or taking of any action upon this information by persons or entities other than the intended recipient is prohibited by law and may subject them to criminal or civil liability.
#-------------------------------------------------------------#
# PCI Host - RHEL Script Setup
#-------------------------------------------------------------#
# rev. 2016.4.b
# Admin must ensure output directory and permissions are set.
#-------------------------------------------------------------#
# Client: (ADD CLIENT NAME HERE)
#-------------------------------------------------------------#

echo "PCI Script rev. 2016.4.b"

echo "#-------------------------------------------------------------#" >> pciresults.txt
echo "# Step 001 - PCI Host - General Information" >> pciresults.txt
echo "#-------------------------------------------------------------#" >> pciresults.txt

echo "date: " >> pciresults.txt
date >> pciresults.txt
echo ""  >> pciresults.txt

echo "whoami: " >> pciresults.txt
whoami >> pciresults.txt
echo ""  >> pciresults.txt

#Hostname and kernel info
echo "uname -a:"  >> pciresults.txt
uname -a >> pciresults.txt
echo ""  >> pciresults.txt

#Runlevel
echo "who -r:" >> pciresults.txt
who -r >> pciresults.txt
echo ""  >> pciresults.txt

#RHEL version
echo "cat /etc/redhat-release:" >> pciresults.txt
cat /etc/redhat-release >> pciresults.txt
echo ""  >> pciresults.txt

#File system information
echo "cat /etc/fstab:"  >> pciresults.txt
cat /etc/fstab >> pciresults.txt
echo ""  >> pciresults.txt

echo "#-------------------------------------------------------------#" >> pciresults.txt
echo "# Step 002 - PCI Host - Software" >> pciresults.txt
echo "#-------------------------------------------------------------#" >> pciresults.txt

#RPM packages list
echo "rpm -q -a:"  >> pciresults.txt
rpm -q -a >> pciresults.txt
echo ""  >> pciresults.txt

#YUM list
echo "yum list all:"  >> pciresults.txt
yum list all >> pciresults.txt
echo ""  >> pciresults.txt

#YUM log history
echo "tail -n 100 /var/log/yum.log:"  >> pciresults.txt
tail -n 100 /var/log/yum.log >> pciresults.txt
echo ""  >> pciresults.txt

echo "#-------------------------------------------------------------#" >> pciresults.txt
echo "# Step 003 - PCI Host - Network" >> pciresults.txt
echo "#-------------------------------------------------------------#" >> pciresults.txt

##############################################
#RHEL 5/6. Deprecated for RHEL 7.
echo "ifconfig:"  >> pciresults.txt
ifconfig >> pciresults.txt
echo ""  >> pciresults.txt
##############################################


##############################################
#Replacement for ifconfig on RHEL 7.
echo "ip addr show:"  >> pciresults.txt
ip addr show >> pciresults.txt
echo ""  >> pciresults.txt
##############################################


##############################################
#RHEL 5/6. Deprecated for RHEL 7.
echo "netstat -a:"  >> pciresults.txt
netstat -a >> pciresults.txt
echo ""  >> pciresults.txt
##############################################


##############################################
#Replacement for netstat on RHEL 7.
echo "ss -a:"  >> pciresults.txt
ss -a >> pciresults.txt
echo ""  >> pciresults.txt
##############################################

echo "cat /etc/hosts:"  >> pciresults.txt
cat /etc/hosts >> pciresults.txt
echo ""  >> pciresults.txt

echo "cat /etc/resolv.conf:"  >> pciresults.txt
cat /etc/resolv.conf >> pciresults.txt
echo ""  >> pciresults.txt

#IPTABLES FIREWALL TESTS
echo "cat /etc/sysconfig/iptables:"  >> pciresults.txt
cat /etc/sysconfig/iptables >> pciresults.txt
echo ""  >> pciresults.txt

echo "iptables -L:"  >> pciresults.txt
iptables -L >> pciresults.txt
echo ""  >> pciresults.txt

#IP FORWARDING
echo "sysctl -a |grep ip_forward:"  >> pciresults.txt
sysctl -a |grep ip_forward >> pciresults.txt
echo ""  >> pciresults.txt


echo "#-------------------------------------------------------------#" >> pciresults.txt
echo "# Step 004 - PCI Host - Service and Processes " >> pciresults.txt
echo "#-------------------------------------------------------------#" >> pciresults.txt

# List Running Services

##############################################
#RHEL 5/6. Deprecated for RHEL 7
echo "service --status-all"  >> pciresults.txt
service --status-all >> pciresults.txt
echo ""  >> pciresults.txt
##############################################


##############################################
#Replacement for service --status-all on RHEL 7.
echo "systemctl -t service --state=active"  >> pciresults.txt
systemctl -t service --state=active >> pciresults.txt
echo ""  >> pciresults.txt
##############################################

#Enabled service status
echo "chkconfig --list" >> pciresults.txt
chkconfig --list >> pciresults.txt
echo "" >> pciresults.txt


echo "ps -ef:"  >> pciresults.txt
ps -ef >> pciresults.txt
echo ""  >> pciresults.txt

echo "#-------------------------------------------------------------#" >> pciresults.txt
echo "# Step 005 - PCI Host - NTP " >> pciresults.txt
echo "#-------------------------------------------------------------#" >> pciresults.txt
echo ""  >> pciresults.txt

echo "cat /etc/ntp.conf:"  >> pciresults.txt
cat /etc/ntp.conf >> pciresults.txt
echo ""  >> pciresults.txt

echo "#-------------------------------------------------------------#" >> pciresults.txt
echo "# Step 006 - PCI Host - SNMP " >> pciresults.txt
echo "#-------------------------------------------------------------#" >> pciresults.txt
echo ""  >> pciresults.txt

echo "cat /etc/snmp/snmpd.conf:"  >> pciresults.txt
cat /etc/snmp/snmpd.conf >> pciresults.txt
echo ""  >> pciresults.txt

echo "#-------------------------------------------------------------#" >> pciresults.txt
echo "# Step 007 - PCI Host - Privileged Use (SU/SUDO) " >> pciresults.txt
echo "#-------------------------------------------------------------#" >> pciresults.txt
echo ""  >> pciresults.txt

echo "cat /etc/sudoers:"  >> pciresults.txt
cat /etc/sudoers >> pciresults.txt
echo ""  >> pciresults.txt

echo "#-------------------------------------------------------------#" >> pciresults.txt
echo "# Step 008 PCI Host - Remote Access & Authentication" >> pciresults.txt
echo "#-------------------------------------------------------------#" >> pciresults.txt
echo ""  >> pciresults.txt

echo "cat /etc/ssh/sshd_config:"  >> pciresults.txt
cat /etc/ssh/sshd_config >> pciresults.txt
echo ""  >> pciresults.txt

echo "cat /etc/ssh/ssh_config:"  >> pciresults.txt
cat /etc/ssh/ssh_config >> pciresults.txt
echo ""  >> pciresults.txt

echo "cat /etc/krb5.conf:"  >> pciresults.txt
cat /etc/krb5.conf >> pciresults.txt
echo ""  >> pciresults.txt

echo "cat /etc/sysconfig/authconfig:"  >> pciresults.txt
cat /etc/sysconfig/authconfig >> pciresults.txt
echo ""  >> pciresults.txt

echo "#-------------------------------------------------------------#" >> pciresults.txt
echo "# Step 009 - PCI Host - FIM" >> pciresults.txt
echo "#-------------------------------------------------------------#" >> pciresults.txt
echo ""  >> pciresults.txt

echo "ls -alR /usr/local/tripwire:" >> pciresults.txt
ls -alR /usr/local/tripwire >> pciresults.txt
echo ""  >> pciresults.txt

echo "#-------------------------------------------------------------#" >> pciresults.txt
echo "# Step 010 - PCI Host - Antivirus" >> pciresults.txt
echo "#-------------------------------------------------------------#" >> pciresults.txt
echo ""  >> pciresults.txt

echo "Manual step. Potentially not used by client, per risk documentation."  >> pciresults.txt
echo ""  >> pciresults.txt

echo "#-------------------------------------------------------------#" >> pciresults.txt
echo "# Step 011 - PCI Host - Local Logging & Forwarding " >> pciresults.txt
echo "#-------------------------------------------------------------#" >> pciresults.txt
echo ""  >> pciresults.txt

echo "ls -l /etc/syslog.conf: " >> pciresults.txt
ls -l /etc/syslog.conf >> pciresults.txt
echo ""  >> pciresults.txt

echo "cat /etc/syslog.conf: " >> pciresults.txt
cat /etc/syslog.conf >> pciresults.txt
echo ""  >> pciresults.txt

echo "ls -l /etc/rsyslog.conf: " >> pciresults.txt
ls -l /etc/rsyslog.conf >> pciresults.txt
echo ""  >> pciresults.txt

echo "cat /etc/rsyslog.conf: " >> pciresults.txt
cat /etc/rsyslog.conf >> pciresults.txt
echo ""  >> pciresults.txt

echo "ls -alR /var/log: " >> pciresults.txt
ls -alR /var/log >> pciresults.txt
echo ""  >> pciresults.txt

echo "last | head -50: " >> pciresults.txt
last | head -50 >> pciresults.txt
echo ""  >> pciresults.txt

echo "lastlog: " >> pciresults.txt
lastlog >> pciresults.txt
echo ""  >> pciresults.txt

echo "cat /var/log/secure | grep password: " >> pciresults.txt
cat /var/log/secure | grep password >> pciresults.txt
echo ""  >> pciresults.txt


echo "#-------------------------------------------------------------#" >> pciresults.txt
echo "# Step 012 - PCI Host - Centralized Logging & Forwarding " >> pciresults.txt
echo "#-------------------------------------------------------------#" >> pciresults.txt
echo ""  >> pciresults.txt

echo "This step is performed separately. IF centralized logging is NOT used (e.g., syslog forwarding to a central log management solution), obtain at least 10 log data alerts/exceptions (if they exist) and at least one hour or 1MB of log data (whichever is smaller) for the system during the 8AM to 5PM local time frame.  Export the log data as a text, CSV or tab delimited file and label the file LOGDATA.txt." >> pciresults.txt
echo ""  >> pciresults.txt

echo "#-------------------------------------------------------------#" >> pciresults.txt
echo "# Step 013 - PCI Host - Auditing " >> pciresults.txt
echo "#-------------------------------------------------------------#" >> pciresults.txt
echo ""  >> pciresults.txt

echo "service auditd status" >> pciresults.txt
service auditd status >> pciresults.txt
echo ""  >> pciresults.txt

echo "cat /etc/audit/auditd.conf: " >> pciresults.txt
cat /etc/audit/auditd.conf >> pciresults.txt
echo ""  >> pciresults.txt

echo "cat /etc/audit/audit.rules: " >> pciresults.txt
cat /etc/audit/audit.rules >> pciresults.txt
echo ""  >> pciresults.txt

echo "grep audit /boot/grub/grub.conf: " >> pciresults.txt
grep audit /boot/grub/grub.conf >> pciresults.txt
echo ""  >> pciresults.txt

echo "tail -n 30 /var/log/messages /var/log/secure: " >> pciresults.txt
tail -n 30 /var/log/messages /var/log/secure >> pciresults.txt
echo ""  >> pciresults.txt

echo "#-------------------------------------------------------------#" >> pciresults.txt
echo "# Step 014 - PCI Host - Local Users & Groups " >> pciresults.txt
echo "#-------------------------------------------------------------#" >> pciresults.txt
echo ""  >> pciresults.txt

echo "cat /etc/group: " >> pciresults.txt
cat /etc/group >> pciresults.txt
echo ""  >> pciresults.txt

echo "cat /etc/login.defs: " >> pciresults.txt
cat /etc/login.defs >> pciresults.txt
echo ""  >> pciresults.txt

echo "#-------------------------------------------------------------#" >> pciresults.txt
echo "# Step 015 - PCI Host - Password Management " >> pciresults.txt
echo "#-------------------------------------------------------------#" >> pciresults.txt
echo ""  >> pciresults.txt

echo "cat /etc/passwd: " >> pciresults.txt
cat /etc/passwd >> pciresults.txt
echo ""  >> pciresults.txt

echo "cat /etc/shadow: " >> pciresults.txt
# cat /etc/shadow >> pciresults.txt
echo ""  >> pciresults.txt

echo "#-------------------------------------------------------------#" >> pciresults.txt
echo "# Step 016 - PCI Host - LDAP " >> pciresults.txt
echo "#-------------------------------------------------------------#" >> pciresults.txt
echo ""  >> pciresults.txt

echo "ls -l /etc/sysconfig/ldap: " >> pciresults.txt
ls -l /etc/sysconfig/ldap >> pciresults.txt
echo ""  >> pciresults.txt

echo "cat /etc/sysconfig/ldap: " >> pciresults.txt
cat /etc/sysconfig/ldap >> pciresults.txt
echo ""  >> pciresults.txt

echo "#-------------------------------------------------------------#" >> pciresults.txt
echo "# Step 017 - PCI Host - PAM " >> pciresults.txt
echo "#-------------------------------------------------------------#" >> pciresults.txt
echo ""  >> pciresults.txt

echo "cat /etc/pam.d/system-auth: " >> pciresults.txt
cat /etc/pam.d/system-auth >> pciresults.txt
echo ""  >> pciresults.txt

echo "cat /etc/pam.d/login: " >> pciresults.txt
cat /etc/pam.d/login >> pciresults.txt
echo ""  >> pciresults.txt

echo "cat /etc/pam.d/crond: " >> pciresults.txt
cat /etc/pam.d/crond >> pciresults.txt
echo ""  >> pciresults.txt

echo "cat /etc/pam.d/passwd: " >> pciresults.txt
cat /etc/pam.d/passwd >> pciresults.txt
echo ""  >> pciresults.txt

echo "cat /etc/pam.d/password-auth: " >> pciresults.txt
cat /etc/pam.d/password-auth >> pciresults.txt
echo ""  >> pciresults.txt

echo "cat /etc/pam.d/runuser: " >> pciresults.txt
cat /etc/pam.d/runuser >> pciresults.txt
echo ""  >> pciresults.txt

echo "cat /etc/pam.d/runuser-l: " >> pciresults.txt
cat /etc/pam.d/runuser-l >> pciresults.txt
echo ""  >> pciresults.txt

echo "cat /etc/pam.d/sshd: " >> pciresults.txt
cat /etc/pam.d/sshd >> pciresults.txt
echo ""  >> pciresults.txt

echo "cat /etc/pam.d/su: " >> pciresults.txt
cat /etc/pam.d/su >> pciresults.txt
echo ""  >> pciresults.txt

echo "cat /etc/pam.d/sudo-i: " >> pciresults.txt
cat /etc/pam.d/sudo-i >> pciresults.txt
echo ""  >> pciresults.txt

echo "cat /etc/pam.d/su-l: " >> pciresults.txt
cat /etc/pam.d/su-l >> pciresults.txt
echo ""  >> pciresults.txt

echo "cat /etc/pam.d/other: " >> pciresults.txt
cat /etc/pam.d/other >> pciresults.txt
echo ""  >> pciresults.txt

#RHEL 7
##############################################
echo "cat /etc/security/pwquality.conf: " >> pciresults.txt
cat /etc/security/pwquality.conf >> pciresults.txt
echo ""  >> pciresults.txt
##############################################

echo "#-------------------------------------------------------------#" >> pciresults.txt
echo "# Script Finalization " >> pciresults.txt
echo "#-------------------------------------------------------------#" >> pciresults.txt
echo ""  >> pciresults.txt

echo "date: " >> pciresults.txt
date >> pciresults.txt
echo ""  >> pciresults.txt

echo "whoami: " >> pciresults.txt
whoami >> pciresults.txt
echo ""  >> pciresults.txt

echo "uname -a:"  >> pciresults.txt
uname -a >> pciresults.txt
echo ""  >> pciresults.txt

echo "#-------------------------------------------------------------#" >> pciresultshash.txt
echo "# Hashing Results... " >> pciresultshash.txt
echo "#-------------------------------------------------------------#" >> pciresultshash.txt
echo ""  >> pciresultshash.txt

echo "date: " >> pciresultshash.txt
date >> pciresultshash.txt
echo ""  >> pciresultshash.txt

echo "whoami: " >> pciresultshash.txt
whoami >> pciresultshash.txt
echo ""  >> pciresultshash.txt

echo "uname -a:"  >> pciresultshash.txt
uname -a >> pciresultshash.txt
echo ""  >> pciresultshash.txt

echo "MD5 and SHA1 of test results TXT file:"  >> pciresultshash.txt
md5sum pciresults.txt >> pciresultshash.txt
sha1sum pciresults.txt >> pciresultshash.txt
echo ""  >> pciresultshash.txt

echo "tar -cf tarpciresults.tar pciresults.txt pciresultshash.txt"
tar -cf tarpciresults.tar pciresults.txt pciresultshash.txt

echo "Script complete. Provide copy of TAR file via secure delivery method."
echo "After collecting files, delete unnecessary copies of script output from server along with any temp directories used."

#End of script

