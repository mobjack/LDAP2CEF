#!/bin/sh

CEF="./ldap2cef.py"

for LOG in `/bin/ls -1 /var/log/syslog/systems/ldap*/*.log` 
do
    #printf "$CEF -i $LOG\n"
    $CEF -i $LOG &
    
done
