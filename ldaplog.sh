#!/bin/sh

CEF="/path-to-script/ldap2cef.py"

for LOG in `/bin/ls -1 path-to-logs/*.log` 
do
    $CEF -i $LOG &
done
