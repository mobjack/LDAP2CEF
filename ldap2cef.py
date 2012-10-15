#!/usr/bin/env python

# Standard Library Imports
from collections import defaultdict
import sys
import re
from pprint import pprint

#
# Sample blob of line text
#

# Oct 10 13:13:13 ldapmaster1 slapd[11268]: conn=10505080 fd=43 ACCEPT from IP=10.8.70.118:52862 (IP=0.0.0.0:389)  Oct 10 13:13:13 ldapmaster1 slapd[11268]: conn=10505080 op=0 EXT oid=1.3.6.1.4.1.1466.20037  Oct 10 13:13:13 ldapmaster1 slapd[11268]: conn=10505080 op=0 STARTTLS  Oct 10 13:13:13 ldapmaster1 slapd[11268]: conn=10505080 op=0 RESULT oid= err=0 text=  Oct 10 13:13:13 ldapmaster1 slapd[11268]: conn=10505080 fd=43 TLS established tls_ssf=256 ssf=256  Oct 10 13:13:13 ldapmaster1 slapd[11268]: conn=10505080 op=1 BIND dn="uid=replicator,ou=logins,dc=mozilla" method=128  Oct 10 13:13:13 ldapmaster1 slapd[11268]: conn=10505080 op=1 BIND dn="uid=replicator,ou=logins,dc=mozilla" mech=SIMPLE ssf=0  Oct 10 13:13:13 ldapmaster1 slapd[11268]: conn=10505080 op=1 RESULT tag=97 err=0 text=  Oct 10 13:13:13 ldapmaster1 slapd[11268]: conn=10505080 op=2 MOD dn="mail=eparker@mozilla.com,o=com,dc=mozilla"  Oct 10 13:13:13 ldapmaster1 slapd[11268]: conn=10505080 op=2 MOD attr=pwdFailureTime pwdUniqueAttempts  Oct 10 13:13:13 ldapmaster1 slapd[11268]: conn=10505080 op=2 RESULT tag=103 err=50 text=

ip_reg            = re.compile(r'ACCEPT from IP=(\d+\.\d+\.\d+\.\d+):')
bind_name_reg     = re.compile(r'BIND dn="uid=(.*?),')
                    #dn="mail=xxxx@mozilla.com,o=com,dc=mozilla"
#user_reg          = re.compile(r'dn="mail=(.*?),')
user_reg          = re.compile(r'mail=(.*?@mozilla.com)\)')
login_outcome_reg = re.compile(r'err=(\d+) ')

def get_connection_id(line):
    """"Parses the conn=xxxxx ID from the string of text.

    Returns None if no ID can be found.
    """
    left, middle, right = line.partition("conn=")
    if right:
        return right.split()[0]
    else:
        return None


def parse_line_data(conn_id, blob):
    """Parses specific pieces of data out of the text, returns it as a
    dictionary.  Returns ``None`` if all data fields cannot be parsed.
    """
    
    ret_dat = {
        "conn_id": conn_id
    }
    
    tmp = None
    
    ip_match = re.search(ip_reg, blob)
    if ip_match:
        tmp = ip_match.group(1)
        #print "parse_line_data#ip got " + tmp
        ret_dat["ip"] = tmp
    #else:
        #print "parse_line_data got no ip"

    bind_name_match = re.search(bind_name_reg, blob)
    if bind_name_match:
        ret_dat["bind_name"] = bind_name_match.group(1)

    user_match = re.search(user_reg, blob)
    if user_match:
    	#print user_match.group(1)
        ret_dat["user"] = user_match.group(1)

    login_outcome_match = re.search(login_outcome_reg, blob)
    if login_outcome_match:
        ret_dat["login_outcome"] = login_outcome_match.group(1)


    return_anything = False # an easy to flip config knob
                            # for producing partially filled
                            # return data.  Could be a global.
    if return_anything:
        return ret_dat
 
    # Only return data if we found all the pieces
    # remember we added the conn_id, so total is 5
    if(len(ret_dat.keys()) == 5):
        #print(ret_dat) #turn this on to see exactly what was extracted.
        return ret_dat    
    else:
        return None

def format_cef(data):
    """Returns an appropriately formatted CEF string."""
    # The format function replaces the {name} tokens with the values from data.
    return """CEF:0|mozilla|openldap|1.0|{login_outcome}||6|src={ip} cs1={bind_name} suser={user} cs1Label=BindId cn1={conn_id}""".format(
        conn_id=data.get("conn_id", "NOCONN"),
        login_outcome=data.get("login_outcome", "not found"),
        ip=data.get("ip", ""),
        bind_name=data.get("bind_name", "None"),
        user=data.get("user", "Unknown")
    )

def main():
    # Set up the main data structure, values will default to a new string.
    connections = defaultdict(str)

    # Iterate through every line in the input file, gathering them in a 
    # dictionary keyed on the connection id.  The value will be the
    # concatenation of all related lines in one big blob.
    #for line in open('ldap.log'):
    for line in open('ldap-big.log'):
        line = line.strip()
        id = get_connection_id(line)
        if id:
            #print "got id " + id
            connections[id] += " " + line + " "

    # Setup the output file
    outfile = open('cef.log', 'w+')
    
    # Iterate through the key:values in the connections dictionary and
    # process each group of log data.
    for conn_id, blob in connections.items():
        #print "{} : {}".format(conn_id, blob)
        data = parse_line_data(conn_id, blob)
        if data: # could be ``None`` if the input was invalid.
            #print >> outfile, format_cef(data)
            print format_cef(data)
            print "-----" 

if __name__ == '__main__':
    main()


