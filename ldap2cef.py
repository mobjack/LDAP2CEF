#!/usr/bin/env python

# Standard Library Imports
from collections import defaultdict
from shutil import move
import sys
import re
import getopt
import time, datetime
import random
from pprint import pprint


conn_reg          = re.compile(r'conn=(\d+)\s+(\w\w)=(\d+)\s+') 
ip_reg            = re.compile(r'ACCEPT from IP=(\d+\.\d+\.\d+\.\d+):')
bind_name_reg     = re.compile(r'BIND\s+dn=\"(.*?)\"')
user_reg          = re.compile(r'mail=(.*?@mozilla.*?\....)')
login_outcome_reg = re.compile(r'err=(\d+) ')
date_reg          = re.compile(r'\w+\s+\d+\s+\d+:\d+:\d+')
proxyAuth_reg     = re.compile(r'PROXYAUTHZ\s+dn=\"(.*?)\"')

# Globals
out_dir = "/var/log/syslog/systems/arcsight-cef/" # set the full path here "../" is not best
out_rand = str(random.randint(1001,9999)) # used for file names
out_file = out_dir + "ldap-" + out_rand + ".log" # this is the staging file
done_file = out_file + ".done" # this file tells arcsight to start reading the file


domain = "@mozilla" # sets what domain to look for

#secsbefore = int(100000) #  Testing; time in seconds to search back
#nowepoch = int(1351231200) # testing parameter

secsbefore = int(605) # time in seconds to search back
nowepoch = time.time()

startepoch = nowepoch - secsbefore


def get_connection_id(line):
    """"Parses the conn=xxxxx ID from the string of text.
    Returns None if no ID can be found.
    """

    try:
        conn_blob = re.search(conn_reg, line)
        conn_id = conn_blob.group(1)
        conn_type = conn_blob.group(2)
        conn_subid = conn_blob.group(3)
    except:
        return "None"

    if conn_type == "fd":
        conn_subid = "0"

    conn_ret = conn_id + "-" + conn_subid
   
    if conn_ret:
        return conn_ret
    else:
        return "None"


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
        ret_dat["ip"] = tmp

    bind_name_match = re.search(bind_name_reg, blob)
    if bind_name_match:
        ret_dat["bind_name"] = bind_name_match.group(1)

    user_match = re.search(user_reg, blob)
    if user_match:
        ret_dat["user"] = user_match.group(1)
    
    proxy_match = re.search(proxyAuth_reg, blob)
    if proxy_match:
        ret_dat["proxy"] = proxy_match.group(1)

    login_outcome_match = re.search(login_outcome_reg, blob)
    if login_outcome_match:
        ret_dat["login_outcome"] = login_outcome_match.group(1)
        login_num = int(login_outcome_match.group(1))
        #print login_num

        if login_num == 0:
            ret_dat["login_name"] = "LDAP_SUCCESS"
        elif login_num == 32:     
            ret_dat["login_name"] = str("LDAP_NO_SUCH_OBJECT")
        elif login_num == 49:     
            ret_dat["login_name"] = str("LDAP_INVALID_CREDENTIALS")
        elif login_num == 50:    
            ret_dat["login_name"] = str("LDAP_INSUFFICIENT_ACCESS")
        elif login_num == 53:    
            ret_dat["login_name"] = str("LDAP_UNWILLING_TO_PERFORM")
        elif login_num == 65:    
            ret_dat["login_name"] = str("LDAP_OBJECT_CLASS_VIOLATION")
        else: 
            ret_dat["login_name"] = str("LDAP_ERROR")


    date_match = re.search(date_reg, blob)
    date_epoch = epoch(date_match.group(0))
    ret_dat["date_end"] = date_epoch

    return_anything = False # an easy to flip config knob
                            # for producing partially filled
                            # return data.  Could be a global.
    if return_anything:
        return ret_dat
 
    # Only return data if we found all the pieces
    # remember we added the conn_id, so total is 5
    if(len(ret_dat.keys()) >= 4):
        #print(ret_dat) #turn this on to see exactly what was extracted.
        return ret_dat    
    else:
        return "None"



def format_cef(data):
    """Returns an appropriately formatted CEF string."""
    # The format function replaces the {name} tokens with the values from data.
    return """CEF:0|mozilla|openldap|1.0|{login_outcome}|{login_name}|6|src={ip} cs1=\"{bind_name}\" suser={user} cs1Label=BindId cs2={proxy} cs2Label=ProxyDn cn1={conn_id} cn2Label2=LdapId cn2={login_outcome} cn2Label=LdapCode cn1Label=ConnId end={end}""".format(
        conn_id=data.get("conn_id", "NOCONN"),
        login_outcome=data.get("login_outcome", "LDAP_EVENT"),
        login_name=data.get("login_name", "not found"),
        ip=data.get("ip", ""),
        bind_name=data.get("bind_name", "None"),
        user=data.get("user", "Unknown"),
        proxy=data.get("proxy", "Not Found"),
        end=data.get("date_end", "Unknown")
    )

def epoch(mydate): # converts standard syslog date stamp and returns epoch
  
    curryear = datetime.datetime.now().year
    date_reg = re.search(r'(\w+)\s+(\d+)\s+(\d+):(\d+):(\d+)', mydate)
    logmonth = time.strptime(date_reg.group(1), '%b').tm_mon
    logday = int(date_reg.group(2))
    loghour = int(date_reg.group(3))
    logmin = int(date_reg.group(4))
    logsec = int(date_reg.group(5))
   
    # -7 is pst time; change to your timezone 
    ltime = (curryear, logmonth, logday, loghour, logmin, logsec, 0, 0, -7)
    eptime = time.mktime(ltime)
    return eptime


def usage():
    print 'ldap2cef.py -i <inputlog>'


def main(argv):
    #print "Running..."
    inputfile = ''
    conn_index = {}
    try:
       opts, args = getopt.getopt(argv,"hi:",["ifile="])
    except getopt.GetoptError:
       usage()
       sys.exit(2)
    for opt, arg in opts:
       if opt == '-h':
          usage()
          sys.exit()
       elif opt in ("-i", "--ifile"):
          inputfile = arg

    # Set up the main data structure, values will default to a new string.
    connections = defaultdict(str)

    """
    Iterate through every line in the input file, gathering them in a 
    dictionary keyed on the connection id.  The value will be the
    concatenation of all related lines in one big blob.
    """  
    for line in open(inputfile):
        line = line.strip()

        if line.count('slapd') == 0: # skip line if not slapd
            continue  

        if line.count('conn=') == 0: # skip line if conn= is not there 
            continue  

        # Check to see if line is within startepoch
        rawdate = re.match (r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+.*', line)
        sandate = int(epoch(rawdate.group(1)))
        if startepoch >= sandate:
            continue

        ldap_id = get_connection_id(line)


        if ldap_id == "None": 
            continue

        """Add the id to dictionary for later use"""
        new_conn = re.search(ip_reg, line)

        #print new_conn

        if new_conn:
            idfull = ldap_id.partition("-")
            rootid = idfull[0] + "-0"
            conn_index[rootid] = line # example 2892760-0:ACCEPT from IP
 
        if ldap_id:
            connections[ldap_id] += " " + line + " "

    # Setup the output file
    out = open(out_file, 'w+')
    
    # Iterate through the key:values in the connections dictionary and
    # process each group of log data.
    for conn_id, blob in connections.items():
        email_count  = blob.count(domain) # skip it there's no user data there
        if email_count == 0:
            continue
     

        """Lookup if there's a connection id in the conn_index"""
        root_part = conn_id.partition("-")
        root_conn_id = root_part[0]
        root_key = root_conn_id + "-0"
 
        full_blob = str(blob)

        if root_key in conn_index.keys():
            root_blob = str(conn_index[root_key])
        else:	
            continue        

        new_blob = root_blob + " " + full_blob

        data = parse_line_data(root_conn_id, new_blob)

        if data: # could be ``None`` if the input was invalid.
            print >> out, format_cef(data)
    
    """Move to directory for arcsight processing"""
    move(out_file,done_file)

if __name__ == '__main__':
    main(sys.argv[1:])
