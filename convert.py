#!/usr/bin/env python2.7

# (c) 2017, Glenn Akester
#
# Title: SRX to ASA Converter
# Description: Python script to convert Juniper SRX configuration to Cisco ASA.
#
# SRX to ASA Converter is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# SRX to ASA Converter is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

# Import modules

import argparse
import netaddr
import re

# Get configuration filepath from args

parser = argparse.ArgumentParser()
parser.add_argument("inputFile", help="/full/path/to/config")
args = parser.parse_args()

# Read config file to variable

with open(args.inputFile, 'r') as configFile:
    config = configFile.read()

# Get local networks

localnetworks = {}

netnum = 0

for n in re.finditer(r"set interfaces ((pp|reth|ae|fe|ge|xe)(-[0-9]{1,2}\/[0-9]{1,2}\/)?[0-9]{1,2}) unit ([0-9]{1,4}) family inet address ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}\/[0-9]{1,2})", config):
    intf = n.group(1) + "." + n.group(4)
    netw = n.group(5)

    localnetworks[netw] = {}
    localnetworks[netw]['intf'] = intf

    seczone = re.search(r"set security zones security-zone ([A-Za-z0-9_-]{1,}) interfaces " + intf, config)

    if seczone is not None:
        localnetworks[netw]['seczone'] = seczone.group(1)
    else:
        localnetworks[netw]['seczone'] = 'undefined'
 
    netnum += 1

# Convert system host name

hostname = re.search(r"(set system host-name ([A-Za-z0-9_-]{1,}))", config)
if hostname is not None:
    print "hostname " + hostname.group(2)

# Convert CIDR subnet mask to dot decimal

config = re.sub(r"([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3})(\/32)", r"\1 255.255.255.255", config)
config = re.sub(r"([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3})(\/31)", r"\1 255.255.255.254", config)
config = re.sub(r"([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3})(\/30)", r"\1 255.255.255.252", config)
config = re.sub(r"([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3})(\/29)", r"\1 255.255.255.248", config)
config = re.sub(r"([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3})(\/28)", r"\1 255.255.255.240", config)
config = re.sub(r"([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3})(\/27)", r"\1 255.255.255.224", config)
config = re.sub(r"([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3})(\/26)", r"\1 255.255.255.192", config)
config = re.sub(r"([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3})(\/25)", r"\1 255.255.255.128", config)
config = re.sub(r"([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3})(\/24)", r"\1 255.255.255.0", config)
config = re.sub(r"([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3})(\/23)", r"\1 255.255.254.0", config)
config = re.sub(r"([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3})(\/22)", r"\1 255.255.252.0", config)
config = re.sub(r"([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3})(\/21)", r"\1 255.255.248.0", config)
config = re.sub(r"([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3})(\/20)", r"\1 255.255.240.0", config)
config = re.sub(r"([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3})(\/19)", r"\1 255.255.224.0", config)
config = re.sub(r"([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3})(\/18)", r"\1 255.255.192.0", config)
config = re.sub(r"([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3})(\/17)", r"\1 255.255.128.0", config)
config = re.sub(r"([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3})(\/16)", r"\1 255.255.0.0", config)
config = re.sub(r"([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3})(\/15)", r"\1 255.254.0.0", config)
config = re.sub(r"([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3})(\/14)", r"\1 255.252.0.0", config)
config = re.sub(r"([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3})(\/13)", r"\1 255.248.0.0", config)
config = re.sub(r"([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3})(\/12)", r"\1 255.240.0.0", config)
config = re.sub(r"([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3})(\/11)", r"\1 255.224.0.0", config)
config = re.sub(r"([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3})(\/10)", r"\1 255.192.0.0", config)
config = re.sub(r"([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3})(\/9)", r"\1 255.128.0.0", config)
config = re.sub(r"([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3})(\/8)", r"\1 255.0.0.0", config)
config = re.sub(r"([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3})(\/7)", r"\1 254.0.0.0", config)
config = re.sub(r"([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3})(\/6)", r"\1 252.0.0.0", config)
config = re.sub(r"([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3})(\/5)", r"\1 248.0.0.0", config)
config = re.sub(r"([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3})(\/4)", r"\1 240.0.0.0", config)
config = re.sub(r"([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3})(\/3)", r"\1 224.0.0.0", config)
config = re.sub(r"([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3})(\/2)", r"\1 192.0.0.0", config)
config = re.sub(r"([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3})(\/1)", r"\1 128.0.0.0", config)
config = re.sub(r"([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3})(\/0)", r"\1 0.0.0.0", config)

# Convert interfaces

intfnum = 0

for n in re.finditer(r"(set interfaces ((pp|reth|ae|fe|ge|xe)(-[0-9]{1,2}\/[0-9]{1,2}\/)?([0-9]{1,2})) unit ([0-9]{1,4}) family inet address ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3} [0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}))", config):
    if intfnum <= 8:
        seczone = re.search(r"set security zones security-zone ([A-Za-z0-9_-]{1,}) interfaces " + n.group(2) + "." + n.group(6), config)

        if seczone is not None:
            print "interface GigabitEthernet0/" + n.group(5) + "\n nameif " + seczone.group(1) + "\n security-level 0\n ip address " + n.group(7)
        else:
            print "interface GigabitEthernet0/" + n.group(5) + "\n nameif undefined\n security-level 0\n ip address " + n.group(7)

    intfnum += 1

# Convert static routes

for n in re.finditer(r"set routing-options static route ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3} [0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) next-hop ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3})", config): 
    for key, value in localnetworks.iteritems():
        if netaddr.IPAddress(n.group(2)) in netaddr.IPNetwork(key):
            print "route " + value['seczone'] + " " + n.group(1) + " " + n.group(2)

# Define static applications

applications = {}

applications['any'] = {}
applications['any']['protocol'] = 'ip'
applications['any']['type'] = 'object'

# Define junos default applications

applications['junos-icmp-all'] = {}
applications['junos-icmp-all']['protocol'] = 'icmp'
applications['junos-icmp-all']['direction'] = 'destination'
applications['junos-icmp-all']['port'] = ''
applications['junos-icmp-all']['type'] = 'object'

applications['junos-icmp-ping'] = {}
applications['junos-icmp-ping']['protocol'] = 'icmp'
applications['junos-icmp-ping']['direction'] = 'destination'
applications['junos-icmp-ping']['port'] = 'echo'
applications['junos-icmp-ping']['type'] = 'object'

applications['junos-ssh'] = {}
applications['junos-ssh']['protocol'] = 'tcp'
applications['junos-ssh']['direction'] = 'destination'
applications['junos-ssh']['port'] = '22'
applications['junos-ssh']['type'] = 'object'

applications['junos-http'] = {}
applications['junos-http']['protocol'] = 'tcp'
applications['junos-http']['direction'] = 'destination'
applications['junos-http']['port'] = '80'
applications['junos-http']['type'] = 'object'

applications['junos-https'] = {}
applications['junos-https']['protocol'] = 'tcp'
applications['junos-https']['direction'] = 'destination'
applications['junos-https']['port'] = '443'
applications['junos-https']['type'] = 'object'

applications['junos-smtp'] = {}
applications['junos-smtp']['protocol'] = 'tcp'
applications['junos-smtp']['direction'] = 'destination'
applications['junos-smtp']['port'] = '25'
applications['junos-smtp']['type'] = 'object'

applications['junos-radius'] = {}
applications['junos-radius']['protocol'] = 'udp'
applications['junos-radius']['direction'] = 'destination'
applications['junos-radius']['port'] = '1812'
applications['junos-radius']['type'] = 'object'

applications['junos-radacct'] = {}
applications['junos-radacct']['protocol'] = 'udp'
applications['junos-radacct']['direction'] = 'destination'
applications['junos-radacct']['port'] = '1813'
applications['junos-radacct']['type'] = 'object'

applications['junos-syslog'] = {}
applications['junos-syslog']['protocol'] = 'udp'
applications['junos-syslog']['direction'] = 'destination'
applications['junos-syslog']['port'] = '161'
applications['junos-syslog']['type'] = 'object'

applications['junos-ntp'] = {}
applications['junos-ntp']['protocol'] = 'udp'
applications['junos-ntp']['direction'] = 'destination'
applications['junos-ntp']['port'] = '123'
applications['junos-ntp']['type'] = 'object'

applications['junos-ftp'] = {}
applications['junos-ftp']['protocol'] = 'tcp'
applications['junos-ftp']['direction'] = 'destination'
applications['junos-ftp']['port'] = '21'
applications['junos-ftp']['type'] = 'object'

applications['junos-telnet'] = {}
applications['junos-telnet']['protocol'] = 'tcp'
applications['junos-telnet']['direction'] = 'destination'
applications['junos-telnet']['port'] = '23'
applications['junos-telnet']['type'] = 'object'

applications['junos-ms-sql'] = {}
applications['junos-ms-sql']['protocol'] = 'tcp'
applications['junos-ms-sql']['direction'] = 'destination'
applications['junos-ms-sql']['port'] = '1433'
applications['junos-ms-sql']['type'] = 'object'

applications['junos-smb-session'] = {}
applications['junos-smb-session']['protocol'] = 'tcp'
applications['junos-smb-session']['direction'] = 'destination'
applications['junos-smb-session']['port'] = '445'
applications['junos-smb-session']['type'] = 'object'

applications['junos-ms-rpc'] = {}
applications['junos-ms-rpc']['protocol'] = 'tcp'
applications['junos-ms-rpc']['direction'] = 'destination'
applications['junos-ms-rpc']['port'] = '135'
applications['junos-ms-rpc']['type'] = 'object'

applications['junos-ms-rpc-tcp'] = {}
applications['junos-ms-rpc-tcp']['protocol'] = 'tcp'
applications['junos-ms-rpc-tcp']['direction'] = 'destination'
applications['junos-ms-rpc-tcp']['port'] = '135'
applications['junos-ms-rpc-tcp']['type'] = 'object'

applications['junos-ms-rpc-udp'] = {}
applications['junos-ms-rpc-udp']['protocol'] = 'udp'
applications['junos-ms-rpc-udp']['direction'] = 'destination'
applications['junos-ms-rpc-udp']['port'] = '135'
applications['junos-ms-rpc-udp']['type'] = 'object'

applications['junos-ldap'] = {}
applications['junos-ldap']['protocol'] = 'tcp'
applications['junos-ldap']['direction'] = 'destination'
applications['junos-ldap']['port'] = '389'
applications['junos-ldap']['type'] = 'object'

applications['junos-nbname'] = {}
applications['junos-nbname']['protocol'] = 'udp'
applications['junos-nbname']['direction'] = 'destination'
applications['junos-nbname']['port'] = '137'
applications['junos-nbname']['type'] = 'object'

applications['junos-dns-udp'] = {}
applications['junos-dns-udp']['protocol'] = 'udp'
applications['junos-dns-udp']['direction'] = 'destination'
applications['junos-dns-udp']['port'] = '53'
applications['junos-dns-udp']['type'] = 'object'

applications['junos-dns-tcp'] = {}
applications['junos-dns-tcp']['protocol'] = 'tcp'
applications['junos-dns-tcp']['direction'] = 'destination'
applications['junos-dns-tcp']['port'] = '53'
applications['junos-dns-tcp']['type'] = 'object'

#applications['junos-'] = {}
#applications['junos-']['protocol'] = ''
#applications['junos-']['direction'] = ''
#applications['junos-']['port'] = ''
#applications['junos-']['type'] = 'object'

# Convert applications to service objects

for n in re.finditer(r"(set applications application ([A-Za-z0-9_-]{1,}) protocol (tcp|udp)[\r\n])(set applications application [A-Za-z0-9_-]{1,} (destination|source)-port ([0-9]{1,5}(-[0-9]{1,5})?|[A-Za-z0-9_-]{1,})[\r\n])", config):
    print "object service " + n.group(2) + "\n service " + n.group(3) + " destination eq " + n.group(6)
    applications[n.group(2)] = {}
    applications[n.group(2)]['protocol'] = n.group(3)
    applications[n.group(2)]['direction'] = n.group(5)
    applications[n.group(2)]['port'] = n.group(6).replace('-',' ')
    applications[n.group(2)]['type'] = 'object'

# Convert applications with multiple terms to service object groups

for n in re.finditer(r"(set applications application ([A-Za-z0-9_-]{1,}) term [A-Za-z0-9_-]{1,} protocol (tcp|udp)[\r\n])(set applications application [A-Za-z0-9_-]{1,} term [A-Za-z0-9_-]{1,} (destination|source)-port ([0-9]{1,5}(-[0-9]{1,5})?)[\r\n])", config):
    print "object-group service " + n.group(2) + "-" + n.group(3) + " " + n.group(3) + "\n port-object eq " + n.group(6)
    applications[n.group(2)] = {}
    applications[n.group(2)]['protocol'] = n.group(3)
    applications[n.group(2)]['direction'] = n.group(5)
    applications[n.group(2)]['port'] = n.group(6).replace('-',' ')
    applications[n.group(2)]['type'] = 'group'

# Convert application sets to service object groups

for n in re.finditer(r"(set applications application-set ([A-Za-z0-9_-]{1,}) application ([A-Za-z0-9_-]{1,}))", config):
    print "object-group service " + n.group(2) + "\n service-object object " + n.group(3)
    applications[n.group(2)] = {}
    applications[n.group(2)]['protocol'] = 'ip'
    applications[n.group(2)]['type'] = 'group'

# Define static addresses

addresses = {}

addresses['any'] = {}
addresses['any']['type'] = 'any'

# Convert address book addresses to network objects

for addr in re.finditer(r"(set security zones security-zone [A-Za-z0-9_-]{1,} address-book address ([A-Za-z0-9_-]{1,}) ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3} [0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}))", config):
    print "object network " + addr.group(2) + "\n subnet " + addr.group(3)
    addresses[addr.group(2)] = {}
    addresses[addr.group(2)]['type'] = 'object'

# Convert address book address sets to network object groups

for addrSet in re.finditer(r"(set security zones security-zone [A-Za-z0-9_-]{1,} address-book address-set ([A-Za-z0-9_-]{1,}) address ([A-Za-z0-9_-]{1,}))", config):
    print "object-group network " + addrSet.group(2) + "\n network-object object " + addrSet.group(3)
    addresses[addrSet.group(2)] = {}
    addresses[addrSet.group(2)]['type'] = 'group'

# Convert address book address sets with nested address sets to network object groups

for addrSetNested in re.finditer(r"(set security zones security-zone [A-Za-z0-9_-]{1,} address-book address-set ([A-Za-z0-9_-]{1,}) address-set ([A-Za-z0-9_-]{1,}))", config):
    print "object-group network " + addrSetNested.group(2) + "\n group-object " + addrSetNested.group(3)
    addresses[addrSetNested.group(2)] = {}
    addresses[addrSetNested.group(2)]['type'] = 'group'

# Convert security policies to access control lists

for policy in re.finditer(r"((set security policies from-zone ([A-Za-z0-9_-]{1,}) to-zone [A-Za-z0-9_-]{1,} policy ([A-Za-z0-9_-]{1,}) match source-address ([A-Za-z0-9_-]{1,})[\r\n]){1,}(set security policies from-zone [A-Za-z0-9_-]{1,} to-zone [A-Za-z0-9_-]{1,} policy [A-Za-z0-9_-]{1,} match destination-address ([A-Za-z0-9_-]{1,})[\r\n]){1,}(set security policies from-zone [A-Za-z0-9_-]{1,} to-zone [A-Za-z0-9_-]{1,} policy [A-Za-z0-9_-]{1,} match application [A-Za-z0-9_-]{1,}[\r\n]){1,}(set security policies from-zone [A-Za-z0-9_-]{1,} to-zone [A-Za-z0-9_-]{1,} policy [A-Za-z0-9_-]{1,} then (permit)|(reject)|(deny)){1,})", config):
    for policySrc in re.finditer(r"(set security policies from-zone [A-Za-z0-9_-]{1,} to-zone [A-Za-z0-9_-]{1,} policy [A-Za-z0-9_-]{1,} match source-address ([A-Za-z0-9_-]{1,}))", policy.group(1)):
        if addresses[policySrc.group(2)]['type'] == 'object':
            policySrcType = 'object '
        elif addresses[policySrc.group(2)]['type'] == 'group':
            policySrcType = 'object-group '
        elif addresses[policySrc.group(2)]['type'] == 'any':
            policySrcType = ''
        else:
            policySrcType = ''

        for policyDst in re.finditer(r"(set security policies from-zone [A-Za-z0-9_-]{1,} to-zone [A-Za-z0-9_-]{1,} policy [A-Za-z0-9_-]{1,} match destination-address ([A-Za-z0-9_-]{1,}))", policy.group(1)):
            if addresses[policyDst.group(2)]['type'] == 'object':
                policyDstType = 'object '
            elif addresses[policyDst.group(2)]['type'] == 'group':
                policyDstType = 'object-group '
            elif addresses[policyDst.group(2)]['type'] == 'any':
                policyDstType = ''
            else:
                policyDstType = ''

            for policyApp in re.finditer(r"(set security policies from-zone [A-Za-z0-9_-]{1,} to-zone [A-Za-z0-9_-]{1,} policy [A-Za-z0-9_-]{1,} match application ([A-Za-z0-9_-]{1,}))", policy.group(1)):
                if policyApp.group(2) == 'any':
                    print "access-list " + policy.group(3) + "_in extended permit " + applications[policyApp.group(2)]['protocol'] + " " + policySrcType + policySrc.group(2) + " " + policyDstType + policyDst.group(2)
                else:
                    if applications[policyApp.group(2)]['type'] == 'object':

                        if re.match(r"[0-9]{1,5} [0-9]{1,5}", applications[policyApp.group(2)]['port']) is not None:
                            portOperator = ' range '
                        elif re.match(r"[0-9]{1,5}", applications[policyApp.group(2)]['port']) is not None:
                            portOperator = ' eq '
                        else:
                            portOperator = ' '

                        print "access-list " + policy.group(3) + "_in extended permit " + applications[policyApp.group(2)]['protocol'] + " " + policySrcType + policySrc.group(2) + " " + policyDstType + policyDst.group(2) + portOperator + applications[policyApp.group(2)]['port']

                    elif applications[policyApp.group(2)]['type'] == 'group':
                        print "access-list " + policy.group(3) + "_in extended permit " + applications[policyApp.group(2)]['protocol'] + " " + policySrcType + policySrc.group(2) + " " + policyDstType + policyDst.group(2) + " object-group " + policyApp.group(2)

# Bind access control lists to interfaces

for key, value in localnetworks.iteritems():
    print "access-group " + value['seczone'] + "_in in interface " + value['seczone']
