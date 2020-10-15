#!/bin/sh

config="pass_persist .1.3.6.1.3.2020 /config/user-data/snmp-traffic-control"
echo "$config" >> /etc/snmp/snmpd.conf
