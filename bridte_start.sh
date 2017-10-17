#!/bin/bash
LAN_INT24="eth1" #Internal LAN Interface
BR_INT24="br24"  #Bridge Interface
ZT_INT24="zt0" #ZeroTier Interface

LAN_INT44="eth2" #Internal LAN Interface
BR_INT44="br44"  #Bridge Interface
ZT_INT44="zt1" #ZeroTier Interface

SLEEP_TIMER="20s"
RUN_TIME=`date`
#Delay Timer to give the system a chance to finish booting
sleep $SLEEP_TIMER

echo $RUN_TIME > /var/log/bridge.log

#Disable Interfaces, Remove IP addresses
echo "Disabling Interface" >> /var/log/bridge.log
/sbin/ifconfig $LAN_INT24 down >> /var/log/bridge.log
/sbin/ifconfig $LAN_INT44 down >> /var/log/bridge.log
/sbin/ifconfig $ZT_INT24 down >> /var/log/bridge.log
/sbin/ifconfig $ZT_INT44 down >> /var/log/bridge.log
/sbin/ip addr flush dev $LAN_INT24 >> /var/log/bridge.log
/sbin/ip addr flush dev $LAN_INT44 >> /var/log/bridge.log
/sbin/ip addr flush dev $ZT_INT24 >> /var/log/bridge.log
/sbin/ip addr flush dev $ZT_INT44 >> /var/log/bridge.log

echo "Setting up Bridging..." >> /var/log/bridge.log

/sbin/brctl addbr $BR_INT24 >> /var/log/bridge.log
/sbin/brctl addbr $BR_INT44 >> /var/log/bridge.log
/sbin/brctl addif $BR_INT24 $ZT_INT24 $LAN_INT24 >> /var/log/bridge.log
/sbin/brctl addif $BR_INT44 $ZT_INT44 $LAN_INT44 >> /var/log/bridge.log

/sbin/ifconfig $LAN_INT24 promisc up >> /var/log/bridge.log
/sbin/ifconfig $LAN_INT44 promisc up >> /var/log/bridge.log
/sbin/ifconfig $ZT_INT24 promisc up >> /var/log/bridge.log
/sbin/ifconfig $ZT_INT44 promisc up >> /var/log/bridge.log
/sbin/ifconfig $BR_INT24 up >> /var/log/bridge.log
/sbin/ifconfig $BR_INT44 up >> /var/log/bridge.log

service zerotier-one restart
sleep 5
/sbin/brctl addif $BR_INT24 $ZT_INT24 >> /var/log/bridge.log
/sbin/brctl addif $BR_INT44 $ZT_INT44 >> /var/log/bridge.log

echo "Finished!" >> /var/log/bridge.log
