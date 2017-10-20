$StockMultiWANWizardConfiguration = @"
set firewall all-ping enable
set firewall broadcast-ping disable
set firewall ipv6-receive-redirects disable
set firewall ipv6-src-route disable
set firewall ip-src-route disable
set firewall log-martians disable
set firewall modify balance rule 1 action modify
set firewall modify balance rule 1 modify lb-group G
set firewall name WAN_IN default-action drop
set firewall name WAN_IN description 'WAN to internal'
set firewall name WAN_IN rule 10 action accept
set firewall name WAN_IN rule 10 description 'Allow established/related'
set firewall name WAN_IN rule 10 state established enable
set firewall name WAN_IN rule 10 state related enable
set firewall name WAN_IN rule 20 action drop
set firewall name WAN_IN rule 20 description 'Drop invalid state'
set firewall name WAN_IN rule 20 state invalid enable
set firewall name WAN_LOCAL default-action drop
set firewall name WAN_LOCAL description 'WAN to router'
set firewall name WAN_LOCAL rule 10 action accept
set firewall name WAN_LOCAL rule 10 description 'Allow established/related'
set firewall name WAN_LOCAL rule 10 state established enable
set firewall name WAN_LOCAL rule 10 state related enable
set firewall name WAN_LOCAL rule 20 action drop
set firewall name WAN_LOCAL rule 20 description 'Drop invalid state'
set firewall name WAN_LOCAL rule 20 state invalid enable
set firewall receive-redirects disable
set firewall send-redirects enable
set firewall source-validation disable
set firewall syn-cookies enable
set interfaces ethernet eth0 address 38.95.4.145/26
set interfaces ethernet eth0 description 'Internet - WAN'
set interfaces ethernet eth0 duplex auto
set interfaces ethernet eth0 firewall in name WAN_IN
set interfaces ethernet eth0 firewall local name WAN_LOCAL
set interfaces ethernet eth0 speed auto
set interfaces ethernet eth1 address 96.243.198.59/24
set interfaces ethernet eth1 description 'Internet - WAN 2'
set interfaces ethernet eth1 duplex auto
set interfaces ethernet eth1 firewall in name WAN_IN
set interfaces ethernet eth1 firewall local name WAN_LOCAL
set interfaces ethernet eth1 speed auto
set interfaces ethernet eth2 description Local
set interfaces ethernet eth2 duplex auto
set interfaces ethernet eth2 speed auto
set interfaces ethernet eth3 description Local
set interfaces ethernet eth3 duplex auto
set interfaces ethernet eth3 speed auto
set interfaces ethernet eth4 description Local
set interfaces ethernet eth4 duplex auto
set interfaces ethernet eth4 speed auto
set interfaces loopback lo
set interfaces switch switch0 address 192.168.1.1/24
set interfaces switch switch0 description Local
set interfaces switch switch0 firewall in modify balance
set interfaces switch switch0 mtu 1500
set interfaces switch switch0 switch-port interface eth2
set interfaces switch switch0 switch-port interface eth3
set interfaces switch switch0 switch-port interface eth4
set load-balance group G interface eth0
set load-balance group G interface eth1
set protocols static route 0.0.0.0/0 next-hop 38.95.4.129
set protocols static route 0.0.0.0/0 next-hop 96.243.198.1
set service dhcp-server disabled false
set service dhcp-server hostfile-update disable
set service dhcp-server shared-network-name LAN authoritative enable
set service dhcp-server shared-network-name LAN subnet 192.168.1.0/24 default-router 192.168.1.1
set service dhcp-server shared-network-name LAN subnet 192.168.1.0/24 dns-server 192.168.1.1
set service dhcp-server shared-network-name LAN subnet 192.168.1.0/24 lease 86400
set service dhcp-server shared-network-name LAN subnet 192.168.1.0/24 start 192.168.1.38 stop 192.168.1.243
set service dns forwarding cache-size 150
set service dns forwarding listen-on switch0
set service gui https-port 443
set service nat rule 5000 description 'masquerade for WAN'
set service nat rule 5000 outbound-interface eth0
set service nat rule 5000 type masquerade
set service nat rule 5002 description 'masquerade for WAN 2'
set service nat rule 5002 outbound-interface eth1
set service nat rule 5002 type masquerade
set service ssh port 22
set service ssh protocol-version v2
set system conntrack expect-table-size 4096
set system conntrack hash-size 4096
set system conntrack table-size 32768
set system conntrack tcp half-open-connections 512
set system conntrack tcp loose enable
set system conntrack tcp max-retrans 3
set system host-name ubnt
set system login user ubnt authentication encrypted-password '`$1$zKNoUbAo$gomzUbYvgyUMcD436Wo66.'
set system login user ubnt level admin
set system name-server 8.8.8.8
set system ntp server 0.ubnt.pool.ntp.org
set system ntp server 1.ubnt.pool.ntp.org
set system ntp server 2.ubnt.pool.ntp.org
set system ntp server 3.ubnt.pool.ntp.org
set system syslog global facility all level notice
set system syslog global facility protocols level debug
set system time-zone UTC
"@ -split "`r`n"

$DefaultConfiguration = @"
set interfaces ethernet eth0 address 192.168.1.1/24
set interfaces ethernet eth0 duplex auto
set interfaces ethernet eth0 speed auto
set interfaces ethernet eth1 duplex auto
set interfaces ethernet eth1 speed auto
set interfaces ethernet eth2 duplex auto
set interfaces ethernet eth2 speed auto
set interfaces ethernet eth3 duplex auto
set interfaces ethernet eth3 speed auto
set interfaces ethernet eth4 duplex auto
set interfaces ethernet eth4 speed auto
set interfaces loopback lo
set interfaces switch switch0 mtu 1500
set service gui https-port 443
set service ssh port 22
set service ssh protocol-version v2
set system host-name ubnt
set system login user ubnt authentication encrypted-password '`$1$zKNoUbAo$gomzUbYvgyUMcD436Wo66.'
set system login user ubnt level admin
set system ntp server 0.ubnt.pool.ntp.org
set system ntp server 1.ubnt.pool.ntp.org
set system ntp server 2.ubnt.pool.ntp.org
set system ntp server 3.ubnt.pool.ntp.org
set system syslog global facility all level notice
set system syslog global facility protocols level debug
set system time-zone UTC
"@ -split "`r`n"

Compare-Object $DefaultConfiguration $StockMultiWANWizardConfiguration | 
where sideindicator -EQ => | 
select -ExpandProperty inputobject

$ConfigurationThatIsDifferentThanStock = @"
set firewall all-ping enable
set firewall broadcast-ping disable
set firewall ipv6-receive-redirects disable
set firewall ipv6-src-route disable
set firewall ip-src-route disable
set firewall log-martians disable
set firewall modify balance rule 1 action modify
set firewall modify balance rule 1 modify lb-group G
set firewall name WAN_IN default-action drop
set firewall name WAN_IN description 'WAN to internal'
set firewall name WAN_IN rule 10 action accept
set firewall name WAN_IN rule 10 description 'Allow established/related'
set firewall name WAN_IN rule 10 state established enable
set firewall name WAN_IN rule 10 state related enable
set firewall name WAN_IN rule 20 action drop
set firewall name WAN_IN rule 20 description 'Drop invalid state'
set firewall name WAN_IN rule 20 state invalid enable
set firewall name WAN_LOCAL default-action drop
set firewall name WAN_LOCAL description 'WAN to router'
set firewall name WAN_LOCAL rule 10 action accept
set firewall name WAN_LOCAL rule 10 description 'Allow established/related'
set firewall name WAN_LOCAL rule 10 state established enable
set firewall name WAN_LOCAL rule 10 state related enable
set firewall name WAN_LOCAL rule 20 action drop
set firewall name WAN_LOCAL rule 20 description 'Drop invalid state'
set firewall name WAN_LOCAL rule 20 state invalid enable
set firewall receive-redirects disable
set firewall send-redirects enable
set firewall source-validation disable
set firewall syn-cookies enable
set interfaces ethernet eth0 firewall in name WAN_IN
set interfaces ethernet eth0 firewall local name WAN_LOCAL
set interfaces ethernet eth1 firewall in name WAN_IN
set interfaces ethernet eth1 firewall local name WAN_LOCAL
set load-balance group G interface eth0
set load-balance group G interface eth1
set service nat rule 5000 description 'masquerade for WAN'
set service nat rule 5000 outbound-interface eth0
set service nat rule 5000 type masquerade
set service nat rule 5002 description 'masquerade for WAN 2'
set service nat rule 5002 outbound-interface eth1
set service nat rule 5002 type masquerade
set system conntrack expect-table-size 4096
set system conntrack hash-size 4096
set system conntrack table-size 32768
set system conntrack tcp half-open-connections 512
set system conntrack tcp loose enable
set system conntrack tcp max-retrans 3
set system name-server 8.8.8.8
"@