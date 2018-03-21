$NetworkNodeDefinitionToHardwareMapping = [PSCustomObject][Ordered]@{
    ComputerName = "INF-EdgeRouter01"
    HardwareSerialNumber = ""
},
[PSCustomObject][Ordered]@{
    ComputerName = "INF-EdgeRouter02"
    HardwareSerialNumber = ""
},
[PSCustomObject][Ordered]@{
    ComputerName = "INF-EdgeRouter03"
    HardwareSerialNumber = ""
},
[PSCustomObject][Ordered]@{
    ComputerName = "INF-EdgeRouter04"
    HardwareSerialNumber = "F09FC2DF0294"
},
[PSCustomObject][Ordered]@{
    ComputerName = "INF-EdgeRouterUBLab01"
    HardwareSerialNumber = "F09FC2DF00D2"
},
[PSCustomObject][Ordered]@{
    ComputerName = "INF-EdgeRouterUBLab02"
    HardwareSerialNumber = "F09FC2DF02B2"
},
[PSCustomObject][Ordered]@{
    ComputerName = "INF-EdgeRouterUBLab03"
    HardwareSerialNumber = "F09FC2DF00E4"
},
[PSCustomObject][Ordered]@{
    ComputerName = "INF-ERWAN01"
    HardwareSerialNumber = "788A2043AA00"
},
[PSCustomObject][Ordered]@{
    ComputerName = "INF-VYOS01"
    HardwareSerialNumber = "00155d00050c"
},
[PSCustomObject][Ordered]@{
    ComputerName = "INF-VYOS02"
    HardwareSerialNumber = "c81f66e82fec"
},
[PSCustomObject][Ordered]@{
    ComputerName = "INF-ERWAN02"
    HardwareSerialNumber = "1721k788a204095a9"
}

$NetworkNodeDefinition = [PSCustomObject][Ordered]@{
    ComputerName = "INF-EdgeRouter01"
    OperatingSystemName = "EdgeOS"
    ManagementIPAddress = "192.168.1.1"
    InterfaceDefinition = [PSCustomObject][Ordered]@{
        Name = "eth1"
        Address = "172.16.0.1/24"
    },
    [PSCustomObject][Ordered]@{
        Name = "eth4"
        Address = "dhcp"
    }
    StaticRoute = [PSCustomObject][Ordered]@{
        Address = "0.0.0.0/0"
        NextHop = "172.16.0.2"
    }    
},
[PSCustomObject][Ordered]@{
    ComputerName = "INF-EdgeRouter02"
    OperatingSystemName = "EdgeOS"
    ManagementIPAddress = "192.168.1.1"
    InterfaceDefinition = [PSCustomObject][Ordered]@{
        Name = "eth1"
        Address = "172.16.0.2/2"
    },
    [PSCustomObject][Ordered]@{
        Name = "eth2"
        Address = "172.16.1.1/24"
    },
    [PSCustomObject][Ordered]@{
        Name = "eth4"
        Address = "dhcp"
    }
    TunnelMemberDefinition = [PSCustomObject][Ordered]@{
        TunnelName = "Tunnel01"
        TunnelSide = "Left"
    }
    #This will be replaced with iBGP
    StaticRoute = [PSCustomObject][Ordered]@{
        Address = "172.16.2.0/24"
        NextHop = "192.168.0.2"
    }    
},
[PSCustomObject][Ordered]@{
    ComputerName = "INF-EdgeRouter03"
    OperatingSystemName = "EdgeOS"
    ManagementIPAddress = "192.168.1.1"
    InterfaceDefinition = [PSCustomObject][Ordered]@{
        Name = "eth1"
        Address = "172.16.1.2/24"
    },
    [PSCustomObject][Ordered]@{
        Name = "eth2"
       Address = "172.16.2.1/24"
    },
    [PSCustomObject][Ordered]@{
        Name = "eth4"
        Address = "dhcp"
    }
    TunnelMemberDefinition = [PSCustomObject][Ordered]@{
        TunnelName = "Tunnel01"
        TunnelSide = "Right"
    }
    #This will be replaced with iBGP
    StaticRoute = [PSCustomObject][Ordered]@{
        Address = "172.16.0.0/24"
        NextHop = "192.168.0.1"
    }
},
[PSCustomObject][Ordered]@{
    ComputerName = "INF-EdgeRouter04"
    OperatingSystemName = "EdgeOS"
    ManagementIPAddress = "192.168.1.1"
    InterfaceDefinition = [PSCustomObject][Ordered]@{
        Name = "eth1"
        Address = "172.16.2.2/24"
    },
    [PSCustomObject][Ordered]@{
        Name = "eth4"
        Address = "dhcp"
    }
    StaticRoute = [PSCustomObject][Ordered]@{
        Address = "0.0.0.0/0"
        NextHop = "172.16.2.1"
    }
},
[PSCustomObject][Ordered]@{
    ComputerName = "INF-EdgeRouterUBLab01"
    OperatingSystemName = "EdgeOS"
    ManagementIPAddress = "192.168.1.1"
    InterfaceDefinition = [PSCustomObject][Ordered]@{
        Name = "eth1"
        Address = "203.0.113.1/24"
    },
    [PSCustomObject][Ordered]@{
        Name = "eth2"
        Address = "172.16.2.1/24"
    },
    [PSCustomObject][Ordered]@{
        Name = "eth4"
        Address = "dhcp"
    }
    StaticRoute = [PSCustomObject][Ordered]@{
        Address = "0.0.0.0/0"
        NextHop = "203.0.113.2"
    }
    TunnelMemberDefinition = [PSCustomObject][Ordered]@{
        TunnelName = "Tunnel02"
        TunnelSide = "Left"
    }
},
[PSCustomObject][Ordered]@{
    ComputerName = "INF-EdgeRouterUBLab02"
    OperatingSystemName = "EdgeOS"
    ManagementIPAddress = "192.168.1.1"
    InterfaceDefinition = [PSCustomObject][Ordered]@{
        Name = "eth1"
        Address = "192.0.2.1/24"
    },
    [PSCustomObject][Ordered]@{
        Name = "eth2"
        Address = "172.16.1.1/24"
    },
    [PSCustomObject][Ordered]@{
        Name = "eth4"
        Address = "dhcp"
    }
    StaticRoute = [PSCustomObject][Ordered]@{
        Address = "0.0.0.0/0"
        NextHop = "192.0.2.2"
    }
    TunnelMemberDefinition = [PSCustomObject][Ordered]@{
        TunnelName = "Tunnel02"
        TunnelSide = "Right"
    }
},
[PSCustomObject][Ordered]@{
    ComputerName = "INF-EdgeRouterUBLab03"
    OperatingSystemName = "EdgeOS"
    ManagementIPAddress = "192.168.1.1"
    InterfaceDefinition = [PSCustomObject][Ordered]@{
        Name = "eth1"
        Address = "203.0.113.2/24"
    },
    [PSCustomObject][Ordered]@{
        Name = "eth2"
        Address = "192.0.2.2/24"
    },
    [PSCustomObject][Ordered]@{
        Name = "eth4"
        Address = "dhcp"
    }
},
#[PSCustomObject][Ordered]@{
#    ComputerName = "INF-ERWAN01"
#    OperatingSystemName = "EdgeOS"
#    ManagementIPAddress = "INF-ERWAN01"
#    PasswordID = 5135
#    InterfaceDefinition = [PSCustomObject][Ordered]@{
#        Name = "eth0"
#        Address = "10.172.48.148/24"
#    },
#    [PSCustomObject][Ordered]@{
#        Name = "eth1"
#        Address = "38.95.4.145/26"
#    },
#    [PSCustomObject][Ordered]@{
#        Name = "eth2"
#        Address = "96.243.198.59/24"
#    },
#    [PSCustomObject][Ordered]@{
#        Name = "eth3"
#        Address = "100.3.102.12/24"
#    },
#    [PSCustomObject][Ordered]@{
#        Name = "eth4"
#        Address = "192.168.1.1/24"
#    }
#    StaticRoute = [PSCustomObject][Ordered]@{
#        Address = "0.0.0.0/0"
#        NextHop = "38.95.4.129"
#    },
#    [PSCustomObject][Ordered]@{
#        Address = "0.0.0.0/0"
#        NextHop = "96.243.198.1"
#    },
#    [PSCustomObject][Ordered]@{
#        Address = "0.0.0.0/0"
#        NextHop = "100.3.102.1"
#    },
#    [PSCustomObject][Ordered]@{
#        Address = "10.16.0.0/24"
#        NextHop = "10.172.48.250"
#    },
#    [PSCustomObject][Ordered]@{
#        Address = "10.4.0.0/16"
#        NextHop = "10.172.48.250"
#    },
#    [PSCustomObject][Ordered]@{
#        Address = "10.128.1.0/24"
#        NextHop = "10.172.48.250"
#    },
#    [PSCustomObject][Ordered]@{
#        Address = "10.2.2.0/24"
#        NextHop = "10.172.48.250"
#    },
#    [PSCustomObject][Ordered]@{
#        Address = "10.200.0.0/24"
#        NextHop = "10.172.48.250"
#    },
#    [PSCustomObject][Ordered]@{
#        Address = "10.54.0.0/19"
#        NextHop = "10.172.48.250"
#    },
#    [PSCustomObject][Ordered]@{
#        Address = "10.128.0.0/24"
#        NextHop = "10.172.48.250"
#    },
#    [PSCustomObject][Ordered]@{
#        Address = "10.32.0.0/24"
#        NextHop = "10.172.48.250"
#    },
#    [PSCustomObject][Ordered]@{
#        Address = "10.40.0.0/24"
#        NextHop = "10.172.48.250"
#    },
#    [PSCustomObject][Ordered]@{
#        Address = "10.64.0.0/16"
#        NextHop = "10.172.48.250"
#    },
#    [PSCustomObject][Ordered]@{
#        Address = "10.200.2.0/24"
#        NextHop = "10.172.48.250"
#    },
#    [PSCustomObject][Ordered]@{
#        Address = "10.92.2.0/24"
#        NextHop = "10.172.48.250"
#    },
#    [PSCustomObject][Ordered]@{
#        Address = "10.55.1.0/24"
#        NextHop = "10.172.48.250"
#    },
#    [PSCustomObject][Ordered]@{
#        Address = "10.172.0.0/16"
#        NextHop = "10.172.48.250"
#    }
#    AdditionalCommands = @"
#set firewall all-ping enable
#set firewall broadcast-ping disable
#set firewall ipv6-receive-redirects disable
#set firewall ipv6-src-route disable
#set firewall ip-src-route disable
#set firewall log-martians disable
#set firewall group network-group LAN_NETS network 10.2.2.0/24
#set firewall group network-group LAN_NETS network 10.4.0.0/16
#set firewall group network-group LAN_NETS network 10.16.0.0/24
#set firewall group network-group LAN_NETS network 10.32.0.0/24
#set firewall group network-group LAN_NETS network 10.40.0.0/24
#set firewall group network-group LAN_NETS network 10.54.0.0/19
#set firewall group network-group LAN_NETS network 10.55.1.0/24
#set firewall group network-group LAN_NETS network 10.64.0.0/16
#set firewall group network-group LAN_NETS network 10.92.2.0/24
#set firewall group network-group LAN_NETS network 10.128.0.0/24
#set firewall group network-group LAN_NETS network 10.128.1.0/24
#set firewall group network-group LAN_NETS network 10.172.0.0/16
#set firewall group network-group LAN_NETS network 10.200.0.0/24
#set firewall group network-group LAN_NETS network 10.200.2.0/24
#set firewall modify balance rule 10 destination group network-group LAN_NETS
#set firewall modify balance rule 10 action modify
#set firewall modify balance rule 10 modify table main
#set firewall modify balance rule 20 action modify
#set firewall modify balance rule 20 modify lb-group G
#set firewall name WAN_IN default-action drop
#set firewall name WAN_IN description 'WAN to internal'
#set firewall name WAN_IN rule 10 action accept
#set firewall name WAN_IN rule 10 description 'Allow established/related'
#set firewall name WAN_IN rule 10 state established enable
#set firewall name WAN_IN rule 10 state related enable
#set firewall name WAN_IN rule 20 action drop
#set firewall name WAN_IN rule 20 description 'Drop invalid state'
#set firewall name WAN_IN rule 20 state invalid enable
#set firewall name WAN_LOCAL default-action drop
#set firewall name WAN_LOCAL description 'WAN to router'
#set firewall name WAN_LOCAL rule 10 action accept
#set firewall name WAN_LOCAL rule 10 description 'Allow established/related'
#set firewall name WAN_LOCAL rule 10 state established enable
#set firewall name WAN_LOCAL rule 10 state related enable
#set firewall name WAN_LOCAL rule 20 action drop
#set firewall name WAN_LOCAL rule 20 description 'Drop invalid state'
#set firewall name WAN_LOCAL rule 20 state invalid enable
#set firewall receive-redirects disable
#set firewall send-redirects enable
#set firewall source-validation disable
#set firewall syn-cookies enable
#set interfaces ethernet eth1 description 'Cogent'
#set interfaces ethernet eth1 firewall in name WAN_IN
#set interfaces ethernet eth1 firewall local name WAN_LOCAL
#set interfaces ethernet eth2 description 'Fios25'
#set interfaces ethernet eth2 firewall in name WAN_IN
#set interfaces ethernet eth2 firewall local name WAN_LOCAL
#set interfaces ethernet eth3 description 'Fios150'
#set interfaces ethernet eth3 firewall in name WAN_IN
#set interfaces ethernet eth3 firewall local name WAN_LOCAL
#set interfaces ethernet eth0 description 'Infrastructure'
#set interfaces ethernet eth0 firewall in modify balance
#set interfaces ethernet eth4 firewall in modify balance
#set load-balance group G interface eth1
#set load-balance group G interface eth1 weight 20
#set load-balance group G interface eth2
#set load-balance group G interface eth2 weight 30
#set load-balance group G interface eth3
#set load-balance group G interface eth3 weight 50
#set service nat rule 5000 description 'masquerade for WAN'
#set service nat rule 5000 outbound-interface eth1
#set service nat rule 5000 type masquerade
#set service nat rule 5002 description 'masquerade for WAN 2'
#set service nat rule 5002 outbound-interface eth2
#set service nat rule 5002 type masquerade
#set service nat rule 5003 description 'masquerade for WAN 3'
#set service nat rule 5003 outbound-interface eth3
#set service nat rule 5003 type masquerade
#set system conntrack expect-table-size 4096
#set system conntrack hash-size 4096
#set system conntrack table-size 32768
#set system conntrack tcp half-open-connections 512
#set system conntrack tcp loose enable
#set system conntrack tcp max-retrans 3
#set system name-server 8.8.8.8
#set system offload hwnat enable
#"@
#},
[PSCustomObject][Ordered]@{
    TemplateName = "INF-ERWAN"
    ComputerName = "INF-ERWAN01"
    ManagementIPAddress = "INF-ERWAN01"
    InterfaceDefinition = [PSCustomObject][Ordered]@{
        Name = "eth1"
        Description = "Fios25"
        VIFVlan = 21
        Address = "96.243.198.62/24"
    },
    [PSCustomObject][Ordered]@{
        Name = "eth1"
        Description = "Cogent"
        VIFVlan = 28
        Address = "38.95.4.141/26"
    },
    [PSCustomObject][Ordered]@{
        Name = "eth1"
        Description = "Fios150"
        VIFVlan = 20
        Address = "100.3.102.4/24"
    },
    [PSCustomObject][Ordered]@{
        Name = "eth2"
        VIFVlan = 48
        Description = "Infrastructure"
        Address = "10.172.48.78/24"
    },
    [PSCustomObject][Ordered]@{
        Name = "eth2"
        VIFVlan = 24
        Address = "10.172.26.24/21"
        Description = "StandardEndpoints"
    },
    [PSCustomObject][Ordered]@{
        Name = "eth2"
        VIFVlan = 12
        Address = "10.172.12.192/22"
        Description = "WifiData"
    },
    [PSCustomObject][Ordered]@{
        Name = "eth2"
        VIFVlan = 72
        Address = "10.172.72.5/22"
        Description = "WifiDataInternetOnly"
    }
},
[PSCustomObject][Ordered]@{
    ComputerName = "INF-ERWAN02"
    OperatingSystemName = "EdgeOS"
    ManagementIPAddress = "INF-ERWAN02"
    PasswordID = 5189
    InterfaceDefinition = [PSCustomObject][Ordered]@{
        Name = "eth0"
        Address = "192.168.1.1/24"
        LoadBalanceIngressTrafficDestinedToWAN = $True
    },
    [PSCustomObject][Ordered]@{
        Name = "eth3"
        Description = "Fios25"
        VIFVlan = 21
        Address = "96.243.198.61/24"
        UseForWANLoadBalancing = $True
        Weight = 50
        VRRPGroup = [PSCustomObject][Ordered]@{
            Number = 100
            VIP = "96.243.198.59/24"
            AuthenticationPasswordStateEntry = 5367
        }
    },
    [PSCustomObject][Ordered]@{
        Name = "eth3"
        Description = "Cogent"
        VIFVlan = 28
        Address = "38.95.4.140/26"
        UseForWANLoadBalancing = $True
        Weight = 30
        VRRPGroup = [PSCustomObject][Ordered]@{
            Number = 200
            VIP = "38.95.4.143/26"
            AuthenticationPasswordStateEntry = 5367
        }
    },
    [PSCustomObject][Ordered]@{
        Name = "eth3"
        Description = "Fios150"
        VIFVlan = 20
        Address = "100.3.102.6/24"
        UseForWANLoadBalancing = $True
        Weight = 50
        VRRPGroup = [PSCustomObject][Ordered]@{
            Number = 300
            VIP = "100.3.102.16/24"
            AuthenticationPasswordStateEntry = 5367
        }
    },
    [PSCustomObject][Ordered]@{
        Name = "eth4"
        VIFVlan = 48
        Description = "Infrastructure"
        Address = "10.172.48.150/24"
        LoadBalanceIngressTrafficDestinedToWAN = $True
        VRRPGroup = [PSCustomObject][Ordered]@{
            Number = 400
            VIP = "10.172.48.77/24"
            AuthenticationPasswordStateEntry = 5367
        }
    },
    [PSCustomObject][Ordered]@{
        Name = "eth4"
        VIFVlan = 24
        Address = "10.172.28.55/21"
        Description = "StandardEndpoints"
        LoadBalanceIngressTrafficDestinedToWAN = $True
        VRRPGroup = [PSCustomObject][Ordered]@{
            Number = 500
            VIP = "10.172.26.23/21"
            AuthenticationPasswordStateEntry = 5367
        }
    },
    [PSCustomObject][Ordered]@{
        Name = "eth4"
        VIFVlan = 12
        Address = "10.172.14.39/22"
        Description = "WifiData"
        LoadBalanceIngressTrafficDestinedToWAN = $True
        VRRPGroup = [PSCustomObject][Ordered]@{
            Number = 600
            VIP = "10.172.12.191/22"
            AuthenticationPasswordStateEntry = 5367
        }
    }
    StaticRoute = [PSCustomObject][Ordered]@{
        Address = "10.4.0.0/16"
        NextHop = "10.172.48.250"
    },
    [PSCustomObject][Ordered]@{
        Address = "10.128.1.0/24"
        NextHop = "10.172.48.250"
    },
    [PSCustomObject][Ordered]@{
        Address = "10.2.2.0/24"
        NextHop = "10.172.48.250"
    },
    [PSCustomObject][Ordered]@{
        Address = "10.200.0.0/24"
        NextHop = "10.172.48.250"
    },
    [PSCustomObject][Ordered]@{
        Address = "10.54.0.0/19"
        NextHop = "10.172.48.250"
    },
    [PSCustomObject][Ordered]@{
        Address = "10.128.0.0/24"
        NextHop = "10.172.48.250"
    },
    [PSCustomObject][Ordered]@{
        Address = "10.32.0.0/24"
        NextHop = "10.172.48.250"
    },
    [PSCustomObject][Ordered]@{
        Address = "10.64.0.0/16"
        NextHop = "10.172.48.250"
    },
    [PSCustomObject][Ordered]@{
        Address = "10.200.2.0/24"
        NextHop = "10.172.48.250"
    },
    [PSCustomObject][Ordered]@{
        Address = "10.55.1.0/24"
        NextHop = "10.172.48.250"
    },
    [PSCustomObject][Ordered]@{
        Address = "10.172.0.0/16"
        NextHop = "10.172.48.250"
    },
    [PSCustomObject][Ordered]@{
        Address = "0.0.0.0/0"
        NextHop = "38.95.4.129"
    },
    [PSCustomObject][Ordered]@{
        Address = "0.0.0.0/0"
        NextHop = "96.243.198.1"
    },
    [PSCustomObject][Ordered]@{
        Address = "0.0.0.0/0"
        NextHop = "100.3.102.1"
    }
    AdditionalCommands = @"
set firewall all-ping enable
set firewall broadcast-ping disable
set firewall ipv6-receive-redirects disable
set firewall ipv6-src-route disable
set firewall ip-src-route disable
set firewall log-martians disable
set firewall group network-group LAN_NETS network 10.2.2.0/24
set firewall group network-group LAN_NETS network 10.4.0.0/16
set firewall group network-group LAN_NETS network 10.16.0.0/24
set firewall group network-group LAN_NETS network 10.32.0.0/24
set firewall group network-group LAN_NETS network 10.40.0.0/24
set firewall group network-group LAN_NETS network 10.54.0.0/19
set firewall group network-group LAN_NETS network 10.55.1.0/24
set firewall group network-group LAN_NETS network 10.64.0.0/16
set firewall group network-group LAN_NETS network 10.92.2.0/24
set firewall group network-group LAN_NETS network 10.128.0.0/24
set firewall group network-group LAN_NETS network 10.128.1.0/24
set firewall group network-group LAN_NETS network 10.172.0.0/16
set firewall group network-group LAN_NETS network 10.200.0.0/24
set firewall group network-group LAN_NETS network 10.200.2.0/24
set firewall receive-redirects disable
set firewall send-redirects enable
set firewall source-validation disable
set firewall syn-cookies enable
set system conntrack expect-table-size 4096
set system conntrack hash-size 4096
set system conntrack table-size 32768
set system conntrack tcp half-open-connections 512
set system conntrack tcp loose enable
set system conntrack tcp max-retrans 3
set system name-server 8.8.8.8
set system offload ipv4 forwarding enable
set system offload ipv4 vlan enable
"@
},
[PSCustomObject][Ordered]@{
    ComputerName = "INF-VyOS01"
    OperatingSystemName = "VyOS"
    ManagementIPAddress = "10.172.48.43"
    PasswordID = 5139
    InterfaceDefinition = [PSCustomObject][Ordered]@{
        Name = "eth1"
        Address = "10.172.48.43/24"
    },
    [PSCustomObject][Ordered]@{
        Name = "eth0"
        Address = "38.95.4.140/26"
    },
    [PSCustomObject][Ordered]@{
        Name = "eth2"
        Address = "96.243.198.61/24"
    },
    [PSCustomObject][Ordered]@{
        Name = "eth3"
        Address = "100.3.102.6/24"
    }
    StaticRoute = [PSCustomObject][Ordered]@{
        Address = "0.0.0.0/0"
        NextHop = "38.95.4.129"
    },
    [PSCustomObject][Ordered]@{
        Address = "0.0.0.0/0"
        NextHop = "96.243.198.1"
    },
    [PSCustomObject][Ordered]@{
        Address = "0.0.0.0/0"
        NextHop = "100.3.102.1"
    },
    [PSCustomObject][Ordered]@{
        Address = "10.16.0.0/24"
        NextHop = "10.172.48.250"
    },
    [PSCustomObject][Ordered]@{
        Address = "10.4.0.0/16"
        NextHop = "10.172.48.250"
    },
    [PSCustomObject][Ordered]@{
        Address = "10.128.1.0/24"
        NextHop = "10.172.48.250"
    },
    [PSCustomObject][Ordered]@{
        Address = "10.2.2.0/24"
        NextHop = "10.172.48.250"
    },
    [PSCustomObject][Ordered]@{
        Address = "10.200.0.0/24"
        NextHop = "10.172.48.250"
    },
    [PSCustomObject][Ordered]@{
        Address = "10.54.0.0/19"
        NextHop = "10.172.48.250"
    },
    [PSCustomObject][Ordered]@{
        Address = "10.128.0.0/24"
        NextHop = "10.172.48.250"
    },
    [PSCustomObject][Ordered]@{
        Address = "10.32.0.0/24"
        NextHop = "10.172.48.250"
    },
    [PSCustomObject][Ordered]@{
        Address = "10.40.0.0/24"
        NextHop = "10.172.48.250"
    },
    [PSCustomObject][Ordered]@{
        Address = "10.64.0.0/16"
        NextHop = "10.172.48.250"
    },
    [PSCustomObject][Ordered]@{
        Address = "10.200.2.0/24"
        NextHop = "10.172.48.250"
    },
    [PSCustomObject][Ordered]@{
        Address = "10.92.2.0/24"
        NextHop = "10.172.48.250"
    },
    [PSCustomObject][Ordered]@{
        Address = "10.55.1.0/24"
        NextHop = "10.172.48.250"
    },
    [PSCustomObject][Ordered]@{
        Address = "10.172.0.0/16"
        NextHop = "10.172.48.250"
    }
    AdditionalCommands = @"
set firewall all-ping enable
set firewall broadcast-ping disable
set firewall ipv6-receive-redirects disable
set firewall ipv6-src-route disable
set firewall ip-src-route disable
set firewall log-martians disable
set firewall group network-group LAN_NETS network 10.2.2.0/24
set firewall group network-group LAN_NETS network 10.4.0.0/16
set firewall group network-group LAN_NETS network 10.16.0.0/24
set firewall group network-group LAN_NETS network 10.32.0.0/24
set firewall group network-group LAN_NETS network 10.40.0.0/24
set firewall group network-group LAN_NETS network 10.54.0.0/19
set firewall group network-group LAN_NETS network 10.55.1.0/24
set firewall group network-group LAN_NETS network 10.64.0.0/16
set firewall group network-group LAN_NETS network 10.92.2.0/24
set firewall group network-group LAN_NETS network 10.128.0.0/24
set firewall group network-group LAN_NETS network 10.128.1.0/24
set firewall group network-group LAN_NETS network 10.172.0.0/16
set firewall group network-group LAN_NETS network 10.200.0.0/24
set firewall group network-group LAN_NETS network 10.200.2.0/24
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
set interfaces ethernet eth0 description 'Cogent'
set interfaces ethernet eth0 firewall in name WAN_IN
set interfaces ethernet eth0 firewall local name WAN_LOCAL
set interfaces ethernet eth2 description 'Fios25'
set interfaces ethernet eth2 firewall in name WAN_IN
set interfaces ethernet eth2 firewall local name WAN_LOCAL
set interfaces ethernet eth3 description 'Fios150'
set interfaces ethernet eth3 firewall in name WAN_IN
set interfaces ethernet eth3 firewall local name WAN_LOCAL
set interfaces ethernet eth1 description 'Infrastructure'
set nat source rule 5000 description 'masquerade for WAN'
set nat source rule 5000 outbound-interface eth0
set nat source rule 5000 translation address masquerade
set nat source rule 5002 description 'masquerade for WAN 2'
set nat source rule 5002 outbound-interface eth2
set nat source rule 5002 translation address masquerade
set nat source rule 5003 description 'masquerade for WAN 3'
set nat source rule 5003 outbound-interface eth3
set nat source rule 5003 translation address masquerade
set system conntrack expect-table-size 4096
set system conntrack hash-size 4096
set system conntrack table-size 32768
set system conntrack tcp half-open-connections 512
set system conntrack tcp loose enable
set system conntrack tcp max-retrans 3
set system name-server 8.8.8.8
set load-balancing wan rule 5 exclude
set load-balancing wan rule 5 inbound-interface eth1
set load-balancing wan rule 5 destination address 10.2.2.0/24
set load-balancing wan rule 6 exclude
set load-balancing wan rule 6 inbound-interface eth1
set load-balancing wan rule 6 destination address 10.4.0.0/16
set load-balancing wan rule 7 exclude
set load-balancing wan rule 7 inbound-interface eth1
set load-balancing wan rule 7 destination address 10.16.0.0/24
set load-balancing wan rule 8 exclude
set load-balancing wan rule 8 inbound-interface eth1
set load-balancing wan rule 8 destination address 10.32.0.0/24
set load-balancing wan rule 9 exclude
set load-balancing wan rule 9 inbound-interface eth1
set load-balancing wan rule 9 destination address 10.40.0.0/24
set load-balancing wan rule 10 exclude
set load-balancing wan rule 10 inbound-interface eth1
set load-balancing wan rule 10 destination address 10.54.0.0/19
set load-balancing wan rule 11 exclude
set load-balancing wan rule 11 inbound-interface eth1
set load-balancing wan rule 11 destination address 10.55.1.0/24
set load-balancing wan rule 12 exclude
set load-balancing wan rule 12 inbound-interface eth1
set load-balancing wan rule 12 destination address 10.64.0.0/16
set load-balancing wan rule 13 exclude
set load-balancing wan rule 13 inbound-interface eth1
set load-balancing wan rule 13 destination address 10.92.2.0/24
set load-balancing wan rule 14 exclude
set load-balancing wan rule 14 inbound-interface eth1
set load-balancing wan rule 14 destination address 10.128.0.0/24
set load-balancing wan rule 15 exclude
set load-balancing wan rule 15 inbound-interface eth1
set load-balancing wan rule 15 destination address 10.128.1.0/24
set load-balancing wan rule 16 exclude
set load-balancing wan rule 16 inbound-interface eth1
set load-balancing wan rule 16 destination address 10.172.0.0/16
set load-balancing wan rule 17 exclude
set load-balancing wan rule 17 inbound-interface eth1
set load-balancing wan rule 17 destination address 10.200.0.0/24
set load-balancing wan rule 18 exclude
set load-balancing wan rule 18 inbound-interface eth1
set load-balancing wan rule 18 destination address 10.200.2.0/24
set load-balancing wan rule 100 inbound-interface eth1
set load-balancing wan rule 100 interface eth0
set load-balancing wan rule 100 interface eth2
set load-balancing wan rule 100 interface eth3
set load-balancing wan rule 100 interface eth0 weight 10
set load-balancing wan rule 100 interface eth2 weight 90
set load-balancing wan rule 100 interface eth3 weight 0
set load-balancing wan interface-health eth0 failure-count 3
set load-balancing wan interface-health eth0 nexthop 38.95.4.129
set load-balancing wan interface-health eth0 test 10 type ping
set load-balancing wan interface-health eth0 test 10 target 8.8.8.8
set load-balancing wan interface-health eth2 failure-count 3
set load-balancing wan interface-health eth2 nexthop 96.243.198.1
set load-balancing wan interface-health eth2 test 10 type ping
set load-balancing wan interface-health eth2 test 10 target 8.8.4.4
set load-balancing wan interface-health eth3 failure-count 3
set load-balancing wan interface-health eth3 nexthop 100.3.102.1
set load-balancing wan interface-health eth3 test 10 type ping
set load-balancing wan interface-health eth3 test 10 target 4.2.2.2
"@
},
[PSCustomObject][Ordered]@{
    ComputerName = "INF-VyOS02"
    OperatingSystemName = "VyOS"
    ManagementIPAddress = "10.172.48.151"
    PasswordID = 5174
    InterfaceDefinition = [PSCustomObject][Ordered]@{
        Name = "eth0"
        Address = "10.172.48.43/24"
    },
    [PSCustomObject][Ordered]@{
        Name = "eth1"
        Address = "38.95.4.140/26"
    },
    [PSCustomObject][Ordered]@{
        Name = "eth2"
        Address = "96.243.198.61/24"
    },
    [PSCustomObject][Ordered]@{
        Name = "eth3"
        Address = "100.3.102.6/24"
    }
    StaticRoute = [PSCustomObject][Ordered]@{
        Address = "10.16.0.0/24"
        NextHop = "10.172.48.250"
    },
    [PSCustomObject][Ordered]@{
        Address = "10.4.0.0/16"
        NextHop = "10.172.48.250"
    },
    [PSCustomObject][Ordered]@{
        Address = "10.128.1.0/24"
        NextHop = "10.172.48.250"
    },
    [PSCustomObject][Ordered]@{
        Address = "10.2.2.0/24"
        NextHop = "10.172.48.250"
    },
    [PSCustomObject][Ordered]@{
        Address = "10.200.0.0/24"
        NextHop = "10.172.48.250"
    },
    [PSCustomObject][Ordered]@{
        Address = "10.54.0.0/19"
        NextHop = "10.172.48.250"
    },
    [PSCustomObject][Ordered]@{
        Address = "10.128.0.0/24"
        NextHop = "10.172.48.250"
    },
    [PSCustomObject][Ordered]@{
        Address = "10.32.0.0/24"
        NextHop = "10.172.48.250"
    },
    [PSCustomObject][Ordered]@{
        Address = "10.40.0.0/24"
        NextHop = "10.172.48.250"
    },
    [PSCustomObject][Ordered]@{
        Address = "10.64.0.0/16"
        NextHop = "10.172.48.250"
    },
    [PSCustomObject][Ordered]@{
        Address = "10.200.2.0/24"
        NextHop = "10.172.48.250"
    },
    [PSCustomObject][Ordered]@{
        Address = "10.92.2.0/24"
        NextHop = "10.172.48.250"
    },
    [PSCustomObject][Ordered]@{
        Address = "10.55.1.0/24"
        NextHop = "10.172.48.250"
    },
    [PSCustomObject][Ordered]@{
        Address = "10.172.0.0/16"
        NextHop = "10.172.48.250"
    },
    [PSCustomObject][Ordered]@{
        Address = "0.0.0.0/0"
        NextHop = "38.95.4.129"
    },
    [PSCustomObject][Ordered]@{
        Address = "0.0.0.0/0"
        NextHop = "96.243.198.1"
    },
    [PSCustomObject][Ordered]@{
        Address = "0.0.0.0/0"
        NextHop = "100.3.102.1"
    }
    AdditionalCommands = @"
set firewall all-ping enable
set firewall broadcast-ping disable
set firewall ipv6-receive-redirects disable
set firewall ipv6-src-route disable
set firewall ip-src-route disable
set firewall log-martians disable
set firewall group network-group LAN_NETS network 10.2.2.0/24
set firewall group network-group LAN_NETS network 10.4.0.0/16
set firewall group network-group LAN_NETS network 10.16.0.0/24
set firewall group network-group LAN_NETS network 10.32.0.0/24
set firewall group network-group LAN_NETS network 10.40.0.0/24
set firewall group network-group LAN_NETS network 10.54.0.0/19
set firewall group network-group LAN_NETS network 10.55.1.0/24
set firewall group network-group LAN_NETS network 10.64.0.0/16
set firewall group network-group LAN_NETS network 10.92.2.0/24
set firewall group network-group LAN_NETS network 10.128.0.0/24
set firewall group network-group LAN_NETS network 10.128.1.0/24
set firewall group network-group LAN_NETS network 10.172.0.0/16
set firewall group network-group LAN_NETS network 10.200.0.0/24
set firewall group network-group LAN_NETS network 10.200.2.0/24
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
set interfaces ethernet eth1 description 'Cogent'
set interfaces ethernet eth1 firewall in name WAN_IN
set interfaces ethernet eth1 firewall local name WAN_LOCAL
set interfaces ethernet eth2 description 'Fios25'
set interfaces ethernet eth2 firewall in name WAN_IN
set interfaces ethernet eth2 firewall local name WAN_LOCAL
set interfaces ethernet eth3 description 'Fios150'
set interfaces ethernet eth3 firewall in name WAN_IN
set interfaces ethernet eth3 firewall local name WAN_LOCAL
set interfaces ethernet eth0 description 'Infrastructure'
set nat source rule 5000 description 'masquerade for WAN'
set nat source rule 5000 outbound-interface eth1
set nat source rule 5000 translation address masquerade
set nat source rule 5002 description 'masquerade for WAN 2'
set nat source rule 5002 outbound-interface eth2
set nat source rule 5002 translation address masquerade
set nat source rule 5003 description 'masquerade for WAN 3'
set nat source rule 5003 outbound-interface eth3
set nat source rule 5003 translation address masquerade
set system conntrack expect-table-size 4096
set system conntrack hash-size 4096
set system conntrack table-size 32768
set system conntrack tcp half-open-connections 512
set system conntrack tcp loose enable
set system conntrack tcp max-retrans 3
set system name-server 8.8.8.8
set load-balancing wan rule 5 exclude
set load-balancing wan rule 5 inbound-interface eth0
set load-balancing wan rule 5 destination address 10.2.2.0/24
set load-balancing wan rule 6 exclude
set load-balancing wan rule 6 inbound-interface eth0
set load-balancing wan rule 6 destination address 10.4.0.0/16
set load-balancing wan rule 7 exclude
set load-balancing wan rule 7 inbound-interface eth0
set load-balancing wan rule 7 destination address 10.16.0.0/24
set load-balancing wan rule 8 exclude
set load-balancing wan rule 8 inbound-interface eth0
set load-balancing wan rule 8 destination address 10.32.0.0/24
set load-balancing wan rule 9 exclude
set load-balancing wan rule 9 inbound-interface eth0
set load-balancing wan rule 9 destination address 10.40.0.0/24
set load-balancing wan rule 10 exclude
set load-balancing wan rule 10 inbound-interface eth0
set load-balancing wan rule 10 destination address 10.54.0.0/19
set load-balancing wan rule 11 exclude
set load-balancing wan rule 11 inbound-interface eth0
set load-balancing wan rule 11 destination address 10.55.1.0/24
set load-balancing wan rule 12 exclude
set load-balancing wan rule 12 inbound-interface eth0
set load-balancing wan rule 12 destination address 10.64.0.0/16
set load-balancing wan rule 13 exclude
set load-balancing wan rule 13 inbound-interface eth0
set load-balancing wan rule 13 destination address 10.92.2.0/24
set load-balancing wan rule 14 exclude
set load-balancing wan rule 14 inbound-interface eth0
set load-balancing wan rule 14 destination address 10.128.0.0/24
set load-balancing wan rule 15 exclude
set load-balancing wan rule 15 inbound-interface eth0
set load-balancing wan rule 15 destination address 10.128.1.0/24
set load-balancing wan rule 16 exclude
set load-balancing wan rule 16 inbound-interface eth0
set load-balancing wan rule 16 destination address 10.172.0.0/16
set load-balancing wan rule 17 exclude
set load-balancing wan rule 17 inbound-interface eth0
set load-balancing wan rule 17 destination address 10.200.0.0/24
set load-balancing wan rule 18 exclude
set load-balancing wan rule 18 inbound-interface eth0
set load-balancing wan rule 18 destination address 10.200.2.0/24
set load-balancing wan rule 100 inbound-interface eth0
set load-balancing wan rule 100 interface eth1
set load-balancing wan rule 100 interface eth2
set load-balancing wan rule 100 interface eth3
set load-balancing wan rule 100 interface eth1 weight 50
set load-balancing wan rule 100 interface eth2 weight 50
set load-balancing wan rule 100 interface eth3 weight 50
set load-balancing wan interface-health eth1 failure-count 3
set load-balancing wan interface-health eth1 nexthop 38.95.4.129
set load-balancing wan interface-health eth1 test 10 type ping
set load-balancing wan interface-health eth1 test 10 target 8.8.8.8
set load-balancing wan interface-health eth2 failure-count 3
set load-balancing wan interface-health eth2 nexthop 96.243.198.1
set load-balancing wan interface-health eth2 test 10 type ping
set load-balancing wan interface-health eth2 test 10 target 8.8.4.4
set load-balancing wan interface-health eth3 failure-count 3
set load-balancing wan interface-health eth3 nexthop 100.3.102.1
set load-balancing wan interface-health eth3 test 10 type ping
set load-balancing wan interface-health eth3 test 10 target 4.2.2.2
"@
}

$NetworkNodeDefinitionTemplate = [PSCustomObject][Ordered]@{
    Name = "INF-ERWAN"
    OperatingSystemName = "EdgeOS"
    PasswordID = 5189
    InterfaceDefinition = [PSCustomObject][Ordered]@{
        Name = "eth0"
        Address = "192.168.1.1/24"
        LoadBalanceIngressTrafficDestinedToWAN = $True
    },
    [PSCustomObject][Ordered]@{
        Name = "eth1"
        Description = "Fios25"
        VIFVlan = 21
        UseForWANLoadBalancing = $True
        Weight = 0
        VRRPGroup = [PSCustomObject][Ordered]@{
            Number = 1
            VIP = "96.243.198.59/24"
            AuthenticationPasswordStateEntry = 5367
        }
    },
    [PSCustomObject][Ordered]@{
        Name = "eth1"
        Description = "Cogent"
        VIFVlan = 28
        UseForWANLoadBalancing = $True
        Weight = 0
        VRRPGroup = [PSCustomObject][Ordered]@{
            Number = 2
            VIP = "38.95.4.143/26"
            AuthenticationPasswordStateEntry = 5367
        }
    },
    [PSCustomObject][Ordered]@{
        Name = "eth1"
        Description = "Fios150"
        VIFVlan = 20
        UseForWANLoadBalancing = $True
        Weight = 100
        VRRPGroup = [PSCustomObject][Ordered]@{
            Number = 3
            VIP = "100.3.102.16/24"
            AuthenticationPasswordStateEntry = 5367
        }
    },
    [PSCustomObject][Ordered]@{
        Name = "eth2"
        VIFVlan = 48
        Description = "Infrastructure"
        LoadBalanceIngressTrafficDestinedToWAN = $True
        VRRPGroup = [PSCustomObject][Ordered]@{
            Number = 4
            VIP = "10.172.48.77/24"
            AuthenticationPasswordStateEntry = 5367
        }
    },
    [PSCustomObject][Ordered]@{
        Name = "eth2"
        VIFVlan = 24
        Description = "StandardEndpoints"
        LoadBalanceIngressTrafficDestinedToWAN = $True
        VRRPGroup = [PSCustomObject][Ordered]@{
            Number = 5
            VIP = "10.172.26.23/21"
            AuthenticationPasswordStateEntry = 5367
        }
    },
    [PSCustomObject][Ordered]@{
        Name = "eth2"
        VIFVlan = 12
        Description = "WifiData"
        LoadBalanceIngressTrafficDestinedToWAN = $True
        VRRPGroup = [PSCustomObject][Ordered]@{
            Number = 6
            VIP = "10.172.12.191/22"
            AuthenticationPasswordStateEntry = 5367
        }
    },
    [PSCustomObject][Ordered]@{
        Name = "eth2"
        VIFVlan = 72
        Description = "WifiDataInternetOnly"
        LoadBalanceIngressTrafficDestinedToWAN = $True
        VRRPGroup = [PSCustomObject][Ordered]@{
            Number = 7
            VIP = "10.172.72.6/22"
            AuthenticationPasswordStateEntry = 5367
        }
    }
    StaticRoute = [PSCustomObject][Ordered]@{
        Address = "10.4.0.0/16"
        NextHop = "10.172.48.250"
    },
    [PSCustomObject][Ordered]@{
        Address = "10.128.1.0/24"
        NextHop = "10.172.48.250"
    },
    [PSCustomObject][Ordered]@{
        Address = "10.2.2.0/24"
        NextHop = "10.172.48.250"
    },
    [PSCustomObject][Ordered]@{
        Address = "10.200.0.0/24"
        NextHop = "10.172.48.250"
    },
    [PSCustomObject][Ordered]@{
        Address = "10.54.0.0/19"
        NextHop = "10.172.48.250"
    },
    [PSCustomObject][Ordered]@{
        Address = "10.128.0.0/24"
        NextHop = "10.172.48.250"
    },
    [PSCustomObject][Ordered]@{
        Address = "10.32.0.0/24"
        NextHop = "10.172.48.250"
    },
    [PSCustomObject][Ordered]@{
        Address = "10.64.0.0/16"
        NextHop = "10.172.48.250"
    },
    [PSCustomObject][Ordered]@{
        Address = "10.200.2.0/24"
        NextHop = "10.172.48.250"
    },
    [PSCustomObject][Ordered]@{
        Address = "10.55.1.0/24"
        NextHop = "10.172.48.250"
    },
    [PSCustomObject][Ordered]@{
        Address = "10.172.0.0/16"
        NextHop = "10.172.48.250"
    },
    [PSCustomObject][Ordered]@{
        Address = "0.0.0.0/0"
        NextHop = "38.95.4.129"
    },
    [PSCustomObject][Ordered]@{
        Address = "0.0.0.0/0"
        NextHop = "96.243.198.1"
    },
    [PSCustomObject][Ordered]@{
        Address = "0.0.0.0/0"
        NextHop = "100.3.102.1"
    }
    AdditionalCommands = @"
set firewall all-ping enable
set firewall broadcast-ping disable
set firewall ipv6-receive-redirects disable
set firewall ipv6-src-route disable
set firewall ip-src-route disable
set firewall log-martians disable
set firewall group network-group LAN_NETS network 10.2.2.0/24
set firewall group network-group LAN_NETS network 10.4.0.0/16
set firewall group network-group LAN_NETS network 10.16.0.0/24
set firewall group network-group LAN_NETS network 10.32.0.0/24
set firewall group network-group LAN_NETS network 10.40.0.0/24
set firewall group network-group LAN_NETS network 10.54.0.0/19
set firewall group network-group LAN_NETS network 10.55.1.0/24
set firewall group network-group LAN_NETS network 10.64.0.0/16
set firewall group network-group LAN_NETS network 10.92.2.0/24
set firewall group network-group LAN_NETS network 10.128.0.0/24
set firewall group network-group LAN_NETS network 10.128.1.0/24
set firewall group network-group LAN_NETS network 10.172.0.0/16
set firewall group network-group LAN_NETS network 10.200.0.0/24
set firewall group network-group LAN_NETS network 10.200.2.0/24
set firewall receive-redirects disable
set firewall send-redirects disable
set firewall source-validation disable
set firewall syn-cookies enable
set system conntrack expect-table-size 4096
set system conntrack hash-size 4096
set system conntrack table-size 32768
set system conntrack tcp half-open-connections 512
set system conntrack tcp loose enable
set system conntrack tcp max-retrans 3
set system name-server 8.8.8.8
set system offload ipv4 forwarding enable
set system offload ipv4 vlan enable
"@
}

$NetworkNodeOperatingSystemTemplate = [PSCustomObject][Ordered]@{
    Name = "EdgeOS"
    DefaultCredential = 5002    
},
[PSCustomObject][Ordered]@{
    Name = "ArchLinux"
    DefaultCredential = 5178    
}

$TunnelDefinition = [PSCustomObject][Ordered]@{
    Name = "Tunnel01"
    LeftPeerIP = "172.16.1.1"
    RightPeerIP = "172.16.1.2"
    LeftVTIIP = "192.168.0.1"
    RightVTIIP = "192.168.0.2"
    VTIIPPrefixBits = 30    
    PreSharedSecret = "vyos"
    Phase1DHGroup = 19
    Phase1Encryption = "aes128"
    Phase1Hash = "sha256"
    Phase2Encryption = "aes128"
    Phase2Hash = "sha1"
},
[PSCustomObject][Ordered]@{
    Name = "Tunnel02"
    LeftPeerIP = "203.0.113.1"
    RightPeerIP = "192.0.2.1"
    LeftVTIIP = "10.255.12.1"
    RightVTIIP = "10.255.12.2"
    VTIIPPrefixBits = 30    
    PreSharedSecret = "vyos"
    Phase1DHGroup = 14
    Phase1Encryption = "aes256"
    Phase1Hash = "sha256"
    Phase2Encryption = "aes128"
    Phase2Hash = "md5"
}

$SystemImageDefinition = [PSCustomObject][Ordered]@{
    Version = "1.9.7+hotfix3"
    Path = "https://dl.ubnt.com/firmwares/edgemax/v1.9.7/ER-e50.v1.9.7+hotfix.3.5013617.tar"
}
