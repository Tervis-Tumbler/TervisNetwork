﻿$NetworkNodeDefinitionToHardwareMapping = [PSCustomObject][Ordered]@{
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
    HardwareSerialNumber = "F09FC2DF9F3A"
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
[PSCustomObject][Ordered]@{
    ComputerName = "INF-ERWAN01"
    OperatingSystemName = "EdgeOS"
    ManagementIPAddress = "192.168.1.1"
    PasswordID = 5135
    InterfaceDefinition = [PSCustomObject][Ordered]@{
        Name = "eth0"
        Address = "10.172.48.148/24"
    },
    [PSCustomObject][Ordered]@{
        Name = "eth1"
        Address = "38.95.4.145/26"
    },
    [PSCustomObject][Ordered]@{
        Name = "eth2"
        Address = "96.243.198.59/24"
    },
    [PSCustomObject][Ordered]@{
        Name = "eth3"
        Address = "100.3.102.12/24"
    },
    [PSCustomObject][Ordered]@{
        Name = "eth4"
        Address = "192.168.1.1/24"
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
        Address = "10.128.1.0/32"
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
set firewall group network-group LAN_NETS network 10.128.1.0/32
set firewall group network-group LAN_NETS network 10.172.0.0/16
set firewall group network-group LAN_NETS network 10.200.0.0/24
set firewall group network-group LAN_NETS network 10.200.2.0/24
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
set interfaces ethernet eth0 firewall in modify balance
set interfaces ethernet eth4 firewall in modify balance
set load-balance group G interface eth1
set load-balance group G interface eth2
set load-balance group G interface eth3
set service nat rule 5000 description 'masquerade for WAN'
set service nat rule 5000 outbound-interface eth1
set service nat rule 5000 type masquerade
set service nat rule 5002 description 'masquerade for WAN 2'
set service nat rule 5002 outbound-interface eth2
set service nat rule 5002 type masquerade
set service nat rule 5003 description 'masquerade for WAN 3'
set service nat rule 5003 outbound-interface eth3
set service nat rule 5003 type masquerade
set system conntrack expect-table-size 4096
set system conntrack hash-size 4096
set system conntrack table-size 32768
set system conntrack tcp half-open-connections 512
set system conntrack tcp loose enable
set system conntrack tcp max-retrans 3
set system name-server 8.8.8.8
set system offload hwnat enable
"@
}

$NetworkNodeOperatingSystemTemplate = [PSCustomObject][Ordered]@{
    Name = "EdgeOS"
    DefaultCredential = 5002    
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