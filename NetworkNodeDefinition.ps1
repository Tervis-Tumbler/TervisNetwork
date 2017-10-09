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