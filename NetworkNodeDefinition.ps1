$NetworkNodeDefinition = [PSCustomObject][Ordered]@{
    ComputerName = "INF-EdgeRouter01"
    HardwareSerialNumber = "F09FC2DF00D2"
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
    HardwareSerialNumber = "F09FC2DF02B2"
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
    HardwareSerialNumber = "F09FC2DF00E4"
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
    HardwareSerialNumber = "F09FC2DF0294"
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
}

$NetworkNodeOperatingSystemTemplate = [PSCustomObject][Ordered]@{
    Name = "EdgeOS"
    DefaultCredential = 5002    
}

$NetworkConnectionMap = [PSCustomObject][Ordered]@{
    Name = "Layer3InterfaceDefinitionOnNetConnections"
    Connections = {
        
    }
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
}