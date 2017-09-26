$NetworkNodeDefinition = [PSCustomObject][Ordered]@{
    ComputerName = "INF-EdgeRouter01"
    HardwareSerialNumber = "F09FC2DF00D2"
    OperatingSystemName = "EdgeOS"
    ManagementIPAddress = "192.168.1.1"
    InterfaceDefinition = [PSCustomObject][Ordered]@{
        Name = "eth1"
        VIF = [PSCustomObject][Ordered]@{
            Vlan = 100
            Address = "172.16.0.1/24"
        }
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
    HardwareSerialNumber = ""
    OperatingSystemName = "EdgeOS"
    InterfaceDefinition = [PSCustomObject][Ordered]@{
        Name = "eth1"
        VIF = [PSCustomObject][Ordered]@{
            Vlan = 100
            Address = "172.16.0.2/2"
        },
        [PSCustomObject][Ordered]@{
            Vlan = 101
            Address = "172.16.1.1/24"
        }
    },
    [PSCustomObject][Ordered]@{
        Name = "eth4"
        Address = "dhcp"
    }
},
[PSCustomObject][Ordered]@{
    ComputerName = "INF-EdgeRouter03"
    HardwareSerialNumber = ""
    OperatingSystemName = "EdgeOS"
    InterfaceDefinition = [PSCustomObject][Ordered]@{
        Name = "eth1"
        VIF = [PSCustomObject][Ordered]@{
            Vlan = 101
            Address = "172.16.1.1/24"
        },
        [PSCustomObject][Ordered]@{
            Vlan = 102
            Address = "172.16.2.1/24"
        }
    },
    [PSCustomObject][Ordered]@{
        Name = "eth4"
        Address = "dhcp"
    }
},
[PSCustomObject][Ordered]@{
    ComputerName = "INF-EdgeRouter04"
    HardwareSerialNumber = ""
    OperatingSystemName = "EdgeOS"
    InterfaceDefinition = [PSCustomObject][Ordered]@{
        Name = "eth1"
        VIF = [PSCustomObject][Ordered]@{
            Vlan = 102
            Address = "172.16.2.2/24"
        }
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

$NetworkConnectionMap = [PSCustomObject][Ordered]@{
    Name = "Layer3InterfaceDefinitionOnNetConnections"
    Connections = {
        
    }
}