$NetworkDefinition = [PSCustomObject][Ordered]@{
    Name = "Wired Endpoints"
    Vlan = 24
    SubnetCIDR = "10.172.24.0/21"
},
[PSCustomObject][Ordered]@{
    Name = "Fios150"
    Vlan = 20
    SubnetCIDR = "100.3.102.0/24"
    AvailableIPRangeStart = "100.3.102.1"
    AvailableIPRangeEnd ="100.3.102.30"

}