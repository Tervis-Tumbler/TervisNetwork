#Requires -Version 5 -modules Posh-SSH

$ModulePath = (Get-Module -ListAvailable TervisNetwork).ModuleBase
. $ModulePath\NetworkNodeDefinition.ps1
. $ModulePath\NetworkDefinition.ps1

function Install-TervisNetwork {
    Install-Module -Name Posh-SSH -Scope CurrentUser
}

#$SSHSession = New-SSHSession -ComputerName $NXOSSwitches -Credential (get-credential)
##Does not work though it probably should
##$Sessions | Invoke-SSHCommand -Command "show version"
#Invoke-SSHCommand -Command "show version" -Index $SSHSession.SessionID

function Get-NXOSMacAddressTable {
    param(
        $SSHSession = (Get-SSHSession)
    )
    $CommandTemplate = Get-Content $PSScriptRoot\NXOSMacAddressTable.Template | Out-String
    Invoke-SSHCommandWithTemplate -SSHSession $SSHSession -Command "show mac address-table dynamic" -CommandTemplate $CommandTemplate
}

function Get-NXOSMacAddressTableByMacAddress {
    param(
        $SSHSession,
        $MacAddressTwoDotFormat
    )
    $CommandTemplate = Get-Content $PSScriptRoot\NXOSMacAddressTable.Template | Out-String
    Invoke-SSHCommandWithTemplate -SSHSession $SSHSession -Command "show mac address-table address $MacAddressTwoDotFormat" -CommandTemplate $CommandTemplate
}


function Get-NXOSIPARP {
    param(
        $SSHSession
    )
    $CommandTemplate = Get-Content $PSScriptRoot\NXOSIPARP.Template | Out-String
    Invoke-SSHCommandWithTemplate -SSHSession $SSHSession -Command "show ip arp" -CommandTemplate $CommandTemplate
}

function Get-NXOSVersion {
    param(
        $SSHSession
    )
    $CommandTemplate = Get-Content $PSScriptRoot\Get-NXOSVersion.Template | Out-String
    Invoke-SSHCommandWithTemplate -SSHSession $SSHSession -Command "show version" -CommandTemplate $CommandTemplate
}

function Invoke-TervisNetworkSSHCommandWithTemplate {
    param(
        $SSHSession,
        $Command,
        $FunctionName = (Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name,
        [ValidateSet("String","Regex")]$TemplateType = "String"
    )
    $CommandTemplate = Get-Content "$PSScriptRoot\$FunctionName.$($TemplateType)Template" | Out-String
    Invoke-SSHCommandWithTemplate -SSHSession $SSHSession -Command $Command -CommandTemplate $CommandTemplate
}

function New-TervisNetworkSSHCommandTemplate {
    param(
        $SSHSession = (Get-SSHSession),
        $Command,
        $FunctionName,
        [ValidateSet("String","Regex")]$TemplateType = "String"
    )
    New-SSHCommandTemplate -SSHSession $SSHSession -Command $Command -ModuleName TervisNetwork -TemplateType $TemplateType
}

function Edit-TervisNetworkSSHCommandTemplate {
    param(
        $Command,
        [ValidateSet("String","Regex")]$TemplateType = "String"
    )
    Edit-SSHCommandTemplate -Command $Command -ModuleName TervisNetwork -TemplateType $TemplateType
}

function Get-NXOSCDPNeighborsDetail {
    param(
        $SSHSession
    )
    $CommandTemplate = Get-Content $PSScriptRoot\NXOSCDPNeighborsDetail.Template | Out-String
    Invoke-SSHCommandWithTemplate -SSHSession $SSHSession -Command "show cdp neighbors detail" -CommandTemplate $CommandTemplate
}

function Get-NXOSInterfaceTransceiver {
    param(
        $SSHSession
    )
    $CommandTemplate = Get-Content $PSScriptRoot\NXOSInterfaceTransceiver.template | Out-String
    Invoke-SSHCommandWithTemplate -SSHSession $SSHSession -Command "show interface transceiver" -CommandTemplate $CommandTemplate
}

function Restart-ConnectedNetworkInterface {
    # Works only on computers with one connected interface, not tested with
    # multiple connected NICs
    param (
    $ComputerName
    )

    Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        
        $NetworkAdapter = Get-WmiObject Win32_NetworkAdapter |
            where {$_.NetConnectionStatus -EQ 2}

        sleep 5
        $NetworkAdapter.Disable()

        $LoopCount = 0
        while (
            # Check if adapter is connected
            ((Get-WmiObject -Class Win32_NetworkAdapter |
                where {$_.MACAddress -EQ $NetworkAdapter.MACAddress}).NetConnectionStatus -NE 2) `
            -AND ($LoopCount -LT 3)
            # Check that we haven't tried 3 times
        ) {
            $NetworkAdapter.Enable()
            sleep -Seconds 10
            $LoopCount ++
        }
    } -ErrorAction SilentlyContinue
}

function Get-NotIPV6Address {
    param (
        [Parameter(ValueFromPipeline)]$IPAddress
    )
    process {
        $IPAddress |
        where { $_ -NotMatch ":" } 
    }
}

function Convert-SubnetMaskToCidr {
    param (
        [Parameter(ValueFromPipeline)]$SubnetMask
    )
    Process {
        $Bits = ""
        $SubnetMask.split(".") | ForEach-Object {$Bits=$Bits + $([convert]::toString($_,2).padleft(8,"0"))}
        $Bits.indexOf("0")
    }
}

function New-TervisNicTeam {
    param (
        [Parameter(ValueFromPipelineByPropertyName)]$ComputerName
    )
    $CimSession = New-CimSession -ComputerName $ComputerName
    if (-NOT (Get-NetLbfoTeam -CimSession $CimSession)) {
        $NICs = Get-NetAdapter -CimSession $CimSession | where Status -eq "Up" | Select -ExpandProperty Name
        if (($NICs).Count -gt 1) {
            New-NetLbfoTeam -CimSession $CimSession -Name "Team 1" -TeamMembers $NICs
        }
    }
}

function Get-NetAdapterWithSpeedInMbps {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName
    ) 
    process {   
        $WMIResult = Get-WmiObject -Class Win32_NetworkAdapter -ComputerName $ComputerName | 
            where Speed -NE $null | 
            Add-Member -MemberType ScriptProperty -Value {($this.Speed)/1000000} -Name SpeedMbps -PassThru | 
            select Name,SpeedMbps
        [PSCustomObject][Ordered]@{
            ComputerName = $ComputerName
            NetworkSpeed = $WMIResult
        }
    }
}

function New-NexusVPC {
    param (
        $ClientComputerName,
        $ClientInterfaceNumber,
        $VPCPortChannelNumber,
        $ChasisNumber,
        $SlotNumber,
        $PortNumber
    )
@"
interface port-channel$VPCPortChannelNumber
description description VPC $VPCPortChannelNumber to $ClientComputerName Eth $ClientInterfaceNumber
switchport mode trunk
vpc $VPCPortChannelNumber
spanning-tree port type edge trunk
exit
"@

@"
interface Ethernet$ChasisNumber/$SlotNumber/$PortNumber
description $ClientComputerName Eth $ClientInterfaceNumber
switchport mode trunk
channel-group $VPCPortChannelNumber mode active
"@


}

function Invoke-EdgeOSProvision {
    $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ubnt, (
        "ubnt" | ConvertTo-SecureString -AsPlainText -Force
    )
    
    Get-SSHTrustedHost | where sshhost -eq 192.168.1.1 | Remove-SSHTrustedHost
    $SSHSession = New-SSHSession -ComputerName 192.168.1.1 -Credential $Credential -AcceptKey
    Invoke-SSHCommand -Command "hostname" -SessionId 0
    Invoke-SSHCommand -Command "/opt/vyatta/bin/vyatta-op-cmd-wrapper show version" -SessionId 0

}

function Get-EdgeOSVersion {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$SSHSession
    )
    process {
        Invoke-EdgeOSSSHCommandWithTemplate -Command "show version" -CommandType Operational -TemplateType Regex -SSHSession $SSHSession
    }
}

function Set-EdgeOSSystemHostName {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$SSHSession,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName
    )
    process {
        Invoke-EdgeOSSSHConfigureModeCommand -Command "set system host-name $ComputerName" -SSHSession $SSHSession
    }
}

function Set-EdgeOSSystemTimeZone {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$SSHSession,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$TimeZone
    )
    process {
        Invoke-EdgeOSSSHSetCommand -Command "set system time-zone $TimeZone" -SSHSession $SSHSession
    }
}

function Set-EdgeOSInterfacesEthernet {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName,ParameterSetName="VIFVlan")]
        [Parameter(Mandatory,ValueFromPipelineByPropertyName,ParameterSetName="NoVIFVlan")]
        $SSHSession,

        [Parameter(Mandatory,ValueFromPipelineByPropertyName,ParameterSetName="VIFVlan")]
        [Parameter(Mandatory,ValueFromPipelineByPropertyName,ParameterSetName="NoVIFVlan")]
        $Name,

        [Parameter(Mandatory,ValueFromPipelineByPropertyName,ParameterSetName="VIFVlan")]
        $VIFVlan,

        [Parameter(Mandatory,ValueFromPipelineByPropertyName,ParameterSetName="VIFVlan")]
        [Parameter(Mandatory,ValueFromPipelineByPropertyName,ParameterSetName="NoVIFVlan")]
        $Address,
        
        [Parameter(ValueFromPipelineByPropertyName,ParameterSetName="VIFVlan")]
        [Parameter(ValueFromPipelineByPropertyName,ParameterSetName="NoVIFVlan")]
        $Description,

        [Parameter(ValueFromPipelineByPropertyName,ParameterSetName="VIFVlan")]
        [Parameter(ValueFromPipelineByPropertyName,ParameterSetName="NoVIFVlan")]
        $VRRPGroup
    )
    process {
        $SetInterfaceCommand = "set interfaces ethernet $Name$(if($VIFVlan){" vif $VIFVlan"})"

        Invoke-EdgeOSSSHSetCommand -Command "$SetInterfaceCommand address $Address" -SSHSession $SSHSession
        if ($Description) {
            Invoke-EdgeOSSSHSetCommand -Command "$SetInterfaceCommand Description $Description" -SSHSession $SSHSession
        }

        if ($VRRPGroup) {
            $SetVRRGroupCommand = "$SetInterfaceCommand vrrp vrrp-group $($VRRPGroup.Number)"
            Invoke-EdgeOSSSHSetCommand -Command "$SetVRRGroupCommand virtual-address $($VRRPGroup.VIP)" -SSHSession $SSHSession
            Invoke-EdgeOSSSHSetCommand -Command "$SetVRRGroupCommand authentication type ah" -SSHSession $SSHSession
            $Credential = Get-PasswordstateCredential -PasswordID $VRRPGroup.AuthenticationPasswordStateEntry
            $Password = $Credential.GetNetworkCredential().password
            Invoke-EdgeOSSSHSetCommand -Command "$SetVRRGroupCommand authentication password $Password" -SSHSession $SSHSession
            Invoke-EdgeOSSSHSetCommand -Command "$SetVRRGroupCommand sync-group MainSyncGroup" -SSHSession $SSHSession
        }
    }
}

function Set-EdgeOSProtocolsStaticRoute {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$SSHSession,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$Address,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$NextHop        
    )
    process {
        Invoke-EdgeOSSSHConfigureModeCommand -Command "set protocols static route $Address next-hop $NextHop" -SSHSession $SSHSession
    }
}

function Add-EdgeOSSystemImage {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$SSHSession,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ImagePath        
    )
    process {
        Invoke-EdgeOSSSHCommandWithTemplate -CommandType Operational -Command "add system image $ImagePath" -SSHSession $SSHSession
    }
}

function Invoke-EdgeOSSSHSetCommand {
    param (
        [Parameter(Mandatory)]$Command,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$SSHSession
    )
    process {
        $CommandToExecute = @"
session_env=`$(cli-shell-api getSessionEnv `$PPID)
eval `$session_env
cli-shell-api setupSession
/opt/vyatta/sbin/my_$Command
/opt/vyatta/sbin/my_commit
cli-shell-api teardownSession
"@ -split "`r`n" -join ";"
    
        Invoke-EdgeOSSSHCommand -Command $CommandToExecute -SSHSession $SSHSession
    }
}

function Invoke-EdgeOSSSHConfigureModeCommand {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory,ValueFromPipeline)]$Command,
        [Parameter(Mandatory)]$SSHSession
    )
    begin {
        [Array]$CommandArray += "/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper begin"
    }
    process {    
        $CommandArray += "/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper $Command"
    }
    end {
        $CommandArray += "/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper commit"
        $CommandArray += "/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper end"
        $CommandToExecute = $CommandArray -join ";"
        Invoke-EdgeOSSSHCommand -Command $CommandToExecute -SSHSession $SSHSession
    }
}

function Invoke-EdgeOSSSHSaveCommand {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$SSHSession
    )
    process {
        $CommandToExecute = @"
session_env=`$(cli-shell-api getSessionEnv `$PPID)
eval `$session_env
cli-shell-api setupSession
/opt/vyatta/sbin/vyatta-save-config.pl
cli-shell-api teardownSession
"@ -split "`r`n" -join ";"
    
        Invoke-EdgeOSSSHCommand -Command $CommandToExecute -SSHSession $SSHSession
    }
}

function Invoke-EdgeOSSSHCommandWithTemplate {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory)]$Command,
        [ValidateSet("Operational")]$CommandType,
        [ValidateSet("FlashExtract","Regex")]$TemplateType = "FlashExtract",
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$SSHSession
    )
    process {
        $CommandToExecute = if ($CommandType -eq "Operational") { 
            "/opt/vyatta/bin/vyatta-op-cmd-wrapper " + $Command
        } else {
            $Command
        }

        Invoke-SSHCommandWithTemplate -Command $CommandToExecute -ModuleName TervisNetwork -TemplateType $TemplateType -SSHSession $SSHSession
    }
}

function Invoke-EdgeOSSSHOperationalModeCommand {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory)]$Command,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$SSHSession
    )
    process {
        $CommandToExecute = "/opt/vyatta/bin/vyatta-op-cmd-wrapper " + $Command
        Invoke-EdgeOSSSHCommand -Command $CommandToExecute -SSHSession $SSHSession
    }   
}

function Invoke-EdgeOSSSHCommand {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory)]$Command,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$SSHSession
    )
    process {
        if ($PSCmdlet.ShouldProcess($SSHSession.Host)) {
            Invoke-SSHCommand -Command $Command -SSHSession $SSHSession
        } else {
            $Command
        }
    }
}

function Get-NetworkNodeDefinition {
    param (
        [Parameter(Mandatory,ParameterSetName="HardwareSerialNumber")]$HardwareSerialNumber,
        [Parameter(Mandatory,ParameterSetName="ComputerName")]$ComputerName
    )
    $HardwareMapping = $NetworkNodeDefinitionToHardwareMapping | 
    Where-Object {-not $HardwareSerialNumber -or $_.HardwareSerialNumber -eq $HardwareSerialNumber} |
    Where-Object {-not $ComputerName -or $_.ComputerName -and $_.ComputerName -eq $ComputerName} 

    $NodeDefinition = $NetworkNodeDefinition |
    where { $_.ComputerName -and $_.ComputerName -eq $HardwareMapping.ComputerName }

    if ($NodeDefinition.TemplateName) { 
        $Template = $NetworkNodeDefinitionTemplate | 
        Where-Object Name -EQ $NodeDefinition.TemplateName

        $Template, $NodeDefinition | Merge-NetworkObject -LastObjectPropertiesOverwritePriorObjects
    } else {
        $NodeDefinition
    }
}

function Get-NetworkNodeOperatingSystemTemplate {
    param (
        $Name
    )
    $NetworkNodeOperatingSystemTemplate |
    Where Name -EQ $Name |
    Add-NetworkNodeOperatingSystemTemplateCustomProperites
}

function Add-NetworkNodeOperatingSystemTemplateCustomProperites {
    param (
        [Parameter(Mandatory,ValueFromPipeline)]$OperatingSystemTemplate
    )
    process {
        $OperatingSystemTemplate |
        Add-Member -MemberType ScriptProperty -Name Credential -Force -Value {
            Get-PasswordstateCredential -PasswordID $this.DefaultCredential
        } -PassThru
    }
}

function Get-NetworkNode {
    param (
        [Parameter(Mandatory,ParameterSetName="HardwareSerialNumber")]$HardwareSerialNumber,
        [Parameter(Mandatory,ParameterSetName="ComputerName")]$ComputerName,
        [Switch]$UseDefaultCredential
    )
    $Parameters = $PSBoundParameters | ConvertFrom-PSBoundParameters -ExcludeProperty $UseDefaultCredential -AsHashTable
    $NetworkNode = Get-NetworkNodeDefinition @Parameters
    $NetworkNode | 
    Add-NetworkNodeCustomProperites -UseDefaultCredential:$UseDefaultCredential
}

function Add-NetworkNodeCustomProperites {
    param (
        [Parameter(Mandatory,ValueFromPipeline)]$Node,
        [Switch]$UseDefaultCredential
    )
    process {
        $Node | 
        Add-Member -MemberType ScriptProperty -Name OperatingSystemTemplate -Force -Value {
            Get-NetworkNodeOperatingSystemTemplate -Name $This.OperatingSystemName
        } -PassThru |
        Add-Member -MemberType ScriptProperty -Name Credential -Force -Value {
            if ($UseDefaultCredential) {
                $This.OperatingSystemTemplate.Credential
            } else {
                Get-PasswordstateCredential -PasswordID $This.PasswordID
            }
        } -PassThru |
        Add-Member -MemberType ScriptProperty -Name SSHSession -Force -Value {
            $SSHSession = Get-SSHSession -ComputerName $This.ManagementIPAddress
            if ($SSHSession -and $SSHSession.Connected -eq $true) {
                $SSHSession
            } else {
                if ($SSHSession) { $SSHSession | Remove-SSHSession | Out-Null }
                New-SSHSession -ComputerName $This.ManagementIPAddress -Credential $This.Credential -AcceptKey
            }
        } -PassThru 
    }
}

function Invoke-NetworkNodeProvision {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory,ParameterSetName="HardwareSerialNumber")]$HardwareSerialNumber,
        [Parameter(Mandatory,ParameterSetName="ComputerName")]$ComputerName
    )
    Get-SSHTrustedHost | where sshhost -eq 192.168.1.1 | Remove-SSHTrustedHost
    $NetworkNode = Get-NetworkNode @PSBoundParameters
    if ($NetworkNode.OperatingSystemName -in "EdgeOS","VyOS") {
        #$NetworkNode | Set-EedgeOSUser
        $NetworkNode | Set-EdgeOSSystemHostName
        $NetworkNode | Set-EdgeOSSystemTimeZone -TimeZone "US/Eastern"        
        $NetWorkNode | Invoke-EdgeOSInterfaceProvision
        
        $NetWorkNode | 
        where {$_.StaticRoute} | 
        Select -ExpandProperty StaticRoute |
        Set-EdgeOSProtocolsStaticRoute -SSHSession $NetworkNode.SSHSession

        
        #$NetworkNode | 
        #where {$_.TunnelMemberDefinition} | 
        #Invoke-EdgeOSTunnelProvision

        #Add-EdgeOSSystemImage -ImagePath https://dl.ubnt.com/firmwares/edgemax/v1.9.7/ER-e50.v1.9.7+hotfix.3.5013617.tar

        $NetworkNode.AdditionalCommands -split "`r`n" |
        Invoke-EdgeOSSSHConfigureModeCommand -SSHSession $NetworkNode.SSHSession

        $NetWorkNode | Invoke-EdgeOSInterfaceUseProvision

        $NetworkNode | Invoke-EdgeOSSSHSaveCommand
    }
}

function Invoke-EdgeOSInterfaceProvision {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$SSHSession,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$InterfaceDefinition
    )
    process {
        $InterfaceDefinition |
        Set-EdgeOSInterfacesEthernet -SSHSession $SSHSession
    }
}

function Invoke-LabHardwareProvision {
    ipmo -Force tervisnetwork
    Invoke-NetworkNodeProvision -HardwareSerialNumber F09FC2DF00D2
    Invoke-NetworkNodeProvision -HardwareSerialNumber F09FC2DF02B2
    Invoke-NetworkNodeProvision -HardwareSerialNumber F09FC2DF00E4
    Invoke-NetworkNodeProvision -HardwareSerialNumber F09FC2DF0294
#set protocols static interface-route 172.16.1.0/24 next-hop-interface vti0
#set protocols static interface-route 172.16.2.0/24 next-hop-interface vti0

    Invoke-NetworkNodeProvision -HardwareSerialNumber F09FC2DF9F3A
    
    Invoke-NetworkNodeProvision -HardwareSerialNumber 00155d00050c
    Invoke-NetworkNodeProvision -HardwareSerialNumber c81f66e82fec
    Invoke-NetworkNodeProvision -HardwareSerialNumber 1721k788a204095a9
}

function Get-TervisNetworkTunnelDefiniton {
    param (
        $Name
    )
    $TunnelDefinition |
    where Name -EQ $Name
}

function Invoke-EdgeOSTunnelProvision {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$SSHSession,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$TunnelMemberDefinition,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$InterfaceDefinition
    )
    process {
        $TunnelDefinition = Get-TervisNetworkTunnelDefiniton -Name $TunnelMemberDefinition.TunnelName
        
        $Commands = $TunnelDefinition |
        New-VyOSSiteToSiteWANVPNCommandsFromTunnelDefinition -TunnelSide $TunnelMemberDefinition.TunnelSide -InterfaceDefinition $InterfaceDefinition

        $Commands -split "`r`n" |
        Invoke-EdgeOSSSHConfigureModeCommand -SSHSession $SSHSession
    }
}

function New-VyOSSiteToSiteWANVPNCommandsFromTunnelDefinition {
    param (
        [ValidateSet("Left","Right")][Parameter(Mandatory)]$TunnelSide,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$LeftPeerIP,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$RightPeerIP,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$LeftVTIIP,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$RightVTIIP,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$VTIIPPrefixBits,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$PreSharedSecret,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$Phase1DHGroup,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$Phase1Encryption,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$Phase1Hash,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$Phase2Encryption,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$Phase2Hash,
        [Parameter(Mandatory)]$InterfaceDefinition
    )

    $VPNParameters = if ($TunnelSide -eq "Left") {
        @{
            WANIPLocal = $LeftPeerIP
            WANIPRemote = $RightPeerIP
            VTIIPLocal = $LeftVTIIP
            VTIIPRemote = $RightVTIIP
        }
    } elseif ($TunnelSide -eq "Right") {
        @{
            WANIPLocal = $RightPeerIP
            WANIPRemote = $LeftPeerIP
            VTIIPLocal = $RightVTIIP
            VTIIPRemote = $LeftVTIIP
        }
    }
    
    $IpsecInterface = $InterfaceDefinition |
    Where-Object Address -Match $VPNParameters.WANIPLocal |
    Select-Object -ExpandProperty Name

    #New-VyOSSiteToSiteWANVPNCommands @VPNParameters -Phase1DHGroup $Phase1DHGroup -Phase1Encryption $Phase1Encryption -Phase1Hash $Phase1Hash -Phase2Encryption $Phase2Encryption -Phase2Hash $Phase2Hash -VTIIPLocalPrefixBits $VTIIPPrefixBits -PreSharedSecret $PreSharedSecret -IpsecInterface $IpsecInterface
    New-VyOSSiteToSiteWANVPNCommandsUbiquitiExample @VPNParameters -Phase1DHGroup $Phase1DHGroup -Phase1Encryption $Phase1Encryption -Phase1Hash $Phase1Hash -Phase2Encryption $Phase2Encryption -Phase2Hash $Phase2Hash -VTIIPLocalPrefixBits $VTIIPPrefixBits -PreSharedSecret $PreSharedSecret -IpsecInterface $IpsecInterface
}

function New-VyOSSiteToSiteWANVPNCommands {
    param (
        [Parameter(Mandatory)]$WANIPLocal,
        [Parameter(Mandatory)]$WANIPRemote,
        [Parameter(Mandatory)]$VTIIPLocal,
        [Parameter(Mandatory)]$VTIIPLocalPrefixBits,
        [Parameter(Mandatory)]$VTIIPRemote,
        [Parameter(Mandatory)]$PreSharedSecret,
        [Parameter(Mandatory)]$Phase1DHGroup,
        [Parameter(Mandatory)]$Phase1Encryption,
        [Parameter(Mandatory)]$Phase1Hash,
        [Parameter(Mandatory)]$Phase2Encryption,
        [Parameter(Mandatory)]$Phase2Hash,
        [Parameter(Mandatory)]$IpsecInterface
    )
    
@"
set interfaces vti vti0 address $VTIIPLocal/$VTIIPLocalPrefixBits
set vpn ipsec ipsec-interfaces interface $IpsecInterface
set vpn ipsec ike-group ikegroup0 key-exchange ikev2
set vpn ipsec ike-group ikegroup0 proposal 1 dh-group $Phase1DHGroup
set vpn ipsec ike-group ikegroup0 proposal 1 encryption $Phase1Encryption
set vpn ipsec ike-group ikegroup0 proposal 1 hash $Phase1Hash
set vpn ipsec esp-group espgroup0 proposal 1 encryption $Phase2Encryption
set vpn ipsec esp-group espgroup0 proposal 1 hash $Phase2Hash
set vpn ipsec site-to-site peer $WANIPRemote local-address $WANIPLocal
set vpn ipsec site-to-site peer $WANIPRemote ike-group ikegroup0
set vpn ipsec site-to-site peer $WANIPRemote vti esp-group espgroup0
set vpn ipsec site-to-site peer $WANIPRemote authentication mode pre-shared-secret
set vpn ipsec site-to-site peer $WANIPRemote authentication pre-shared-secret $PreSharedSecret
set vpn ipsec site-to-site peer $WANIPRemote connection-type initiate
set vpn ipsec site-to-site peer $WANIPRemote vti bind vti0
"@
}

function New-VyOSSiteToSiteWANVPNCommandsUbiquitiExample {
    param (
        [Parameter(Mandatory)]$WANIPLocal,
        [Parameter(Mandatory)]$WANIPRemote,
        [Parameter(Mandatory)]$VTIIPLocal,
        [Parameter(Mandatory)]$VTIIPLocalPrefixBits,
        [Parameter(Mandatory)]$VTIIPRemote,
        [Parameter(Mandatory)]$PreSharedSecret,
        [Parameter(Mandatory)]$Phase1DHGroup,
        [Parameter(Mandatory)]$Phase1Encryption,
        [Parameter(Mandatory)]$Phase1Hash,
        [Parameter(Mandatory)]$Phase2Encryption,
        [Parameter(Mandatory)]$Phase2Hash,
        [Parameter(Mandatory)]$IpsecInterface
    )
    
@"
set vpn ipsec auto-firewall-nat-exclude enable
set vpn ipsec esp-group FOO0 lifetime 43200
set vpn ipsec esp-group FOO0 pfs disable
set vpn ipsec esp-group FOO0 proposal 1 encryption $Phase2Encryption
set vpn ipsec esp-group FOO0 proposal 1 hash $Phase2Hash
set vpn ipsec ike-group FOO0 lifetime 86400
set vpn ipsec ike-group FOO0 proposal 1 dh-group $Phase1DHGroup
set vpn ipsec ike-group FOO0 proposal 1 encryption $Phase1Encryption
set vpn ipsec ike-group FOO0 proposal 1 hash $Phase1Hash
set vpn ipsec site-to-site peer $WANIPRemote authentication mode pre-shared-secret
set vpn ipsec site-to-site peer $WANIPRemote authentication pre-shared-secret $PreSharedSecret
set vpn ipsec site-to-site peer $WANIPRemote description IPsec
set vpn ipsec site-to-site peer $WANIPRemote ike-group FOO0
set vpn ipsec site-to-site peer $WANIPRemote local-address $WANIPLocal
set vpn ipsec site-to-site peer $WANIPRemote vti bind vti0
set vpn ipsec site-to-site peer $WANIPRemote vti esp-group FOO0
set interfaces vti vti0 address $VTIIPLocal/$VTIIPLocalPrefixBits
set protocols static interface-route 172.16.1.0/24 next-hop-interface vti0
"@
}

function Invoke-ZeroTierBridgeProvision {
    Invoke-ApplicationProvision -ApplicationName ZeroTierBridge
    $Nodes = Get-TervisApplicationNode -ApplicationName ZeroTierBridge -IncludeSSHSession
    $Nodes | Install-LinuxZeroTierOne
}

function Invoke-UnifiControllerProvision {
    Invoke-ApplicationProvision -ApplicationName UnifiController
    $Nodes = Get-TervisApplicationNode -ApplicationName UnifiController -IncludeSSHSession
#Install Controller service after opening it via rdp the first time
@"
cd "%UserProfile%\Ubiquiti UniFi\"
java -jar lib\ace.jar installsvc
java -jar lib\ace.jar startsvc
"@    
}

function Invoke-ArchRouterProvision {
    Invoke-ApplicationProvision -ApplicationName ArchRouter
    $Nodes = Get-TervisApplicationNode -ApplicationName ArchRouter -IncludeSSHSession -IncludeSFTSession -IncludeVM
    $Nodes | Copy-PathToSFTPDestinationPath -Path "$ModulePath\ArchLinux" -DestinationPath "/"

}

function Copy-PathToSFTPDestinationPath {
    param (
        [Parameter(Mandatory)]$Path,
        [Parameter(Mandatory)]$DestinationPath,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$SFTPSession
    )
    $Files = Get-ChildItem -Recurse -Path $Path -File
    foreach ($File in $Files) {
        $DestinationFileName = $File.Name
        $RelativeDestinationPath = $File.DirectoryName.Replace($Path,"").Replace("\","/").Substring(1)
        $DestinationPathOfFile = "$DestinationPath$RelativeDestinationPath"
        
        $Folder = Get-SFTPChildItem -Path "$DestinationPathOfFile" -SFTPSession $SFTPSession -ErrorAction SilentlyContinue
        if (-not $Folder) {
            New-SFTPItem -ItemType Directory -Path $DestinationPathOfFile -SFTPSession $SFTPSession | Out-Null
        }
        Set-SFTPFile -RemotePath $DestinationPathOfFile -LocalFile $File.FullName -SFTPSession $SFTPSession
    }
}

function Get-EdgeOSEtherNetInterfaceStanza {
    param (
        $Name,
        $VIFVlan
    )
    process {
        if ($VIFVlan) { 
            "$InterfaceName vif $VIFVlan" 
        } else {
            $InterfaceName
        }
    }
}

function New-EdgeOSLoadBalancedWanInterfaceStanza {
    param (
        $InterfaceName,
        $VIFVlan,
        $Weight,
        $Description,
        $NatRuleNumber
    )
    $EthernetInterfaceStanza = Get-EdgeOSEtherNetInterfaceStanza -Name $InterfaceName -VIFVlan $VIFVlan

    $InterfaceStanza = if ($VIFVlan) { 
        "$InterfaceName.$VIFVlan" 
    } else {
        $InterfaceName
    }
@"
set load-balance group G interface $InterfaceStanza
set load-balance group G interface $InterfaceStanza weight $Weight
set service nat rule $NatRuleNumber description 'masquerade for $Description'
set service nat rule $NatRuleNumber outbound-interface $InterfaceStanza
set service nat rule $NatRuleNumber type masquerade
set interfaces ethernet $EthernetInterfaceStanza firewall in name WAN_IN
set interfaces ethernet $EthernetInterfaceStanza firewall local name WAN_LOCAL
"@
}

function New-EdgeOSFirewallLoadBalanceStanza {
@"
set firewall modify balance rule 10 destination group network-group LAN_NETS
set firewall modify balance rule 10 action modify
set firewall modify balance rule 10 modify table main
set firewall modify balance rule 20 action modify
set firewall modify balance rule 20 modify lb-group G
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
"@
}


function New-EdgeOSLoadBalancedLanInterfaceStanza {
    param (
        $InterfaceName,
        $VIFVlan
    )
    $EthernetInterfaceStanza = Get-EdgeOSEtherNetInterfaceStanza -Name $InterfaceName -VIFVlan $VIFVlan
@"
set interfaces ethernet $EthernetInterfaceStanza firewall in modify balance
"@
}

function Set-EdgeOSLoadBalancedWanInterface {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$SSHSession,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$InterfaceDefinition
    )
    process {
        $NextAvailableNATRuleNumber = Get-EdgeOSNextAvailableNATRuleNumber -SSHSession $SSHSession

        $Commands = @()
        $Commands += New-EdgeOSFirewallLoadBalanceStanza
        $Commands += New-EdgeOSLoadBalancedWanInterfaceStanza -NatRuleNumber $NextAvailableNATRuleNumber -InterfaceName $InterfaceDefinition.Name -Weight $InterfaceDefinition.Weight -Description $InterfaceDefinition.Description -VIFVlan $InterfaceDefinition.VIFVlan

        $Commands -split "`r`n" |
        Invoke-EdgeOSSSHConfigureModeCommand -SSHSession $SSHSession
    }
}

function Get-EdgeOSNextAvailableNATRuleNumber {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$SSHSession
    )
    process {
        $Results = Invoke-EdgeOSSSHOperationalModeCommand -Command 'show configuration commands | grep "nat rule"' -SSHSession $SSHSession | 
        Select-Object -ExpandProperty Output
        
        [int]$LastNatRuleNumberUsed = $Results -split "`r`n" | 
        Select-StringBetween -After "set service nat rule " -Before " " |
        Sort-Object -Unique -Descending |
        Select-Object -First 1

        $LastNatRuleNumberUsed + 1
    }
}

function Set-EdgeOSLoadBalancedLanInterface {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$SSHSession,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$InterfaceDefinition
    )
    process {
        $Commands = @()
        $Commands += New-EdgeOSLoadBalancedLanInterfaceStanza -InterfaceName $InterfaceDefinition.Name -VIFVlan $InterfaceDefinition.VIFVlan

        $Commands -split "`r`n" |
        Invoke-EdgeOSSSHConfigureModeCommand -SSHSession $SSHSession
    }
}


function Invoke-EdgeOSInterfaceUseProvision {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$SSHSession,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$InterfaceDefinition
    )
    process {
        $InterfaceDefinition |
        Where {$_.UseForWANLoadBalancing} |
        foreach {
            Set-EdgeOSLoadBalancedWanInterface -SSHSession $SSHSession -InterfaceDefinition $_
        }
        
        $InterfaceDefinition |
        Where {$_.LoadBalanceIngressTrafficDestinedToWAN} |
        foreach {
            Set-EdgeOSLoadBalancedLanInterface -SSHSession $SSHSession -InterfaceDefinition $_
        }
    }
}

function Merge-NetworkObject {
    param(
        [Parameter(Mandatory,ValueFromPipeline)][PSCustomObject]$Object,
        [Switch]$LastObjectPropertiesOverwritePriorObjects
    )
    begin {
        $MergedObject = New-Object -TypeName PSObject
    }
    process {
        foreach ($Property in $Object.PSObject.Properties) {
            $MergedObjectProperty = $MergedObject.$($Property.Name)
            if ($MergedObjectProperty) {
                if($MergedObjectProperty -is [PSCustomObject] -and $Property.Value -is [PSCustomObject]) {
                    $MergedObjectProperty, $Property | Merge-Object
                } elseif ($MergedObjectProperty -is [System.Object[]] -and $Property.Value -is [System.Object[]]) {
                    
                    $Where = if ($Property.Name -eq "InterfaceDefinition") {
                        {$args[0].Name -eq $args[1].Name -and $args[0].VIFVlan -eq $args[1].VIFVlan}
                    }
                    
                    $MergedProperties = Join-Object -Left $MergedObjectProperty -Right $Property.Value -Where $Where -LeftProperties * -RightProperties * -Type AllInBoth
                    $MergedObject | Add-Member -MemberType NoteProperty -Name $Property.Name -Value $MergedProperties -Force
                }
            } else {
                $MergedObject | Add-Member -MemberType NoteProperty -Name $Property.Name -Value $Property.value -Force:$LastObjectPropertiesOverwritePriorObjects
            }
        }
    }
    end {
        $MergedObject
    }
}

#https://blogs.msdn.microsoft.com/powershell/2012/07/13/join-object/
function AddItemProperties($item, $properties, $output)
{
    if($item -ne $null)
    {
        foreach($property in $properties)
        {
            $propertyHash =$property -as [hashtable]
            if($propertyHash -ne $null)
            {
                $hashName=$propertyHash[“name”] -as [string]
                if($hashName -eq $null)
                {
                    throw “there should be a string Name”  
                }
         
                $expression=$propertyHash[“expression”] -as [scriptblock]
                if($expression -eq $null)
                {
                    throw “there should be a ScriptBlock Expression”  
                }
         
                $_=$item
                $expressionValue=& $expression
         
                $output | add-member -MemberType “NoteProperty” -Name $hashName -Value $expressionValue -Force
            }
            else
            {
                # .psobject.Properties allows you to list the properties of any object, also known as “reflection”
                foreach($itemProperty in $item.psobject.Properties)
                {
                    if ($itemProperty.Name -like $property)
                    {
                        $output | add-member -MemberType “NoteProperty” -Name $itemProperty.Name -Value $itemProperty.Value -Force
                    }
                }
            }
        }
    }
}

    
function WriteJoinObjectOutput($leftItem, $rightItem, $leftProperties, $rightProperties, $Type)
{
    $output = new-object psobject

    if($Type -eq “AllInRight”)
    {
        # This mix of rightItem with LeftProperties and vice versa is due to
        # the switch of Left and Right arguments for AllInRight
        AddItemProperties $rightItem $leftProperties $output
        AddItemProperties $leftItem $rightProperties $output
    }
    else
    {
        AddItemProperties $leftItem $leftProperties $output
        AddItemProperties $rightItem $rightProperties $output
    }
    $output
}

<# 
.Synopsis
   Joins two lists of objects
.DESCRIPTION
   Joins two lists of objects
.EXAMPLE
   Join-Object $a $b “Id” (“Name”,”Salary”)
#>
function Join-Object
{
    [CmdletBinding()]
    [OutputType([int])]
    Param
    (
        # List to join with $Right
        [Parameter(Mandatory=$true,
                   Position=0)]
        [object[]]
        $Left,

        # List to join with $Left
        [Parameter(Mandatory=$true,
                   Position=1)]
        [object[]]
        $Right,

        # Condition in which an item in the left matches an item in the right
        # typically something like: {$args[0].Id -eq $args[1].Id}
        [Parameter(Mandatory=$true,
                   Position=2)]
        [scriptblock]
        $Where,

        # Properties from $Left we want in the output.
        # Each property can:
        # – Be a plain property name like “Name”
        # – Contain wildcards like “*”
        # – Be a hashtable like @{Name=”Product Name”;Expression={$_.Name}}. Name is the output property name
        #   and Expression is the property value. The same syntax is available in select-object and it is 
        #   important for join-object because joined lists could have a property with the same name
        [Parameter(Mandatory=$true,
                   Position=3)]
        [object[]]
        $LeftProperties,

        # Properties from $Right we want in the output.
        # Like LeftProperties, each can be a plain name, wildcard or hashtable. See the LeftProperties comments.
        [Parameter(Mandatory=$true,
                   Position=4)]
        [object[]]
        $RightProperties,

        # Type of join. 
        #   AllInLeft will have all elements from Left at least once in the output, and might appear more than once
        # if the where clause is true for more than one element in right, Left elements with matches in Right are 
        # preceded by elements with no matches. This is equivalent to an outer left join (or simply left join) 
        # SQL statement.
        #  AllInRight is similar to AllInLeft.
        #  OnlyIfInBoth will cause all elements from Left to be placed in the output, only if there is at least one
        # match in Right. This is equivalent to a SQL inner join (or simply join) statement.
        #  AllInBoth will have all entries in right and left in the output. Specifically, it will have all entries
        # in right with at least one match in left, followed by all entries in Right with no matches in left, 
        # followed by all entries in Left with no matches in Right.This is equivallent to a SQL full join.
        [Parameter(Mandatory=$false,
                   Position=5)]
        [ValidateSet(“AllInLeft”,”OnlyIfInBoth”,”AllInBoth”, “AllInRight”)]
        [string]
        $Type=”OnlyIfInBoth”
    )

    Begin
    {
        # a list of the matches in right for each object in left
        $leftMatchesInRight = new-object System.Collections.ArrayList

        # the count for all matches  
        $rightMatchesCount = New-Object “object[]” $Right.Count

        for($i=0;$i -lt $Right.Count;$i++)
        {
            $rightMatchesCount[$i]=0
        }
    }

    Process
    {
        if($Type -eq “AllInRight”)
        {
            # for AllInRight we just switch Left and Right
            $aux = $Left
            $Left = $Right
            $Right = $aux
        }

        # go over items in $Left and produce the list of matches
        foreach($leftItem in $Left)
        {
            $leftItemMatchesInRight = new-object System.Collections.ArrayList
            $null = $leftMatchesInRight.Add($leftItemMatchesInRight)

            for($i=0; $i -lt $right.Count;$i++)
            {
                $rightItem=$right[$i]

                if($Type -eq “AllInRight”)
                {
                    # For AllInRight, we want $args[0] to refer to the left and $args[1] to refer to right,
                    # but since we switched left and right, we have to switch the where arguments
                    $whereLeft = $rightItem
                    $whereRight = $leftItem
                }
                else
                {
                    $whereLeft = $leftItem
                    $whereRight = $rightItem
                }

                if(Invoke-Command -ScriptBlock $where -ArgumentList $whereLeft,$whereRight)
                {
                    $null = $leftItemMatchesInRight.Add($rightItem)
                    $rightMatchesCount[$i]++
                }
            
            }
        }

        # go over the list of matches and produce output
        for($i=0; $i -lt $left.Count;$i++)
        {
            $leftItemMatchesInRight=$leftMatchesInRight[$i]
            $leftItem=$left[$i]
                               
            if($leftItemMatchesInRight.Count -eq 0)
            {
                if($Type -ne “OnlyIfInBoth”)
                {
                    WriteJoinObjectOutput $leftItem  $null  $LeftProperties  $RightProperties $Type
                }

                continue
            }

            foreach($leftItemMatchInRight in $leftItemMatchesInRight)
            {
                WriteJoinObjectOutput $leftItem $leftItemMatchInRight  $LeftProperties  $RightProperties $Type
            }
        }
    }

    End
    {
        #produce final output for members of right with no matches for the AllInBoth option
        if($Type -eq “AllInBoth”)
        {
            for($i=0; $i -lt $right.Count;$i++)
            {
                $rightMatchCount=$rightMatchesCount[$i]
                if($rightMatchCount -eq 0)
                {
                    $rightItem=$Right[$i]
                    WriteJoinObjectOutput $null $rightItem $LeftProperties $RightProperties $Type
                }
            }
        }
    }
}