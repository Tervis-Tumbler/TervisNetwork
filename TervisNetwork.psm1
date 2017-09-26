#Requires -Version 5 -modules Posh-SSH

$ModulePath = (Get-Module -ListAvailable TervisNetwork).ModuleBase
. $ModulePath\NetworkNodeDefinition.ps1

function Install-TervisNetwork {
    Install-Module -Name Posh-SSH -Scope CurrentUser
}

filter Add-SSHSessionCustomProperty {
    $_ | Add-Member -MemberType ScriptProperty -Name Index -Value { $this.SessionID }
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

function Set-EdgeOSInterfacesEthernetAddress {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$SSHSession,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$Name,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$Address
    )
    process {
        Invoke-EdgeOSSSHSetCommand -Command "set interfaces ethernet $Name address $Address" -SSHSession $SSHSession
    }
}

function Set-EdgeOSInterfacesEthernetVIFAddress {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$SSHSession,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$Name,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$Vlan,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$Address
    )
    process {
        Invoke-EdgeOSSSHSetCommand -Command "set interfaces ethernet $Name vif $Vlan address $Address" -SSHSession $SSHSession
    }
}

function Set-EdgeOSProtocolsStaticRoute {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$SSHSession,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$Address,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$NextHop        
    )
    process {
        Invoke-EdgeOSSSHConfigureModeCommandWrapper -Command "set protocols static route $Address next-hop $NextHop" -SSHSession $SSHSession
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
    param (
        [Parameter(Mandatory)]$Command,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$SSHSession
    )
    process {
        $CommandToExecute = @"
/config/scripts/executecommand.sh "configure; $Command; commit"
"@    
        Invoke-EdgeOSSSHCommand -Command $CommandToExecute -SSHSession $SSHSession
    }
}

function Invoke-EdgeOSSSHConfigureModeCommandWrapper {
    param (
        [Parameter(Mandatory)]$Command,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$SSHSession
    )
    process {    
        $CommandToExecute = @"
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper begin; /opt/vyatta/sbin/vyatta-cfg-cmd-wrapper $Command; /opt/vyatta/sbin/vyatta-cfg-cmd-wrapper commit; /opt/vyatta/sbin/vyatta-cfg-cmd-wrapper end;
"@    
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


function Invoke-EdgeOSSSHCommand {
    param (
        [Parameter(Mandatory)]$Command,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$SSHSession
    )
    process {
        Invoke-SSHCommand -Command $CommandToExecute -SSHSession $SSHSession
    }
}

function Get-NetworkNodeDefinition {
    param (
        $HardwareSerialNumber
    )
    $NetworkNodeDefinition |
    where HardwareSerialNumber -eq $HardwareSerialNumber
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
        $HardwareSerialNumber
    )
    $NetworkNode = Get-NetworkNodeDefinition -HardwareSerialNumber $HardwareSerialNumber
    $NetworkNode | 
    Add-NetworkNodeCustomProperites
}

function Add-NetworkNodeCustomProperites {
    param (
        [Parameter(Mandatory,ValueFromPipeline)]$Node
    )
    process {
        $Node | 
        Add-Member -MemberType ScriptProperty -Name OperatingSystemTemplate -Force -Value {
            Get-NetworkNodeOperatingSystemTemplate -Name $This.OperatingSystemName
        } -PassThru |
        Add-Member -MemberType ScriptProperty -Name SSHSession -Force -Value {
            $SSHSession = Get-SSHSession -ComputerName $This.ManagementIPAddress
            if ($SSHSession -and $SSHSession.Connected -eq $true) {
                $SSHSession
            } else {
                if ($SSHSession) { $SSHSession | Remove-SSHSession }
                New-SSHSession -ComputerName $This.ManagementIPAddress -Credential $This.OperatingSystemTemplate.Credential
            }
        } -PassThru 
    }
}

function Invoke-NetworkNodeProvision {
    param (
        $HardwareSerialNumber
    )
    $NetworkNode = Get-NetworkNode -HardwareSerialNumber $HardwareSerialNumber
    if ($NetworkNode.OperatingSystemName -eq "EdgeOS") {
        $NetworkNode | Set-EdgeOSSystemHostName
        $NetworkNode | Set-EdgeOSSystemTimeZone -TimeZone "US/Eastern"
        $NetworkNode | Invoke-EdgeOSSSHSaveCommand
        $NetWorkNode | Invoke-EdgeOSInterfaceProvision
        $NetWorkNode.StaticRoute | Set-EdgeOSProtocolsStaticRoute -SSHSession $NetworkNode.SSHSession
    }

}

function Invoke-EdgeOSInterfaceProvision {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$SSHSession,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$InterfaceDefinition
    )
    process {
        $InterfaceDefinition |
        Where {$_.Address} |
        Set-EdgeOSInterfacesEthernetAddress -SSHSession $SSHSession

        $InterfaceDefinition |
        Where {$_.VIF} | % {
            $_.VIF |
            Set-EdgeOSInterfacesEthernetVIFAddress -Name $_.Name -SSHSession $SSHSession
        }
    }
}