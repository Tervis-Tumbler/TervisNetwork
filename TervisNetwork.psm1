#Requires -Version 5 -modules Posh-SSH

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

function Invoke-EdgeRouterProvision {
    $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ubnt, (
        "ubnt" | ConvertTo-SecureString -AsPlainText -Force
    )
    
    Get-SSHTrustedHost | where sshhost -eq 192.168.1.1 | Remove-SSHTrustedHost
    $SSHSession = New-SSHSession -ComputerName 192.168.1.1 -Credential $Credential -AcceptKey
    Invoke-SSHCommand -Command "hostname" -SessionId 0
    Invoke-SSHCommand -Command "/opt/vyatta/bin/vyatta-op-cmd-wrapper show version" -SessionId 0

}

function Get-EdgeRouterVersion {
    Invoke-EdgeRouterSSHCommand -Command "show version" -CommandType Operational -TemplateType Regex -SSHSession $SSHSession
}

function Invoke-EdgeRouterSSHCommand {
    param (
        $Command,
        [ValidateSet("Operational")]$CommandType,
        [ValidateSet("FlashExtract","Regex")]$TemplateType = "FlashExtract",
        $SSHSession
    )
    $CommandToExecute = if ($CommandType -eq "Operational") { 
        "/opt/vyatta/bin/vyatta-op-cmd-wrapper " + $Command
    } else {
        $Command
    }

    Invoke-SSHCommandWithTemplate -Command $CommandToExecute -ModuleName TervisNetwork -TemplateType $TemplateType -SSHSession $SSHSession
}

function Invoke-EdgeRouterOperationalCommand {
    param (
        $OperationalCommand
    )
    $Command = "/opt/vyatta/bin/vyatta-op-cmd-wrapper" + $OperationalCommand
    Invoke-EdgeRouterSSHCommand -Command $Command -SessionId 0 | select -ExpandProperty output
}