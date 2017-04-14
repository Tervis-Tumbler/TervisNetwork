#Requires -Version 5 -modules Posh-SSH

function Install-TervisNetwork {
    Install-Module -Name Posh-SSH
}

filter mixin-SSHSession {
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
        $FunctionName = (Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name
    )
    $CommandTemplate = Get-Content "$PSScriptRoot\$FunctionName.Template" | Out-String
    Invoke-SSHCommandWithTemplate -SSHSession $SSHSession -Command "show ip arp" -CommandTemplate $CommandTemplate
}

function New-TervisNetworkSSHCommandTemplate {
    param(
        $SSHSession = (Get-SSHSession),
        $Command,
        $FunctionName
    )
    $SSHCommandResults = Invoke-SSHCommand -Command $Command -Index $SSHSession.SessionID
    $SSHCommandResults.output | Out-File "$PSScriptRoot\$FunctionName.Template" 
}

function Edit-TervisNetworkSSHCommandTemplate {
    param(
        $FunctionName
    )
    Invoke-Item "$PSScriptRoot\$FunctionName.Template" 
}

function Invoke-SSHCommandWithTemplate {
    param(
        $SSHSession,
        $Command,
        $CommandTemplate
    )
    $SSHCommandResults = Invoke-SSHCommand -Command $Command -Index $SSHSession.SessionID
    ForEach ($SSHCommandResult in $SSHCommandResults) {
        $Objects = $SSHCommandResult.output | ConvertFrom-String -TemplateContent $CommandTemplate
        $Objects | Add-Member -MemberType NoteProperty -Name Host -Value $SSHCommandResult.Host
        $Results += $Objects
    }
    $Results
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