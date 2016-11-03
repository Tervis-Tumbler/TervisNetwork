﻿#Requires -Version 5

filter mixin-SSHSession {
    $_ | Add-Member -MemberType ScriptProperty -Name Index -Value { $this.SessionID }
}

#$SSHSession = New-SSHSession -ComputerName $NXOSSwitches -Credential (get-credential)
##Does not work though it probably should
##$Sessions | Invoke-SSHCommand -Command "show version"
#Invoke-SSHCommand -Command "show version" -Index $SSHSession.SessionID

function Get-NXOSMacAddressTable {
    param(
        $SSHSession
    )
    $CommandTemplate = Get-Content $PSScriptRoot\NXOSMacAddressTable.Template | Out-String
    Invoke-SSHCommandWithTemplate -SSHSession $SSHSession -Command "show mac address-table dynamic" -CommandTemplate $CommandTemplate
}

function Get-NXOSIPARP {
    param(
        $SSHSession
    )
    $CommandTemplate = Get-Content $PSScriptRoot\NXOSIPARP.Template | Out-String
    Invoke-SSHCommandWithTemplate -SSHSession $SSHSession -Command "show ip arp" -CommandTemplate $CommandTemplate
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
        $SSHSession,
        $Command,
        $FunctionName
    )
    $SSHCommandResults = Invoke-SSHCommand -Command $Command -Index $SSHSession.SessionID
    $SSHCommandResult.output | Out-File "$PSScriptRoot\$FunctionName.Template" 
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