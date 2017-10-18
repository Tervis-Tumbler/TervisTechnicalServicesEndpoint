#Requires -version 5.0
#Requires -modules PasswordstatePowershell, TervisChocolatey, TervisNetTCPIP, TervisApplication
#Requires -RunAsAdministrator

function Enter-PSSessionToNewEndpoint {
    [CmdletBinding()]
    param (
        [parameter(Mandatory, ValueFromPipeline)]$IPAddress,
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )        
    Enter-PSSession -ComputerName $IPAddress -Credential $Credential
}

function New-CustomerCareSignatures {
    param (            
        [parameter(Mandatory)][string]$UserName,
        [parameter(Mandatory)][string]$Computername,
        [string]$SignatureTemplateLocation = "\\dfs-13\Departments - I Drive\Sales\DTC\Signatures"
    )  

    Copy-Item -Path $SignatureTemplateLocation -Destination C:\SigTemp\Signatures -Recurse

    #Placeholders
    $NameHolder = '\[Name\]'
    $PersonalEmailHolder = '\[PersonalEmail\]'
    $TitleHolder = '\[Title\]'

    #Get AD info of current user
    $ADUser = Get-ADUser -Identity $Username -Properties name,title,mail
    $ADDisplayName = $ADUser.Name.ToUpper()
    $ADTitle = $ADUser.title
    $ADEmailAddress = $ADUser.mail

    $SignatureFiles = Get-ChildItem -Path C:\SigTemp\Signatures\*.*

    ForEach ($SignatureFile in $SignatureFiles) {
        (Get-Content $SignatureFile) |
        ForEach-Object {    
           $_ -replace $NameHolder, $ADDisplayName `
              -replace $TitleHolder, $ADTitle `
              -replace $PersonalEmailHolder, $ADEmailAddress } |
        Set-Content $SignatureFile
    }

    Copy-Item "C:\SigTemp\Signatures" "\\$computername\c$\Users\$username\appdata\roaming\microsoft\" -Recurse -Force
    Remove-Item -Path "C:\SigTemp" -Recurse -Force
}

function Get-TervisIPAddressAsString {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][String]$MACAddressWithDashes
    )

    Write-Verbose "Getting IP address"
    $IPAddress = Find-DHCPServerv4LeaseIPAddress -MACAddressWithDashes $MACAddressWithDashes -AsString
    
    if (-not $IPAddress) { 
        throw "No ip v4 lease found for MacAddress $MACAddressWithDashes" 
    } else {
        Write-Verbose "IP address found: $IPAddress"
    }

    $IPAddress
}

function New-TervisEndpoint {    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][ValidateSet("ContactCenterAgent","BartenderPrintStationKiosk","StandardOfficeEndpoint","ShipStation","CafeKiosk","IT","MESAuditor","MESStation","FillRoomSurface","SurfaceMES","IQ2Welder")][String]$EndpointTypeName,
        [Parameter(Mandatory,ParameterSetName="EndpointMacAddress")][String]$MACAddressWithDashes,
        [Parameter(Mandatory,ParameterSetName="IPAddress")][String]$IPAddress,
        [Parameter(Mandatory)][String]$ComputerName
    )
    $EndpointType = Get-TervisEndpointType -Name $EndpointTypeName

    Write-Verbose "Getting local admin credentials"
    $LocalAdministratorCredential = Get-PasswordstateCredential -PasswordID 3954

    if ($MACAddressWithDashes) {
        $IPAddress = Get-TervisIPAddressAsString -MACAddressWithDashes $MACAddressWithDashes
    }
    Add-IPAddressToWSManTrustedHosts -IPAddress $IPAddress

    Set-TervisEndpointNameAndDomain -OUPath $EndpointType.DefaultOU -ComputerName $ComputerName -IPAddress $IPAddress -LocalAdministratorCredential $LocalAdministratorCredential -ErrorAction Stop    

    $PSDefaultParameterValues = @{"*:ComputerName" = $ComputerName}
    Invoke-TervisGroupPolicyUpdateForceRestart 
    Set-TervisEndpointPowerPlan -PowerPlanProfile "High Performance"
    Sync-ADDomainControllers
    Add-ComputerToPrivilege_PrincipalsAllowedToDelegateToAccount
    Remove-KerberosTickets
    New-TervisLocalAdminAccount
    Set-TervisBuiltInAdminAccountPassword
    Disable-TervisBuiltInAdminAccount
    Install-TervisChocolatey
    Install-TervisChocolateyPackages -ChocolateyPackageGroupNames $EndpointType.ChocolateyPackageGroupNames
    Add-ADGroupMember -Identity "EndpointType_$($EndpointType.Name)" -Members (Get-ADComputer -Identity $ComputerName)
    $PSDefaultParameterValues.clear()

    if ($EndpointType.InstallScript) {
        Invoke-Command -ScriptBlock $EndpointType.InstallScript -ArgumentList $ComputerName
    }

    if ($EndpointType.Name -eq "CafeKiosk") {
        Write-Verbose "Starting Cafe Kiosk install"
        New-TervisEndpointCafeKiosk -EndpointName $ComputerName 
    }    
}

Function Sync-ADDomainControllers {
    [CmdletBinding()]
    param ()
    Write-Verbose "Forcing a sync between domain controllers"
    $DC = Get-ADDomainController | Select -ExpandProperty HostName
    Invoke-Command -ComputerName $DC -ScriptBlock {repadmin /syncall}
    Start-Sleep 30 
}

function Get-TervisEndpointType {
    param (
        $Name
    )
    $EndpointTypes | where Name -eq $Name
}

$EndpointTypes = [PSCustomObject][Ordered]@{
    Name = "ContactCenterAgent"
    InstallScript = {
        Invoke-Command -ComputerName $ComputerName {
            Write-Verbose "Starting Contact Center Agent install"
            Start-DscConfiguration -Wait -Path \\$env:USERDNSDOMAIN\applications\PowerShell\DotNet35 -Force
            Copy-Item -Path "\\$env:USERDNSDOMAIN\applications\PowerShell\FedEx Customer Tools" -Destination "c:\programdata\" -Recurse -Force
        }
    }
    DefaultOU = "OU=Computers,OU=Sales,OU=Departments,DC=tervis,DC=prv"
    ChocolateyPackageGroupNames = "StandardOfficeEndpoint","ContactCenter"
},[PSCustomObject][Ordered]@{
    Name = "BartenderPrintStationKiosk"
    BaseName = "LabelPrint"
    DefaultOU = "OU=BartenderPCs,OU=IndustryPCs,DC=tervis,DC=prv"
},
[PSCustomObject][Ordered]@{
    Name = "CafeKiosk"
    BaseName = "Cafe"
    DefaultOU = "OU=Cafe Kiosks,OU=Human Resources,OU=Departments,DC=tervis,DC=prv"
},
[PSCustomObject][Ordered]@{
    Name = "StandardOfficeEndpoint"
    ChocolateyPackageGroupNames = "StandardOfficeEndpoint"
    DefaultOU = "OU=Sandbox,DC=tervis,DC=prv"
},
[PSCustomObject][Ordered]@{
    Name = "ShipStation"
    BaseName = "Ship"
    DefaultOU = "OU=Computers,OU=Shipping Stations,OU=Operations,OU=Departments,DC=tervis,DC=prv"
    InstallScript = {
        Write-Verbose "Starting Expeditor install"
        Install-WCSScaleSupport -ComputerName $ComputerName
    }
    ChocolateyPackageGroupNames = "StandardOfficeEndpoint"
},
[PSCustomObject][Ordered]@{
    Name = "IT"
    ChocolateyPackageGroupNames = "StandardOfficeEndpoint","IT"
    DefaultOU = "OU=Computers,OU=Information Technology,OU=Departments,DC=tervis,DC=prv"
},
[PSCustomObject][Ordered]@{
    Name = "MESAuditor"
    BaseName = "MESAuditor"
    ChocolateyPackageGroupNames = "StandardOfficeEndpoint"
    DefaultOU = "OU=Computers,OU=MES Auditors,OU=Operations,OU=Departments,DC=tervis,DC=prv"
    InstallScript = {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {            
            Remove-LocalGroupMember -Group Users -Member "TERVIS\Domain Users"
            Add-LocalGroupMember -Group Users -Member Privilege_MESAuditorStationUsers
        }
    }
},
[PSCustomObject][Ordered]@{
    Name = "MESStation"
    DefaultOU = "OU=ProductionFloor,OU=IndustryPCs,DC=tervis,DC=prv"
    InstallScript = {
        Write-Verbose "Restarting for Autologon"
        Restart-Computer -Wait -Force -ComputerName $ComputerName
    }
},
[PSCustomObject][Ordered]@{
    Name = "FillRoomSurface"
    ChocolateyPackageGroupNames = "FillRoomSurface"
    DefaultOU = "OU=FillRoom,OU=IndustryPCs,DC=tervis,DC=prv"
    InstallScript = {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AutoRotation" -Name Enable -Value 0
        }
        Write-Verbose "Restarting for Autologon"
        Restart-Computer -Wait -Force -ComputerName $ComputerName
    }
},
[PSCustomObject][Ordered]@{
    Name = "SurfaceMES"
    ChocolateyPackageGroupNames = "SurfaceMES"
    DefaultOU = "OU=SurfaceMES,OU=IndustryPCs,DC=tervis,DC=prv"
    InstallScript = {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AutoRotation" -Name Enable -Value 0
        }        
        Set-TervisEndpointPowerPlan -ComputerName $ComputerName -NoSleepOnBattery
        Set-TervisAutoHotKeyF2PrintScript -ComputerName $ComputerName
        Set-TervisSurfaceMESKioskMode -ComputerName $ComputerName
        Write-Verbose "Restarting for Autologon"
        Restart-Computer -Wait -Force -ComputerName $ComputerName
    }
},
[PSCustomObject][Ordered]@{
    Name = "IQ2Welder"
    ChocolateyPackageGroupNames = "IQ2Welder"
    DefaultOU = "OU=IQ Explorer II,OU=Welder Stations,OU=Engineering,OU=Departments,DC=tervis,DC=prv"
    InstallScript = {
        Enable-TouchKeyboardOnWindows10Endpoint -ComputerName $ComputerName
        Install-DotNet35OnEndpoint -ComputerName $ComputerName
        New-iQExplorerIIOptionsFile -ComputerName $ComputerName
        Write-Verbose "Restarting for Autologon"
        Restart-Computer -Wait -Force -ComputerName $ComputerName
        Write-Warning "Weld tech will install desired iQ II version"
    }
}

function New-TervisEndpointCafeKiosk {
    param (
        $ComputerName
    )

    $EndpointADObject = Get-ADComputer -Identity $ComputerName
        
    Write-Verbose "Adding computer object to Resource_CafeKiosks group"
    Add-ADGroupMember -Identity Resource_CafeKiosks -Members $EndpointADObject
        
    Write-Verbose "Updating Group Policy on endpoint"
    Invoke-GPUpdate -Computer $ComputerName -RandomDelayInMinutes 0 -Force | Out-Null

    Write-Verbose "Restarting endpoint"
    Restart-Computer -ComputerName $ComputerName -Force

    Wait-ForEndpointRestart -ComputerName $ComputerName -PortNumbertoMonitor 5985

    Write-Verbose "Restarting endpoint again"
    Restart-Computer -ComputerName $ComputerName -Force
    Wait-ForEndpointRestart -ComputerName $ComputerName -PortNumbertoMonitor 5985
}

function Add-ComputerToPrivilege_PrincipalsAllowedToDelegateToAccount {
    [CmdletBinding()]
    param (
        $ComputerName
    )
    Write-Verbose "Setting Resource-Based Kerberos Constrained Delegation"

    $EndpointObjectToAccessResource = Get-ADComputer -Identity $ComputerName
    Add-ADGroupMember -Identity Privilege_PrincipalsAllowedToDelegateToAccount -Members $EndpointObjectToAccessResource
}

function Remove-KerberosTickets {
    [CmdletBinding()]
    param (
        $ComputerName,
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )
    
    Invoke-Command @PSBoundParameters -ScriptBlock {
        klist purge -li 0x3e7
    }
}

function Set-TervisEndpointNameAndDomain {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]$ComputerName,
        [Parameter(Mandatory)]$IPAddress,
        [Parameter(Mandatory)]$LocalAdministratorCredential,
        $OUPath,
        $DomainName = "$env:USERDNSDOMAIN"
    )
    Write-Verbose "Renaming computer to $ComputerName"
    Invoke-TervisRenameComputerOnOrOffDomain -ComputerName $ComputerName -IPAddress $IPAddress -Credential $LocalAdministratorCredential

    if (!($OUPath)) {
        $OUPath = "OU=Sandbox,DC=tervis,DC=prv"
    }
    Write-Verbose "Setting OU path to $OUPath"
    Write-Verbose "Joining computer to $DomainName"
    Invoke-TervisJoinDomain -OUPath $OUPath -ComputerName $ComputerName -IPAddress $IPAddress -Credential $LocalAdministratorCredential    
}

function Wait-ForEndpointRestart{    
    param (
        [Parameter(Mandatory)][Alias("IPAddress")]$ComputerName,
        [Parameter(Mandatory)]$PortNumbertoMonitor
    )
    
    Write-Verbose "Waiting for endpoint to reboot"
    Wait-ForPortNotAvailable -ComputerName $ComputerName -PortNumbertoMonitor $PortNumbertoMonitor -WarningAction SilentlyContinue
    
    Write-Verbose "Waiting for endpoint to startup"    
    Wait-ForPortAvailable -ComputerName $ComputerName -PortNumbertoMonitor $PortNumbertoMonitor -WarningAction SilentlyContinue

    Write-Verbose "Endpoint is up and running"
}

function New-TervisLocalAdminAccount {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]$ComputerName
    )
    
    Write-Verbose "Creating TumblerAdministrator local account"

    $TumblerAdminCredential = Get-PasswordstateCredential -PasswordID 14    
    $TumblerAdminPassword = $TumblerAdminCredential.Password
    Invoke-Command -ComputerName $ComputerName -ScriptBlock {        
        New-LocalUser -Name "TumblerAdministrator" -Password $Using:TumblerAdminPassword -FullName "TumblerAdministrator" -Description "Local Admin Account" -PasswordNeverExpires
        Add-LocalGroupMember -Name "Administrators" -Member "TumblerAdministrator"
    }
}

function Get-TervisLocalAdminAccount {
    param (
        [Parameter(Mandatory)]$ComputerName,
        $LocalUserName = '*'
    )
    Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        Get-LocalUser -Name $Using:LocaUserName
    }
}

function Set-TervisBuiltInAdminAccountPassword {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]$ComputerName
    )
    
    Write-Verbose "Resetting password of built-in Administrator account"
    $BuiltinAdminCredential = Get-PasswordstateCredential -PasswordID 3972    
    $BuiltinAdminPassword = $BuiltinAdminCredential.Password

    Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        Set-LocalUser -Name Administrator -Password $Using:BuiltinAdminPassword
    }
}

function Disable-TervisBuiltInAdminAccount {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]$ComputerName
    )
    Write-Verbose "Disabling built-in Administrator account"

    Invoke-Command -ComputerName $ComputerName -ScriptBlock {        
        Disable-LocalUser -Name Administrator
    }
}

function Set-TervisEndpointPowerPlan {
    param (
        [ValidateSet("High Performance")]
        [String]$PowerPlanProfile = "High Performance",

        [Parameter(Mandatory)]
        [String]$ComputerName,

        [pscredential]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Switch]$NoSleepOnBattery
    )

    Write-Verbose "Setting power configuration to $PowerPlanProfile"
    $ActivePowerScheme = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {        
        <#$PowerPlanInstanceID = (Get-WmiObject -Class win32_powerplan -Namespace root\cimv2\power -Filter "ElementName=`'$Using:PowerPlanProfile`'").InstanceID
        $Using:PowerPlanProfile
        $PowerPlanInstanceID.ToString()
        $PowerPlanGUID = $PowerPlanInstanceID.split("{")[1].split("}")[0]
        powercfg -S $PowerPlanGUID
        $ActivePowerScheme = powercfg /getactivescheme
        $ActivePowerScheme#>
        
        powercfg -change -monitor-timeout-ac 0
        powercfg -change -standby-timeout-ac 0
        powercfg -change -hibernate-timeout-ac 0

        if ($Using:NoSleepOnBattery) {
            powercfg -change -monitor-timeout-dc 0
            powercfg -change -standby-timeout-dc 0
            powercfg -change -hibernate-timeout-dc 0
        }
    }

    if ($ActivePowerScheme) {Write-Verbose $ActivePowerScheme}
}

function New-DotNet35DSCMOF {
    configuration DotNet35 {

        Import-DscResource –ModuleName "PSDesiredStateConfiguration"

        Node localhost {
            WindowsOptionalFeature DotNet35 {
                Ensure = "Enable"
                Name = "netfx3"
            }
        }
    }

    DotNet35
    New-DscChecksum -Path .\DotNet35\localhost.mof
    Copy-Item -Path .\DotNet35 -Destination \\$env:USERDNSDOMAIN\applications\PowerShell -Recurse -Force
}

function Install-WCSScaleSupport {
    param (
        $ComputerName
    )
    $PSDefaultParameterValues = @{"*:ComputerName" = $ComputerName}
    Set-JavaHomeEnvironmentVariable
    $JavaLibDir = Invoke-Command -ScriptBlock {"$env:JAVA_HOME\lib\"}
    $JavaBinDir = Invoke-Command -ScriptBlock {"$env:JAVA_HOME\bin\"}
    $RemoteJavaLibDir = $JavaLibDir | ConvertTo-RemotePath
    $RemoteJavaBinDir = $JavaBinDir | ConvertTo-RemotePath
    New-Item -Path $RemoteJavaBinDir -ItemType Directory -Force | Out-Null
    New-Item -Path $RemoteJavaLibDir -ItemType Directory -Force | Out-Null
    $LibFileSource = "\\fs1\DisasterRecovery\Programs\WCS\Scale Dependancies\javax.comm.properties"
    $BinFileSource = "\\fs1\DisasterRecovery\Programs\WCS\Scale Dependancies\win32com.dll"
    Copy-Item -Path $LibFileSource -Destination $RemoteJavaLibDir
    Copy-Item -Path $BinFileSource -Destination $RemoteJavaBinDir
    $PSDefaultParameterValues.clear()
}

function Set-TervisUserAsLocalAdministrator {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory)]$SAMAccountName,
        $ComputerName
    )

    if (-not $ComputerName) {
        Write-Verbose "Finding user's last used computer"
        $ComputerName = Find-TervisADUsersComputer -SAMAccountName $SAMAccountName -Properties LastLogonDate |
            sort -Property LastLogonDate |
            select -Last 1 |
            select -ExpandProperty Name
    }

    $WhatIf = $PSCmdlet.ShouldProcess("$ComputerName","Add $SAMAccountName as local admin")
    try {
        Write-Verbose "Connecting to remote computer"
        $Result = Invoke-Command -ComputerName $ComputerName -ArgumentList $SAMAccountName,$WhatIf -ScriptBlock {
            param (
                $SAMAccountName,
                $WhatIf
            )

            #$LocalAdministrators = Get-LocalGroupMember -Group Administrators | select -ExpandProperty Name
            # PowerShell 2.0 Compatible 
            $LocalAdministratorsGroup = [ADSI]"WinNT://$env:COMPUTERNAME/Administrators,group"
            $LocalAdministrators = $LocalAdministratorsGroup.invoke("members") | 
                foreach {$_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)}

            if ($LocalAdministrators -match $SAMAccountName) {
                return "Set"
            } else {
                try {
                    if ($WhatIf) {
                        #Add-LocalGroupMember -Group Administrators -Member $SAMAccountName -ErrorAction Stop | 
                        # PowerShell 2.0 Compatible
                        $LocalAdministratorsGroup.Add("WinNT://$env:USERDOMAIN/$SAMAccountName,user") | Out-Null
                        return "Set"
                    } else {
                        return "WhatIf"
                    }
                } catch {
                    return "Not Set"
                }
            }
        } -ErrorAction Stop

        Write-Verbose 'Adding computer to "Local - Computer Admin Group Exception"'
        $ComputerObject = Get-ADComputer -Identity $ComputerName
        Add-ADGroupMember -Identity "Local - Computer Admin Group Exception" -Members $ComputerObject
    } catch {
        $Result = "No connection"
    }

    [PSCustomObject][Ordered]@{
        SAMAccountName = $SAMAccountName
        ComputerName = $ComputerName
        LocalAdminSet = $Result
    }
}

function Set-TervisUserAsRemoteDesktopUser {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory)]$SAMAccountName,
        $ComputerName
    )

    if (-not $ComputerName) {
        Write-Verbose "Finding user's last used computer"
        $ComputerName = Find-TervisADUsersComputer -SAMAccountName $SAMAccountName -Properties LastLogonDate |
            sort -Property LastLogonDate |
            select -Last 1 |
            select -ExpandProperty Name
    }

    $WhatIf = $PSCmdlet.ShouldProcess("$ComputerName","Add $SAMAccountName as Remote Desktop User")
    try {
        Write-Verbose "Connecting to remote computer"
        $Result = Invoke-Command -ComputerName $ComputerName -ArgumentList $SAMAccountName,$WhatIf -ScriptBlock {
            param (
                $SAMAccountName,
                $WhatIf
            )

            $RemoteDesktopUsersGroup = [ADSI]"WinNT://$env:COMPUTERNAME/Remote Desktop Users,group"
            $RemoteDesktopUsers = $RemoteDesktopUsersGroup.invoke("members") | 
                foreach {$_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)}

            if ($RemoteDesktopUsers -match $SAMAccountName) {
                return "Set"
            } else {
                try {
                    if ($WhatIf) {
                        $RemoteDesktopUsersGroup.Add("WinNT://$env:USERDOMAIN/$SAMAccountName,user") | Out-Null
                        return "Set"
                    } else {
                        return "WhatIf"
                    }
                } catch {
                    return "Not Set"
                }
            }
        } -ErrorAction Stop
    } catch {
        $Result = "No connection"
    }

    [PSCustomObject][Ordered]@{
        SAMAccountName = $SAMAccountName
        ComputerName = $ComputerName
        RemoteDesktopUserSet = $Result
    }
}


function Set-TervisADGroupAsLocalAdmin {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]$Group
    )

    $GroupMembers = Get-ADGroupMember -Identity $Group -Recursive -ErrorAction Stop |
        where objectClass -EQ user |
        select -ExpandProperty SAMAccountName

    Start-ParallelWork -Parameters $GroupMembers -ScriptBlock {
        param ($Parameter)
        Set-TervisUserAsLocalAdministrator -SAMAccountName $Parameter
    } | select -Property SAMAccountName,ComputerName,LocalAdminSet
}

function Get-TervisLocalAdmin {
    param (
        [Parameter(ParameterSetName="ByUser")]$SAMAccountName,
        [Parameter(ParameterSetName="ByComputer")]$ComputerName
    )
    
    if ($SAMAccountName) {
        $ComputerName = Find-TervisADUsersComputer -SAMAccountName $SAMAccountName |
            select -ExpandProperty Name
    }

    foreach ($Computer in $ComputerName) {
        try {
            $LocalAdmins =Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                $LocalAdminGroup = [ADSI]"WinNT://$env:COMPUTERNAME/Administrators,group"
                $LocalAdmins = $LocalAdminGroup.invoke("members") | 
                    foreach {$_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)}
                $LocalAdmins
            } -ErrorAction Stop

            if ($SAMAccountName) {
                if ($LocalAdmins -match $SAMAccountName) {
                    $IsLocalAdmin = $true
                } else {
                    $IsLocalAdmin = $false
                }
            } else {
                $IsLocalAdmin = $null
            }

            [PSCustomObject][Ordered]@{
                ComputerName = $Computer
                SAMAccountName = $SAMAccountName
                IsLocalAdmin = $IsLocalAdmin
                LocalAdmins = $LocalAdmins
            
            }
        } catch {
            [PSCustomObject][Ordered]@{
                ComputerName = $Computer
                SAMAccountName = $SAMAccountName
                IsLocalAdmin = $null            
                LocalAdmins = "No connection"
            }
        }
    }

}

function Get-TervisLocalAdminsForADGroup {
    param (
        $ADGroupIdentity
    )

    $ADGroupMembers = Get-ADGroupMember -Identity $ADGroupIdentity -Recursive

    Start-ParallelWork -Parameters $ADGroupMembers.SAMAccountName -MaxConcurrentJobs 5 -ScriptBlock {
        param (
            $Parameter
        )
        Get-TervisLocalAdmin -SAMAccountName $Parameter
    } | select ComputerName,SAMAccountName,IsLocalAdmin,LocalAdmins
}

function Install-TervisEPSViewer {
    param (
        [Parameter(Mandatory)]$ComputerName
    )
    $PSDefaultParameterValues = @{"*:ComputerName" = $ComputerName}
    Install-TervisChocolatey -Verbose
    Install-TervisChocolateyPackage -PackageName ghostscript.app -Version 9.20
    Install-TervisChocolateyPackage -PackageName gimp -Version 2.8.20
    Set-TervisEPSConfiguration
    Install-TervisChocolateyPackage -PackageName foxitreader
    $PSDefaultParameterValues.Clear()
}

function Remove-LocalSecurityPolicyConfiguration {
    param (
        [Parameter(Mandatory)]$ComputerName
    )
    $GroupPolicyPath = "C:\windows\system32\GroupPolicy\"
    $RemoteGroupPolicyPath = $GroupPolicyPath | ConvertTo-RemotePath -ComputerName $ComputerName
    Remove-Item -Path "$RemoteGroupPolicyPath\Machine" -Recurse -Force
    Remove-Item -Path "$RemoteGroupPolicyPath\User" -Recurse -Force
    Remove-Item -Path "$RemoteGroupPolicyPath\gpt.ini"
}

function Invoke-RemoveAndRefreshGroupPolicy {
    param (
        [Parameter(Mandatory)]$ComputerName
    )
    Remove-LocalSecurityPolicyConfiguration -ComputerName $ComputerName
    Restart-Computer -ComputerName $ComputerName -Force
    Wait-ForNodeRestart -ComputerName $ComputerName
    Invoke-Command -ComputerName $ComputerName -ScriptBlock {gpupdate /force}
    Restart-Computer -ComputerName $ComputerName
}

function Invoke-TervisGroupPolicyUpdateForceRestart {    
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName
    )
    process{
        $PSDefaultParameterValues = @{"*:ComputerName" = $ComputerName}
        Write-Verbose "Updating Group Policy on $ComputerName"
        Invoke-Command -ScriptBlock {gpupdate}
        Write-Verbose "Waiting on computer restart"
        Restart-Computer -Force -Wait
        $PSDefaultParameterValues.Clear()
    }
}

function Test-IsGPUpdateRunning {
    param (
        [Parameter(Mandatory)]$ComputerName
    )
    process{
        if (Get-Process @PSBoundParameters -Name gpupdate -ErrorAction SilentlyContinue){$true} 
        else {$false}
    }
}

function Invoke-ForceLogOffAllUsers {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName
    )
    Invoke-CimMethod @PSBoundParameters -ClassName Win32_OperatingSystem -MethodName Win32Shutdown -Arguments @{Flags = 4}
}

function Set-JavaHomeEnvironmentVariable {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName
    )
    process {    
        $PSDefaultParameterValues = @{"*:ComputerName" = $ComputerName}
        $Java32Path = "C:\Program Files (x86)\Java\"
        $Java64Path = "C:\Program Files\Java\"
        $Java32PathRemote = $Java32Path | ConvertTo-RemotePath
        $Java64PathRemote = $Java64Path | ConvertTo-RemotePath
        
        if (Test-Path $Java32PathRemote) {
            $JavaHomeRoot = $Java32Path
        } elseif (Test-Path $Java64PathRemote) {
            $JavaHomeRoot = $Java64Path
        } else {
            throw "Cannot find Java install directory on $ComputerName"
        }
        
        $JavaHomeRootRemote = $JavaHomeRoot | ConvertTo-RemotePath
        $LatestJavaInstall =  Get-ChildItem -Path $JavaHomeRootRemote -ErrorAction Stop | 
            where Name -like "jre1*" |
            sort Name |
            select -Last 1 |
            select -ExpandProperty Name
        $JavaHomeDirectory = Join-Path -Path $JavaHomeRoot -ChildPath $LatestJavaInstall
        Write-Verbose "Setting JAVA_HOME to `"$JavaHomeDirectory`" on $ComputerName"
        Invoke-Command -ScriptBlock {
            [Environment]::SetEnvironmentVariable("JAVA_HOME",$Using:JavaHomeDirectory,"Machine")
        }
        $PSDefaultParameterValues.Clear()
    }
}

function Set-TervisEPSConfiguration {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName
    )

    Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        Write-Verbose "Setting Ghostscript environment variable"
        [Environment]::SetEnvironmentVariable( "GS_PROG", '"C:\Program Files\gs\gs9.20\bin\gswin64c.exe"', "Machine")
        Write-Verbose "Copying Ghostscript files"
        Copy-Item -Path "C:\Program Files\gs\gs9.20\bin\gsdll64.dll" -Destination "C:\Program Files\GIMP 2\bin\libgs-8.dll" -Force

        Write-Verbose "Writing file associations to registry"
        New-Item -Path HKLM:\SOFTWARE\Classes\ps_auto_file
        New-Item -Path HKLM:\SOFTWARE\Classes\ps_auto_file\shell
        New-Item -Path HKLM:\SOFTWARE\Classes\ps_auto_file\shell\open
        New-Item -Path HKLM:\SOFTWARE\Classes\ps_auto_file\shell\open\command
        New-ItemProperty `
            -Path HKLM:\SOFTWARE\Classes\ps_auto_file\shell\open\command `
            -Name '(default)' `
            -Value '"C:\Program Files\GIMP 2\bin\gimp-2.8.exe" "%1"' `
            -PropertyType String            

        New-Item -Path HKLM:\SOFTWARE\Classes\eps_auto_file
        New-Item -Path HKLM:\SOFTWARE\Classes\eps_auto_file\shell
        New-Item -Path HKLM:\SOFTWARE\Classes\eps_auto_file\shell\open
        New-Item -Path HKLM:\SOFTWARE\Classes\eps_auto_file\shell\open\command
        New-ItemProperty `
            -Path HKLM:\SOFTWARE\Classes\eps_auto_file\shell\open\command `
            -Name '(default)' `
            -Value '"C:\Program Files\GIMP 2\bin\gimp-2.8.exe" "%1"' `
            -PropertyType String

        New-Item -Path HKLM:\SOFTWARE\Classes\ai_auto_file
        New-Item -Path HKLM:\SOFTWARE\Classes\ai_auto_file\shell
        New-Item -Path HKLM:\SOFTWARE\Classes\ai_auto_file\shell\open
        New-Item -Path HKLM:\SOFTWARE\Classes\ai_auto_file\shell\open\command
        New-ItemProperty `
            -Path HKLM:\SOFTWARE\Classes\ai_auto_file\shell\open\command `
            -Name '(default)' `
            -Value '"C:\Program Files (x86)\Foxit Software\Foxit Reader\FoxitReader.exe" "%1"' `
            -PropertyType String

        New-ItemProperty `
            -Path HKLM:\SOFTWARE\Classes\.ps `
            -Name '(default)' `
            -Value "ps_auto_file" `
            -PropertyType String
        Set-ItemProperty `
            -Path HKLM:\SOFTWARE\Classes\.ps `
            -Name "Content Type" `
            -Value "application/postscript" `

        New-ItemProperty `
            -Path HKLM:\SOFTWARE\Classes\.eps `
            -Name '(default)' `
            -Value "eps_auto_file" `
            -PropertyType String
        Set-ItemProperty `
            -Path HKLM:\SOFTWARE\Classes\.eps `
            -Name "Content Type" `
            -Value "application/postscript" `

        New-ItemProperty `
            -Path HKLM:\SOFTWARE\Classes\.ai `
            -Name '(default)' `
            -Value "ai_auto_file" `
            -PropertyType String
    }
}

function Remove-AllPhotoshopTemporaryFiles {
    param (
        [Parameter(Mandatory)]$ComputerName,
        [switch]$WhatIf
    )
    $RunningProcesses = Get-Process -ComputerName $ComputerName
    if (
        ($RunningProcesses -match "Photoshop") -or
        ($RunningProcesses -match "Illustrator") -or
        ($RunningProcesses -match "Bridge")        
    ) {
        throw "Photoshop, Illustrator, and/or Bridge are still running on $ComputerName"
    }
    $UserProfiles = Get-UserProfilesOnComputer -Computer $ComputerName | select -ExpandProperty UserProfileName
    foreach ($Profile in $UserProfiles) {
        $PhotoShopTempFiles = Get-ChildItem \\$ComputerName\C$\Users\$Profile\AppData\Local\Temp -Filter "Photoshop Temp*" | 
            Remove-Item -WhatIf:$WhatIf
    }
}

function Set-TervisSurfaceMESKioskMode {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName,
        [ValidateSet("Delta","Epsilon","Production")]$MESEnvironment = "Production"
    )
    begin {
        $ADDomain = (Get-ADDomain).DNSRoot
        $AutoLogonSID = (Get-ADUser -Filter {Name -like "Surface*"}).SID.Value
        $KioskURL = "mesiis.$MESEnvironment.$ADDomain"
    }
    process {
        Write-Verbose "Setting Surface MES Kiosk mode"
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Enable-WindowsOptionalFeature -FeatureName Client-DeviceLockdown -Online
            Enable-WindowsOptionalFeature -FeatureName Client-EmbeddedShellLauncher -Online
            $ShellLauncherClass = [wmiclass]"\\localhost\root\standardcimv2\embedded:WESL_UserSetting"
            $ShellLauncherClass.RemoveCustomShell($Using:AutoLogonSID)
            $ShellLauncherClass.SetCustomShell($Using:AutoLogonSID, "c:\program files\internet explorer\iexplore.exe -k $Using:KioskURL", ($null), ($null), 0)
            $ShellLauncherClass.SetDefaultShell("explorer.exe",0)
            $ShellLauncherClass.SetEnabled($TRUE)
        }
    }
}

function Set-TervisAutoHotKeyF2PrintScript {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName
    )
    begin {
        $AHKScript = @"
F2:: ;Supports Wasp pen scanners
	Send,{CTRLDOWN}p{CTRLUP}
Return

::`$TB:: ;Supports Bluetooth scanners
	Send,{CTRLDOWN}p{CTRLUP}
Return       
"@
        $ScriptsDirectory = "C:\Scripts"
        $LogonRegistryKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        $LogonRegistryName = "F2Print"
        $LogonRegistryValue = "$ScriptsDirectory"
    }
    process {
        $RemoteScriptsDirectory = $ScriptsDirectory | ConvertTo-RemotePath -ComputerName $ComputerName
        if (-not (Test-Path -Path $RemoteScriptsDirectory)) {
            New-Item -Path $RemoteScriptsDirectory -ItemType Directory
        }
        Write-Verbose "Creating F2Print script on $RemoteScriptsDirectory"
        $AHKScript | Out-File -FilePath $RemoteScriptsDirectory\F2Print.ahk -Encoding utf8
        Write-Verbose "Creating Run F2Print on Logon registry key"
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            if (-not (Get-ItemProperty -Path $Using:LogonRegistryKey -Name $Using:LogonRegistryName -ErrorAction SilentlyContinue)) {                            
                New-ItemProperty -Path $Using:LogonRegistryKey -Name $Using:LogonRegistryName -Value "Autohotkey $Using:ScriptsDirectory\F2Print.ahk" -PropertyType String
            } else {
                Set-ItemProperty -Path $Using:LogonRegistryKey -Name $Using:LogonRegistryName -Value "Autohotkey $Using:ScriptsDirectory\F2Print.ahk"
            }
        }
    }
}

function Invoke-PushSurfaceMESSettings {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName,
        [ValidateSet("Delta","Epsilon","Production")]$MESEnvironment = "Production"
    )
    process {
        $PSDefaultParameterValues = @{"*:ComputerName" = $ComputerName}
        Invoke-Command -ScriptBlock {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AutoRotation" -Name Enable -Value 0
        }
        #Invoke-TervisGroupPolicyUpdateForceRestart 
        Set-TervisEndpointPowerPlan -PowerPlanProfile "High Performance"
        Set-TervisAutoHotKeyF2PrintScript
        Set-TervisSurfaceMESKioskMode -MESEnvironment $MESEnvironment
        Invoke-TervisGroupPolicyUpdateForceRestart
        Restart-Computer -Force #-Wait 
        $PSDefaultParameterValues.Clear()
    }
}

function Install-AdobeReaderOnEndpoint {
<#
.DESCRIPTION
Intended to accept an ADComputer object through the pipeline and attempt to install Adobe Reader. Returns a PSCustomObject result.
.EXAMPLE
$Windows10MESStations =  Get-ADComputer -Filter {(OperatingSystem -like "*10*") -and (Name -like "0*")} | ? Enabled -eq $true
$Result = $null 
$Windows10MESStations | Install-AdobeReaderOnEndpoint | ? InstallStatus -NE $null | Tee-Object -Variable Result
#>
    param (
        [Parameter(ValueFromPipelineByPropertyName)]$Name
    )
    process {
        #$Name.GetType()
        if ((Test-NetConnection -ComputerName $Name -CommonTCPPort WINRM).TcpTestSucceeded) {
            try {
                Invoke-Command -ComputerName $Name -Scriptblock {
                    choco install adobereader -y
                } -ErrorAction Stop | Out-Null
                $RemoteInstallPath = 'C:\Program Files (x86)\Adobe\Acrobat Reader DC' | ConvertTo-RemotePath -ComputerName $Name
                if (Test-Path $RemoteInstallPath) {
                    $InstallStatus = "Successful"
                } else {throw}
            } catch {
                 $InstallStatus = "Failed"
            }
        } else {
            Write-Warning "Could not reach $($Name)"
            $InstallStatus = "NoConnection"
        }
        [PSCustomObject][Ordered]@{
            ComputerName = $Name
            InstallStatus = $InstallStatus
        }
    }
}

function Move-ADComputerOrUserToSourceOU{
    param(
        [cmdletbinding()]
        [Parameter(Mandatory="True")][ValidateSet("Computer","User")]$ADObjectType,
        [Parameter(Mandatory="True")]$IdentityOfADObjectBeingMoved,
        [Parameter(Mandatory="True")]$IdentityOfSourceADObject

    )
    
    if ($ADObjectType -eq "User"){
        [string]$Path = Get-ADUser $IdentityOfSourceADObject -Properties distinguishedname,cn | select @{n='ParentContainer';e={$_.distinguishedname -replace '^.+?,(CN|OU.+)','$1'}} | Select -ExpandProperty ParentContainer
        Get-ADUser -Identity $IdentityOfADObjectBeingMoved | Move-ADObject -TargetPath $Path
        [string]$NewPath = Get-ADComputer $IdentityOfADObjectBeingMoved -Properties distinguishedname,cn | select @{n='ParentContainer';e={$_.distinguishedname -replace '^.+?,(CN|OU.+)','$1'}} | Select -ExpandProperty ParentContainer
        Write-Host "$IdentityOfADObjectBeingMoved location is now $NewPath"
    } 
    if ($ADObjectType -eq "Computer"){
        [string]$Path = Get-ADComputer $IdentityOfSourceADObject -Properties distinguishedname,cn | select @{n='ParentContainer';e={$_.distinguishedname -replace '^.+?,(CN|OU.+)','$1'}} | Select -ExpandProperty ParentContainer
        Get-ADComputer -Identity $IdentityOfADObjectBeingMoved | Move-ADObject -TargetPath $Path
        [string]$NewPath = Get-ADComputer $IdentityOfADObjectBeingMoved -Properties distinguishedname,cn | select @{n='ParentContainer';e={$_.distinguishedname -replace '^.+?,(CN|OU.+)','$1'}} | Select -ExpandProperty ParentContainer
        Write-Host "$IdentityOfADObjectBeingMoved location is now $NewPath"
    }
}

function Install-DotNet35OnEndpoint {
    param (
        [Parameter(ValueFromPipelineByPropertyName)]$ComputerName
    )
    process {
        Copy-Item -Path "\\$env:USERDNSDOMAIN\applications\PowerShell\DotNet35" -Destination "\\$ComputerName\C$\DotNet35" -Recurse -Force
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Start-DscConfiguration -Wait -Force -Path "C:\DotNet35"
        }
    }
}

function New-iQExplorerIIOptionsFile {
    param (
        [Parameter(ValueFromPipelineByPropertyName)]$ComputerName
    )
    begin {
        $RemoteProgramDataRoot = "C:\ProgramData" | ConvertTo-RemotePath -ComputerName $ComputerName
    }
    process {
        $DukaneRoot = New-Item -Path $RemoteProgramDataRoot -Name "Dukane Corporation" -ItemType Directory -Force
        $FolderAcl = $DukaneRoot | Get-Acl
        
        $IdentityReference = "Authenticated Users"
        $FileSystemRights = [System.Security.AccessControl.FileSystemRights]::Modify
        $InheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::ObjectInherit,[System.Security.AccessControl.InheritanceFlags]::ContainerInherit
        $PropagationFlags = [System.Security.AccessControl.PropagationFlags]::None
        $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
        $FileSystemAccessRule = [System.Security.AccessControl.FileSystemAccessRule]::new($IdentityReference,$FileSystemRights,$InheritanceFlags,$PropagationFlags,$AccessControlType)

        $FolderAcl.AddAccessRule($FileSystemAccessRule)
        Set-Acl -Path $DukaneRoot -AclObject $FolderAcl

        $iQExplorerIIPath = New-Item -Path $DukaneRoot -Name "iQ Explorer II" -ItemType Directory -Force
        
        $OptionsFileString = @"
<?xml version="1.0" standalone="yes"?>
<iQOptions_v1_0>
  <RestrictedIpAddr>
    <Name>169.254.1.1</Name>
  </RestrictedIpAddr>
</iQOptions_v1_0>
"@
        $OptionsFileString | Out-File -FilePath "$($iQExplorerIIPath.FullName)\iQOptions.xml" -Encoding utf8 -Force
    }
}

function Enable-TouchKeyboardOnWindows10Endpoint {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName
    )
    process {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\TabletTip\1.7 -Name TipbandDesiredVisibility -PropertyType DWORD -Value 1 -Force
        }
    }
}
