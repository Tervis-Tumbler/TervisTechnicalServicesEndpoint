﻿#Requires -version 5.0
#Requires -modules PasswordstatePowershell, TervisChocolatey, TervisNetTCPIP
#Requires -RunAsAdministrator

function Add-IPAddressToWSManTrustedHosts {
    [CmdletBinding()]
    param (
        [parameter(Mandatory, ValueFromPipeline)][string]$IPAddress
    )
    Write-Verbose "Adding $IPAddress to WSMan Trusted Hosts"
    Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value $IPAddress -Force
}

function Get-WSManTrustedHosts {
    Get-Item -Path WSMan:\localhost\Client\TrustedHosts
}

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

function Get-TervisEndpointIPAddressAsString {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][String]$MACAddressWithDashes
    )

    Write-Verbose "Getting IP address"
    $EndpointIPAddress = Find-DHCPServerv4LeaseIPAddress -MACAddressWithDashes $MACAddressWithDashes -AsString
    
    if (-not $EndpointIPAddress) { 
        throw "No ip v4 lease found for MacAddress $MACAddressWithDashes" 
    } else {
        Write-Verbose "IP address found: $EndpointIPAddress"
    }

    $EndpointIPAddress
}

function New-TervisEndpoint {    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][ValidateSet("ContactCenterAgent","BartenderPrintStationKiosk","StandardOfficeEndpoint","ShipStation","CafeKiosk","IT")][String]$EndpointTypeName,
        [Parameter(Mandatory,ParameterSetName="EndpointMacAddress")][String]$MACAddressWithDashes,
        [Parameter(Mandatory,ParameterSetName="EndpointIPAddress")][String]$EndpointIPAddress,
        [Parameter(Mandatory)][String]$NewComputerName
    )
    $EndpointType = Get-TervisEndpointType -Name $EndpointTypeName

    Write-Verbose "Getting domain admin credentials"
    $DomainAdministratorCredential = Get-Credential -Message "Enter credentials used to join computer to domain"
    
    Write-Verbose "Getting local admin credentials"
    $LocalAdministratorCredential = Get-PasswordstateCredential -PasswordID 3954

    if ($MACAddressWithDashes) {
        $EndpointIPAddress = Get-TervisEndpointIPAddressAsString -MACAddressWithDashes $MACAddressWithDashes
    }
    Add-IPAddressToWSManTrustedHosts -IPAddress $EndpointIPAddress

    Set-TervisEndpointNameAndDomain -OUPath $EndpointType.DefaultOU -NewComputerName $NewComputerName -EndpointIPAddress $EndpointIPAddress -LocalAdministratorCredential $LocalAdministratorCredential -DomainAdministratorCredential $DomainAdministratorCredential -ErrorAction Stop

    $PSDefaultParameterValues = @{"*:ComputerName" = $NewComputerName}
    Set-TervisEndpointPowerPlan -PowerPlanProfile "High Performance"
    Sync-ADDomainControllers
    Add-EndpointToPrivilege_PrincipalsAllowedToDelegateToAccount
    Remove-KerberosTickets
    New-TervisLocalAdminAccount
    Set-TervisBuiltInAdminAccountPassword
    Disable-TervisBuiltInAdminAccount
    Install-TervisChocolatey
    Install-TervisChocolateyPackages -ChocolateyPackageGroupNames $EndpointType.ChocolateyPackageGroupNames
    Add-ADGroupMember -Identity "EndpointType_$($EndpointType.Name)" -Members (Get-ADComputer -Identity $NewComputerName)

    if ($EndpointType.InstallScript) {
        Invoke-Command -ScriptBlock $EndpointType.InstallScript
    }

    if ($EndpointType.Name -eq "CafeKiosk") {
        Write-Verbose "Starting Cafe Kiosk install"
        New-TervisEndpointCafeKiosk -EndpointName $NewComputerName 
    }
    $PSDefaultParameterValues.clear()
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
        Write-Verbose "Starting Contact Center Agent install"
        Start-DscConfiguration -Wait -Path \\$env:USERDNSDOMAIN\applications\PowerShell\DotNet35
        Copy-Item -Path "\\$env:USERDNSDOMAIN\applications\PowerShell\FedEx Customer Tools" -Destination "c:\programdata\" -Recurse
    }
    DefaultOU = "OU=Computers,OU=Sales,OU=Departments,DC=tervis,DC=prv"
    ChocolateyPackageGroupNames = "StandardOfficeEndpoint","ContactCenter"
},
[PSCustomObject][Ordered]@{
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
    DefaultOU = "OU=Computers,OU=Sales,OU=Departments,DC=tervis,DC=prv"
},
[PSCustomObject][Ordered]@{
    Name = "ShipStation"
    BaseName = "Ship"
    DefaultOU = "OU=Computers,OU=Shipping Stations,OU=Operations,OU=Departments,DC=tervis,DC=prv"
    InstallScript = {
        Write-Verbose "Starting Expeditor install"
        Install-WCSScaleSupport
    }
    ChocolateyPackageGroupNames = "StandardOfficeEndpoint"
},
[PSCustomObject][Ordered]@{
    Name = "IT"
    ChocolateyPackageGroupNames = "StandardOfficeEndpoint","IT"
    DefaultOU = "OU=Computers,OU=Information Technology,OU=Departments,DC=tervis,DC=prv"
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

function Add-EndpointToPrivilege_PrincipalsAllowedToDelegateToAccount {
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
        [Parameter(Mandatory)]$NewComputerName,
        [Parameter(Mandatory)]$EndpointIPAddress,
        [Parameter(Mandatory)]$LocalAdministratorCredential,
        [Parameter(Mandatory)]$DomainAdministratorCredential,
        $OUPath,
        $DomainName = "$env:USERDNSDOMAIN",
        $TimeToWaitForGroupPolicy = "180"
    )

    Write-Verbose "Renaming endpoint and restarting"
    Invoke-Command -ComputerName $EndpointIPAddress -Credential $LocalAdministratorCredential -ScriptBlock {
        param($NewComputerName,$LocalAdministratorCredential)
        
        Rename-Computer -NewName $NewComputerName -LocalCredential $LocalAdministratorCredential -Force -Restart

    } -ArgumentList $NewComputerName,$LocalAdministratorCredential -ErrorAction Stop

    Wait-ForEndpointRestart -IPAddress $EndpointIPAddress -PortNumbertoMonitor 5985

    if (!($OUPath)) {
        $OUPath = "OU=Sandbox,DC=tervis,DC=prv"
    }

    Write-Verbose "Adding endpoint to domain"
    Invoke-Command -ComputerName $EndpointIPAddress -Credential $LocalAdministratorCredential -ScriptBlock {
        param($DomainName,$OUPath,$DomainAdministratorCredential)
        
        Add-Computer -DomainName $DomainName -Force -Restart -OUPath $OUPath -Credential $DomainAdministratorCredential

    } -ArgumentList $DomainName,$OUPath,$DomainAdministratorCredential
    
    Wait-ForEndpointRestart -IPAddress $EndpointIPAddress -PortNumbertoMonitor 5985
    
    Write-Verbose "Waiting for Group Policy update to complete"
    Start-Sleep -Seconds $TimeToWaitForGroupPolicy

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
        param($TumblerAdminPassword)
        
        New-LocalUser -Name "TumblerAdministrator" -Password $TumblerAdminPassword -FullName "TumblerAdministrator" -Description "Local Admin Account" -PasswordNeverExpires
        Add-LocalGroupMember -Name "Administrators" -Member "TumblerAdministrator"

    } -ArgumentList $TumblerAdminPassword
}

function Get-TervisLocalAdminAccount {
    param (
        [Parameter(Mandatory)]$ComputerName,
        $LocalUserName = '*'
    )

    Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        param($LocaUserName)
        
        Get-LocalUser -Name $LocaUserName

    } -ArgumentList $LocalUserName
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
        param($BuiltinAdminPassword)
        
        Set-LocalUser -Name Administrator -Password $BuiltinAdminPassword

    } -ArgumentList $BuiltinAdminPassword
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
        [Parameter(Mandatory)]
        [ValidateSet("High Performance")]
        [String]$PowerPlanProfile,

        [Parameter(Mandatory)]
        [String]$ComputerName,

        [pscredential]$Credential = [System.Management.Automation.PSCredential]::Empty
    )

    Write-Verbose "Setting power configuration to $PowerPlanProfile"
    $ActivePowerScheme = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {        
        param($PowerPlanProfile)

        $PowerPlanInstanceID = (Get-WmiObject -Class win32_powerplan -Namespace root\cimv2\power -Filter "ElementName=`'$PowerPlanProfile`'").InstanceID
        $PowerPlanGUID = $PowerPlanInstanceID.split("{")[1].split("}")[0]
        powercfg -S $PowerPlanGUID
        $ActivePowerScheme = powercfg /getactivescheme
        $ActivePowerScheme  
    } -ArgumentList $PowerPlanProfile

    Write-Verbose $ActivePowerScheme
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
    $JavaLibDir = "$env:JAVA_HOME\lib\"
    $JavaBinDir = "$env:JAVA_HOME\bin\"
    $LibFileSource = "\\fs1\DisasterRecovery\Programs\WCS\Scale Dependancies\javax.comm.properties"
    $BinFileSource = "\\fs1\DisasterRecovery\Programs\WCS\Scale Dependancies\win32com.dll"
    Copy-Item -Path $LibFileSource -Destination $JavaLibDir
    Copy-Item -Path $BinFileSource -Destination $JavaBinDir
}

function Set-TervisUserAsLocalAdmin {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]$SAMAccountName,
        $ComputerName
    )

    if ($ComputerName -eq $null) {
        Write-Verbose "Finding user's last used computer"
        $ComputerName = Find-TervisADUsersComputer -SAMAccountName $SAMAccountName -Properties LastLogonDate |
            sort -Property LastLogonDate |
            select -Last 1 |
            select -ExpandProperty Name
    }

    Write-Verbose 'Adding computer to "Local - Computer Admin Group Exception"'
    $ComputerObject = Get-ADComputer -Identity $ComputerName
    Add-ADGroupMember -Identity "Local - Computer Admin Group Exception" -Members $ComputerObject

    try {
        Write-Verbose "Connecting to remote computer"
        $Result = Invoke-Command -ComputerName $ComputerName -ArgumentList $SAMAccountName -ScriptBlock {
            param (
                $SAMAccountName
            )

            #$LocalAdministrators = Get-LocalGroupMember -Group Administrators | select -ExpandProperty Name
            # PowerShell 2.0 Compatible 
            $LocalAdminGroup = [ADSI]"WinNT://$env:COMPUTERNAME/Administrators,group"
            $LocalAdministrators = $LocalAdminGroup.invoke("members") | 
                foreach {$_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)}

            if ($LocalAdministrators -match $SAMAccountName) {
                return "Set"
            } else {
                try {
                    # PowerShell 2.0 Compatible
                    $LocalAdminGroup.Add("WinNT://$env:USERDOMAIN/$SAMAccountName,user") | Out-Null
                    
                    #Add-LocalGroupMember -Group Administrators -Member $SAMAccountName -ErrorAction Stop
                    return "Set"
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
        LocalAdminSet = $Result
    }
}