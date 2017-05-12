#Requires -version 5.0
#Requires -modules PasswordstatePowershell, TervisChocolatey, TervisNetTCPIP
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
        [Parameter(Mandatory)][ValidateSet("ContactCenterAgent","BartenderPrintStationKiosk","StandardOfficeEndpoint","ShipStation","CafeKiosk","IT","MESAuditor")][String]$EndpointTypeName,
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

    if ($EndpointType.InstallScript) {
        Invoke-Command -ScriptBlock $EndpointType.InstallScript
    }

    if ($EndpointType.Name -eq "CafeKiosk") {
        Write-Verbose "Starting Cafe Kiosk install"
        New-TervisEndpointCafeKiosk -EndpointName $ComputerName 
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
    DefaultOU = "OU=Sandbox,DC=tervis,DC=prv"
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
        [Parameter(Mandatory)]
        [ValidateSet("High Performance")]
        [String]$PowerPlanProfile,

        [Parameter(Mandatory)]
        [String]$ComputerName,

        [pscredential]$Credential = [System.Management.Automation.PSCredential]::Empty
    )

    Write-Verbose "Setting power configuration to $PowerPlanProfile"
    $ActivePowerScheme = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {        
        $PowerPlanInstanceID = (Get-WmiObject -Class win32_powerplan -Namespace root\cimv2\power -Filter "ElementName=`'$Using:PowerPlanProfile`'").InstanceID
        $PowerPlanGUID = $PowerPlanInstanceID.split("{")[1].split("}")[0]
        powercfg -S $PowerPlanGUID
        $ActivePowerScheme = powercfg /getactivescheme
        $ActivePowerScheme  
    }

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

    [Scriptblock]$InstallScript = {    
        choco install ghostscript.app --version 9.20 -y
        choco install gimp --version 2.8.20 -y

        # Add environment variable - GS_PROG value: "C:\Program Files\gs\gs9.20\bin\gswin64c.exe"
        [Environment]::SetEnvironmentVariable( "GS_PROG", '"C:\Program Files\gs\gs9.20\bin\gswin64c.exe"', "Machine")
        # Copy GS DLL to GIMP Bin
        Write-Host -ForegroundColor Cyan -BackgroundColor Black "Copying Ghostscript files"
        Copy-Item -Path "C:\Program Files\gs\gs9.20\bin\gsdll64.dll" -Destination "C:\Program Files\GIMP 2\bin\libgs-8.dll" -Force

        # Associating GIMP with EPS,PS
        Write-Host -ForegroundColor Cyan -BackgroundColor Black "Writing file associations to registry"
        New-Item -Path HKLM:\SOFTWARE\Classes\ps_auto_file
        New-Item -Path HKLM:\SOFTWARE\Classes\ps_auto_file\shell
        New-Item -Path HKLM:\SOFTWARE\Classes\ps_auto_file\shell\open
        New-Item -Path HKLM:\SOFTWARE\Classes\ps_auto_file\shell\open\command
        New-ItemProperty `
            -Path HKLM:\SOFTWARE\Classes\ps_auto_file\shell\open\command `
            -Name '(default)' `
            -Value '"C:\Program Files\GIMP 2\bin\gimp-2.8.exe" "%1"' `
            -PropertyType String
            #-Value '"C:\Program Files\gs\gs9.20\bin\gswin64c.exe" -g2000x2000 "%1"' `

        New-Item -Path HKLM:\SOFTWARE\Classes\eps_auto_file
        New-Item -Path HKLM:\SOFTWARE\Classes\eps_auto_file\shell
        New-Item -Path HKLM:\SOFTWARE\Classes\eps_auto_file\shell\open
        New-Item -Path HKLM:\SOFTWARE\Classes\eps_auto_file\shell\open\command
        New-ItemProperty `
            -Path HKLM:\SOFTWARE\Classes\eps_auto_file\shell\open\command `
            -Name '(default)' `
            -Value '"C:\Program Files\GIMP 2\bin\gimp-2.8.exe" "%1"' `
            -PropertyType String
            #-Value '"C:\Program Files\gs\gs9.20\bin\gswin64c.exe" -g2000x2000 "%1"' `

        New-Item -Path HKLM:\SOFTWARE\Classes\ai_auto_file
        New-Item -Path HKLM:\SOFTWARE\Classes\ai_auto_file\shell
        New-Item -Path HKLM:\SOFTWARE\Classes\ai_auto_file\shell\open
        New-Item -Path HKLM:\SOFTWARE\Classes\ai_auto_file\shell\open\command
        New-ItemProperty `
            -Path HKLM:\SOFTWARE\Classes\ai_auto_file\shell\open\command `
            -Name '(default)' `
            -Value '"C:\Program Files (x86)\Foxit Software\Foxit Reader\FoxitReader.exe" "%1"' `
            -PropertyType String

        #New-Item -Path HKLM:\SOFTWARE\Classes\.ps
        New-ItemProperty `
            -Path HKLM:\SOFTWARE\Classes\.ps `
            -Name '(default)' `
            -Value "ps_auto_file" `
            -PropertyType String
        Set-ItemProperty `
            -Path HKLM:\SOFTWARE\Classes\.ps `
            -Name "Content Type" `
            -Value "application/postscript" `
            #-PropertyType String

        #New-Item -Path HKLM:\SOFTWARE\Classes\.eps
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

        choco install foxitreader -y
    }

    Install-TervisChocolatey -ComputerName $ComputerName -Verbose
    Invoke-Command -ComputerName $ComputerName -ScriptBlock $InstallScript -Verbose
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
        Write-Verbose "Updating Group Policy on $ComputerName"
        Invoke-GPUpdate -Boot -Computer $ComputerName -RandomDelayInMinutes 0 -Force
        Write-Verbose "Waiting on computer restart"
        Wait-ForNodeRestart @PSBoundParameters
    }
}
