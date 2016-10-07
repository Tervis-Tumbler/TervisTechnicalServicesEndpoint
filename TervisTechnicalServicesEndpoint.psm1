function Add-IPAddressToWSManTrustedHosts {
    [CmdletBinding()]
    param (
        [parameter(Mandatory, ValueFromPipeline)][string]$IPAddress
    )

    Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value $IPAddress -Force
}

function Get-WSManTrustedHosts {

    Get-Item -Path WSMan:\localhost\Client\TrustedHosts

}

function Enter-PSSessionToNewEndpoint {
    [CmdletBinding()]
    param (
        [parameter(Mandatory, ValueFromPipeline)]$IPAddress
    )    
    $Credentials = Get-Credential

    Enter-PSSession -ComputerName $IPAddress -Credential $Credentials
}

function New-CustomerCareSignatures {

param(            
[parameter (Mandatory)][string]$UserName,
[parameter (Mandatory)][string]$Computername,
[parameter()][string]$SignatureTemplateLocation = "\\dfs-13\Departments - I Drive\Sales\DTC\Signatures"
)  

Copy-Item -Path $SignatureTemplateLocation -Destination C:\SigTemp\Signatures -Recurse

#Placeholders
$NameHolder = '\[Name\]'
$PersonalEmailHolder = '\[PersonalEmail\]'
$TitleHolder = '\[Title\]'

#Get AD info of current user
$ADUser = Get-ADUser -Identity $Username -Properties name,title,mail
$ADDisplayName = $ADUser.Name
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

function New-TervisEndpoint {
    #Requires -version 5.0
    #Requires -modules PasswordstatePowershell
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [String]$EndpointTypeName,
        
        [Parameter(Mandatory)]
        [String]$MACAddressWithDashes,
        
        [Parameter(Mandatory)]
        [String]$NewComputerName,
        
        [Parameter(Mandatory)]
        [String]$PasswordstateListAPIKey
    )

    $EndpointType = Get-TervisEndpointType -Name $EndpointTypeName

    Write-Verbose "Getting IP address..."

    $EndpointIPAddress = (Find-DHCPServerv4Lease -MACAddressWithDashes $MACAddressWithDashes).IPAddress.IPAddressToString

    Write-Verbose "IP address found: $EndpointIPAddress"

    Write-Verbose "Adding host to WSMan Trusted Hosts..."

    Add-IPAddressToWSManTrustedHosts -IPAddress $EndpointIPAddress

    Write-Verbose "Getting local admin credentials..."

    $LocalAdministratorCredential = Get-PasswordstateCredential -PasswordstateListAPIKey $PasswordstateListAPIKey -PasswordID 3954

    Write-Verbose "Getting domain admin credentials..."

    $DomainAdministratorCredential = Get-Credential -Message "Enter domain administrator credentials."

    Set-TervisEndpointNameAndDomain -OUPath $EndpointType.DefaultOU -NewComputerName $NewComputerName -EndpointIPAddress $EndpointIPAddress -LocalAdministratorCredential $LocalAdministratorCredential -DomainAdministratorCredential $DomainAdministratorCredential -ErrorAction Stop

    Write-Verbose "Forcing a sync between domain controllers..."
    $DC = Get-ADDomainController | Select -ExpandProperty HostName
    Invoke-Command -ComputerName $DC -ScriptBlock {repadmin /syncall}
    Start-Sleep 30 
    
    Write-Verbose "Setting Resource-Based Kerberos Constrained Delegation..."

    Set-PrincipalsAllowedToDelegateToAccount -EndpointToAccessResource $NewComputerName -Credentials $DomainAdministratorCredential

    Write-Verbose "Creating TumblerAdministrator local account..."

    New-TervisLocalAdminAccount -ComputerName $NewComputerName -PasswordstateListAPIKey $PasswordstateListAPIKey
        
    Write-Verbose "Resetting password of built-in Administrator account..."

    Set-TervisBuiltInAdminAccountPassword -ComputerName $NewComputerName -PasswordstateListAPIKey $PasswordstateListAPIKey

    Write-Verbose "Disabling built-in Administrator account..."
        
    Disable-TervisBuiltInAdminAccount -ComputerName $NewComputerName

    Write-Verbose "Installing Chocolatey..."

    Install-TervisEndpointChocolatey -EndpointName $NewComputerName -Credentials $DomainAdministratorCredential

    if ($EndpointType.Name -eq "ContactCenterAgent") {        
        
        Write-Verbose "Starting Contact Center Agent install..."
        
        New-TervisEndpointContactCenterAgent -EndpointName $NewComputerName -Credential $DomainAdministratorCredential -InstallScript $EndpointType.InstallScript        

    }
    elseif ($EndpointType.Name -eq "CafeKiosk") {
        
        Write-Verbose "Starting Cafe Kiosk install..."
        
        New-TervisEndpointCafeKiosk -EndpointName $NewComputerName -Credential $DomainAdministratorCredential -InstallScript $EndpointType.InstallScript -EndpointIPAddress $EndpointIPAddress     


    }
}

function Install-TervisEndpointChocolatey {
    [CmdletBinding()]
    param (
        $EndpointName,
        $Credentials    
    )

    Write-Verbose "Installing Chocolatey..."

    Invoke-Command -ComputerName $EndpointName -Credential $Credentials -ScriptBlock {
       
        iwr https://chocolatey.org/install.ps1 -UseBasicParsing | iex
        
        refreshenv
        
        choco feature enable -n allowEmptyChecksums

        choco source add -n=Tervis -s"\\tervis.prv\applications\chocolatey\"

        choco source list
    }
}

function Get-TervisEndpointType {
    param (
        $Name
    )

    $EndpointTypes | where Name -eq $Name
}

$EndpointTypes = [PSCustomObject][Ordered] @{
    Name = "ContactCenterAgent"
    InstallScript = {

        choco install CiscoJabber -y

        choco install CiscoAgentDesktop -y

        choco install googlechrome -y

        choco install firefox -y

        choco install autohotkey -y

    }
    DefaultOU = "OU=Computers,OU=Sales,OU=Departments,DC=tervis,DC=prv"
},
[PSCustomObject][Ordered] @{
    Name = "BartenderPrintStationKiosk"
    BaseName = "LabelPrint"
    DefaultOU = "OU=BartenderPCs,OU=IndustryPCs,DC=tervis,DC=prv"
},
[PSCustomObject][Ordered] @{
    Name = "CafeKiosk"
    BaseName = "Cafe"
    DefaultOU="OU=Cafe Kiosks,OU=Human Resources,OU=Departments,DC=tervis,DC=prv"
    InstallScript = {
    
    #choco install adobereader -y

    #choco install office365-2016-deployment-tool -version 16.0.7213.5776 -y

    }    
}

function New-TervisEndpointContactCenterAgent {
    param (
        $EndpointName,
        $Credentials,
        $InstallScript
    )

        Invoke-Command -ComputerName $EndpointName -Credential $Credentials -ScriptBlock $InstallScript
}

function New-TervisEndpointCafeKiosk {
    param (
        $EndpointName,
        $EndpointIPAddress,
        $Credentials,
        $InstallScript
    )

        Write-Verbose "Updating Group Policy on endpoint..."

        Invoke-GPUpdate -Computer $EndpointName -RandomDelayInMinutes 0 -Force | Out-Null

        Write-Verbose "Restarting endpoint..."

        Restart-Computer -ComputerName $EndpointName -Force

        Write-Verbose "Waiting for endpoint to reboot..."

        Wait-ForEndpointRestart -IPAddress $EndpointIPAddress -PortNumbertoMonitor 5985
        
        Invoke-Command -ComputerName $EndpointName -Credential $Credentials -ScriptBlock $InstallScript
}

function Set-PrincipalsAllowedToDelegateToAccount {
    [CmdletBinding()]
    param (
        $EndpointToAccessResource,
        $Credentials = (Get-Credential),
        $ComputerName
    )

    $EndpointObjectToAccessResource = Get-ADComputer -Identity $EndpointToAccessResource

    Add-ADGroupMember -Identity Privilege_PrincipalsAllowedToDelegateToAccount -Members $EndpointObjectToAccessResource

    Invoke-Command -ComputerName $EndpointToAccessResource -Credential $Credentials -ScriptBlock {            
        
        klist purge -li 0x3e7            
    
    }
}

function Set-TervisEndpointNameAndDomain {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]$NewComputerName,
        [Parameter(Mandatory)]$EndpointIPAddress,
        [Parameter(Mandatory)]$OUPath,
        [Parameter(Mandatory)]$LocalAdministratorCredential,
        [Parameter(Mandatory)]$DomainAdministratorCredential,
        $DomainName = 'tervis.prv',
        $TimeToWaitForGroupPolicy = '180'
    )

    Write-Verbose 'Renaming endpoint and restarting...'

    Invoke-Command -ComputerName $EndpointIPAddress -Credential $LocalAdministratorCredential -ScriptBlock {
        param($NewComputerName,$LocalAdministratorCredential)
        
        Rename-Computer -NewName $NewComputerName -LocalCredential $LocalAdministratorCredential -Force -Restart

        } -ArgumentList $NewComputerName,$LocalAdministratorCredential -ErrorAction Stop

    Wait-ForEndpointRestart -IPAddress $EndpointIPAddress -PortNumbertoMonitor 5985

    Write-Verbose 'Adding endpoint to domain...'

    Invoke-Command -ComputerName $EndpointIPAddress -Credential $LocalAdministratorCredential -ScriptBlock {
        param($NewComputerName,$DomainName,$OUPath,$DomainAdministratorCredential)
        
        Add-Computer -DomainName $DomainName -Force -Restart -OUPath $OUPath -Credential $DomainAdministratorCredential

        } -ArgumentList $NewComputerName,$DomainName,$OUPath,$DomainAdministratorCredential
    
    Wait-ForEndpointRestart -IPAddress $EndpointIPAddress -PortNumbertoMonitor 5985
    
    Write-Verbose 'Waiting for Group Policy update to complete.'

    Start-Sleep -Seconds $TimeToWaitForGroupPolicy

}

function Wait-ForEndpointRestart{
    #Requires -Modules TervisTechnicalServicesLinux
    
    Param(
        [Parameter(Mandatory)]$IPAddress,
        [Parameter(Mandatory)]$PortNumbertoMonitor
    )
    Write-Verbose "Waiting for endpoint to reboot..."

    Wait-ForPortNotAvailable -IPAddress $IPAddress -PortNumbertoMonitor $PortNumbertoMonitor -WarningAction SilentlyContinue
    
    Write-Verbose "Waiting for endpoint to startup..."
    
    Wait-ForPortAvailable -IPAddress $IPAddress -PortNumbertoMonitor $PortNumbertoMonitor -WarningAction SilentlyContinue

    Write-Verbose "Endpoint is up and running..."

}

function New-TervisLocalAdminAccount {
    #Requires -version 5.0
    #Requires -modules PasswordstatePowershell

    Param(
        [Parameter(Mandatory)]$ComputerName,
        [Parameter(Mandatory)]$PasswordstateListAPIKey
    )
    
    $TumblerAdminCredential = Get-PasswordstateCredential -PasswordstateListAPIKey $PasswordstateListAPIKey -PasswordID 14
    
    $TumblerAdminPassword = $TumblerAdminCredential.Password

    Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        param($TumblerAdminPassword)
        
        New-LocalUser -Name "TumblerAdministrator" -Password $TumblerAdminPassword -FullName "TumblerAdministrator" -Description "Local Admin Account" -PasswordNeverExpires
        Add-LocalGroupMember -Name "Administrators" -Member "TumblerAdministrator"

        } -ArgumentList $TumblerAdminPassword
}

function Get-TervisLocalAdminAccount {
    #Requires -version 5.0

    Param(
        [Parameter(Mandatory)]$ComputerName,
        $LocalUserName = '*'
    )

    Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        param($LocaUserName)
        
        Get-LocalUser -Name $LocaUserName

    } -ArgumentList $LocalUserName
}

function Set-TervisBuiltInAdminAccountPassword {
    #Requires -version 5.0
    #Requires -modules PasswordstatePowershell

    Param(
        [Parameter(Mandatory)]$ComputerName,
        [Parameter(Mandatory)]$PasswordstateListAPIKey
    )
    
    $BuiltinAdminCredential = Get-PasswordstateCredential -PasswordstateListAPIKey $PasswordstateListAPIKey -PasswordID 3972
    
    $BuiltinAdminPassword = $BuiltinAdminCredential.Password

    Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        param($BuiltinAdminPassword)
        
        Set-LocalUser -Name Administrator -Password $BuiltinAdminPassword

    } -ArgumentList $BuiltinAdminPassword
}

function Disable-TervisBuiltInAdminAccount {
    #Requires -version 5.0

    Param(
        [Parameter(Mandatory)]$ComputerName
    )

    Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        
        Disable-LocalUser -Name Administrator

    }
}