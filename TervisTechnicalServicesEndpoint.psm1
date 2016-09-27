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
    [CmdletBinding()]
    param (
        $EndpointTypeName,
        $MACAddressWithDashes,
        $NewComputerName
    )

    $EndpointType = Get-TervisEndpointType -Name $EndpointTypeName

    Write-Verbose "Getting IP address..."

    $EndpointIPAddress = (Find-DHCPServerv4Lease -MACAddressWithDashes $MACAddressWithDashes).IPAddress.IPAddressToString

    Write-Verbose "IP address found: $EndpointIPAddress"

    Write-Verbose "Adding host to WSMan Trusted Hosts..."

    Add-IPAddressToWSManTrustedHosts -IPAddress $EndpointIPAddress

    Write-Verbose "Getting local admin credentials..."

    $LocalAdministratorCredential = Get-Credential -Message "Enter local administrator credentials."

    Write-Verbose "Getting domain admin credentials..."

    $DomainAdministratorCredential = Get-Credential -Message "Enter domain administrator credentials."

    Write-Verbose "Adding endpoint to domain..."
    
    Set-TervisEndpointNameAndDomain -OUPath $EndpointType.DefaultOU -NewComputerName $NewComputerName -EndpointIPAddress $EndpointIPAddress -LocalAdministratorCredential $LocalAdministratorCredential -DomainAdministratorCredential $DomainAdministratorCredential

    Write-Verbose "Forcing a sync between domain controllers..."
    $DC = Get-ADDomainController | Select -ExpandProperty HostName
    Invoke-Command -ComputerName $DC -ScriptBlock {repadmin /syncall}
    Start-Sleep 30 
    
    Write-Verbose "Setting Resource-Based Kerberos Constrained Delegation..."

    Set-PrincipalsAllowedToDelegateToAccount -EndpointToAccessResource $NewComputerName -Credentials $DomainAdministratorCredential

    Write-Verbose "Installing Chocolatey..."

    Install-TervisEndpointChocolatey -EndpointName $NewComputerName -Credentials $DomainAdministratorCredential

    if ($EndpointType.Name -eq "ContactCenterAgent") {        
        
        Write-Verbose "Starting Contact Center Agent install..."
        
        New-TervisEndpointContactCenterAgent -EndpointName $NewComputerName -Credential $DomainAdministratorCredential -InstallScript $EndpointType.InstallScript        
    
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

        #choco install CiscoJabber -y

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
}

function New-TervisEndpointContactCenterAgent {
    param (
        $EndpointName,
        $Credentials,
        $InstallScript
    )

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
    param (
        [Parameter(Mandatory)]$NewComputerName,
        [Parameter(Mandatory)]$EndpointIPAddress,
        [Parameter(Mandatory)]$OUPath,
        [Parameter(Mandatory)]$LocalAdministratorCredential,
        [Parameter(Mandatory)]$DomainAdministratorCredential,
        $DomainName = 'tervis.prv',
        $TimeToWaitForGroupPolicy = '180'
    )

    Invoke-Command -ComputerName $EndpointIPAddress -Credential $LocalAdministratorCredential -ScriptBlock {
        param($NewComputerName,$DomainName,$OUPath,$DomainAdministratorCredential)
        Add-Computer -NewName $NewComputerName -DomainName $DomainName -Force -Restart -OUPath $OUPath -Credential $DomainAdministratorCredential

        } -ArgumentList $NewComputerName,$DomainName,$OUPath,$DomainAdministratorCredential

    Wait-ForEndpointRestart -IPAddress $EndpointIPAddress -PortNumbertoMonitor 5985
    
    Write-Verbose 'Waiting for Group Policy to complete.'

    Start-Sleep -Seconds $TimeToWaitForGroupPolicy

}

function Wait-ForEndpointRestart{
    #Requires -Modules TervisTechnicalServicesLinux
    Param(
        [Parameter(Mandatory)]$IPAddress,
        [Parameter(Mandatory)]$PortNumbertoMonitor
    )
    Write-Verbose "Waiting for endpoint to reboot..."

    Wait-ForPortNotAvailable -IPAddress $IPAddress -PortNumbertoMonitor $PortNumbertoMonitor -WarningAction Ignore
    
    Write-Verbose "Waiting for endpoint to startup..."
    
    Wait-ForPortAvailable -IPAddress $IPAddress -PortNumbertoMonitor $PortNumbertoMonitor -WarningAction Ignore

    Write-Verbose "Endpoint is up and running..."

}