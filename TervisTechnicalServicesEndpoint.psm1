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
        $MACAddressWithDashes
    )

    $EndpointType = Get-TervisEndpointType -Name $EndpointTypeName

    Write-Verbose "Getting IP address..."

    $EndpointIPAddress = (Find-DHCPServerv4Lease -MACAddressWithDashes $MACAddressWithDashes).IPAddress.IPAddressToString

    Write-Verbose "IP address found: $EndpointIPAddress"

    Write-Verbose "Adding host to WSMan Trusted Hosts"

    Add-IPAddressToWSManTrustedHosts -IPAddress $EndpointIPAddress

    Write-Verbose "Getting credentials..."

    # May need to change this to $LocalCredentials
    $Credentials = Get-Credential -Message "Enter local administrator credentials."

    # Insert function to add PC to domain here

    # Set-PrincipalsAllowedToDelegateToAccount -EndpointToAccessResource $ADEndpoint -Credentials $DomainCredentials

    # May need to change $Credentials to $DomainCredentials
    Install-TervisEndpointChocolatey -EndpointIPAddress $EndpointIPAddress -Credentials $Credentials -Verbose

    if ($EndpointType.Name -eq "ContactCenterAgent") {

        Write-Verbose "Starting Contact Center Agent install."
       
        New-TervisEndpointContactCenterAgent `
            -EndpointIPAddress $EndpointIPAddress `
            -Credential $Credentials `
            -InstallScript $EndpointType.InstallScript

    }
}

function Install-TervisEndpointChocolatey {
    [CmdletBinding()]
    param (
        $EndpointIPAddress,
        $Credentials    
    )

    Write-Verbose "Installing Chocolatey..."

    Invoke-Command -ComputerName $EndpointIPAddress -Credential $Credentials -ScriptBlock {
        
        Set-ExecutionPolicy Bypass

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

},
[PSCustomObject][Ordered] @{
    Name = "BartenderPrintStationKiosk"
    BaseName = "LabelPrint"
    
}

function New-TervisEndpointContactCenterAgent {
    param (
        $EndpointIPAddress,
        $Credentials,
        $InstallScript
    )

        Invoke-Command -ComputerName $EndpointIPAddress -Credential $Credentials -ScriptBlock $InstallScript
}

function Set-PrincipalsAllowedToDelegateToAccount {
    [CmdletBinding()]
    param (
        $EndpointToAccessResource,
        $Credentials = (Get-Credential)
    )

    $EndpointToAccessResourceObject = Get-ADComputer -Identity $EndpointToAccessResource

    Add-ADGroupMember -Identity Privilege_PrincipalsAllowedToDelegateToAccount -Members $EndpointToAccessResource

    Invoke-Command -ComputerName $EndpointToAccessResource -Credential $Credentials -ScriptBlock {            
        
        klist purge -li 0x3e7            
    
    }

}