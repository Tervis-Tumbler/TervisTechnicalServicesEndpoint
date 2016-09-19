function Add-IPAddressToWSManTrustedHosts {
    [CmdletBinding()]
    param (
        [parameter(Mandatory, ValueFromPipeline)]$IPAddress
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

    $EndpointIPAddress = (Find-DHCPServerv4Lease -MACAddressWithDashes $MACAddressWithDashes).IPAddress

    Add-IPAddressToWSManTrustedHosts -IPAddress $EndpointIPAddress

    $Credentials = Get-Credential

    if ($EndpointType.Name -eq "ContactCenterAgent") {
       
        New-TervisEndpointContactCenterAgent -EndpointIPAddress $EndpointIPAddress -Credential $Credentials -InstallScript $EndpointType.InstallScript

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
        
        iwr https://chocolatey.org/install.ps1 | iex
        
        refreshenv
        
        choco feature enable -n allowEmptyChecksums

        Install-TervisChocolateyPackageInstall -PackageName CiscoJabber

        Install-TervisChocolateyPackageInstall -PackageName CiscoAgentDesktop

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