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

function Copy-Windows10InstallFilesToUSBDrive {
    [CmdletBinding()]
    param (
        [parameter(Mandatory)]$USBDriveLetterWithColon
    )  

    Copy-Item -Path "\\fs1\DisasterRecovery\Programs\Microsoft\Windows 10 Enterprise USB Install\*" -Destination $USBDriveLetterWithColon -Force -Recurse    
    Copy-Item -Path "\\fs1\DisasterRecovery\Source Controlled Items\TervisWindows10\*" -Destination $USBDriveLetterWithColon -Force -Recurse

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