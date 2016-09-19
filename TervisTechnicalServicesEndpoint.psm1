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

    Write-Verbose "Getting IP address..."

    $EndpointIPAddress = (Find-DHCPServerv4Lease -MACAddressWithDashes $MACAddressWithDashes).IPAddress.IPAddressToString

    Write-Verbose "IP address found: $EndpointIPAddress"

    Write-Verbose "Adding host to WSMan Trusted Hosts"

    Add-IPAddressToWSManTrustedHosts -IPAddress $EndpointIPAddress

    Write-Verbose "Getting credentials..."

    $Credentials = Get-Credential

    Write-Verbose "Installing Chocolatey..."

    Invoke-Command -ComputerName $EndpointIPAddress -Credential $Credentials -ScriptBlock {
        
        Set-ExecutionPolicy Bypass

        iwr https://chocolatey.org/install.ps1 -UseBasicParsing | iex
        
        refreshenv
        
        choco feature enable -n allowEmptyChecksums
    }

    if ($EndpointType.Name -eq "ContactCenterAgent") {

        Write-Verbose "Starting Contact Center Agent install."
       
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