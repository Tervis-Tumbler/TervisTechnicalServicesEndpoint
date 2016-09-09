function Add-IPAddressToWSManTrustedHosts {
    [CmdletBinding()]
    param(
        [parameter(Mandatory, ValueFromPipeline)]$IPAddress
    )

    Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value $IPAddress -Force
}

function Get-WSManTrustedHosts {

    Get-Item -Path WSMan:\localhost\Client\TrustedHosts

}

function Enter-PSSessionToNewEndpoint {
    [CmdletBinding()]
    param(
        [parameter(Mandatory, ValueFromPipeline)]$IPAddress
    )    
    $Credentials = Get-Credential

    Enter-PSSession -ComputerName $IPAddress -Credential $Credentials
}

function Copy-Windows10InstallFilesToUSBDrive {
    [CmdletBinding()]
    param(
        [parameter(Mandatory)]$USBDriveLetterWithColon
    )  

    Copy-Item -Path "\\fs1\DisasterRecovery\Programs\Microsoft\Windows 10 Enterprise USB Install\*" -Destination $USBDriveLetterWithColon -Force -Recurse    
    Copy-Item -Path "\\fs1\DisasterRecovery\Source Controlled Items\TervisWindows10\*" -Destination $USBDriveLetterWithColon -Force -Recurse

}