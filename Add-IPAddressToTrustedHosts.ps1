function Add-IPAddressToTrustedHosts {
    param (
    [string]$IPAddress
    )

    Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value $IPAddress -Force
}

