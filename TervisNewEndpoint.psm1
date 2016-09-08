function Add-IPAddressToTrustedHosts {
    param (
    [string][parameter(Mandatory, ValueFromPipeline)]$IPAddress
    )

    Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value $IPAddress -Force
}

