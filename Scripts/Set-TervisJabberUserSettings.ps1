$JabberConfigFilePath = "$env:APPDATA\Cisco\Unified Communications\Jabber\CSF\Config\jabberLocalConfig.xml"
if (Test-Path -Path $JabberConfigFilePath) {
    [xml]$ConfigXML = Get-Content -Path $JabberConfigFilePath
    $CalenderIntegrationConfiguration = $ConfigXML.SelectSingleNode("//userConfig[@name='calendarintegrationtype']")
    if ($CalenderIntegrationConfiguration) {
        Write-Host "CalendarIntegration exists. Setting to 'none'."
        $CalenderIntegrationConfiguration.Value = "0"
    } else {
        Write-Host "CalendarIntegration not set. Setting to 'none'."
        $ChildElement = $ConfigXML.CreateElement("userConfig")
        $ChildElement.SetAttribute("name","calendarintegrationtype")
        $ChildElement.SetAttribute("value","0")
        $ConfigXML.Jabber.AppendChild($ChildElement)
    }
    $ConfigXML.Save($JabberConfigFilePath)

    [xml]$ConfigXMLCheck = Get-Content -Path $JabberConfigFilePath
    if (($ConfigXML.SelectSingleNode("//userConfig[@name='calendarintegrationtype']")).Value -eq "0") {
        Write-Host "CalendarIntegration successfully set to 'none'. Self-destructing."
        Remove-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -Name Set-TervisJabberUserSettings -Force
        Remove-Item -Path $PSScriptRoot\Set-TervisJabberUserSettings.ps1
    }
} else {
    Write-Host "No Jabber configuration file found."
}
