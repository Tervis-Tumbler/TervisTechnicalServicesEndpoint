$JabberConfigFilePath = "$env:APPDATA\Cisco\Unified Communications\Jabber\CSF\Config\jabberLocalConfig.xml"
if (Test-Path -Path $JabberConfigFilePath) {
    [xml]$ConfigXML = Get-Content -Path $JabberConfigFilePath
    $CalenderIntegrationConfiguration = $ConfigXML.SelectSingleNode("//userConfig[@name='calendarintegrationtype']")
    $CalenderIntegrationConfiguration.Value = "0"
    $ConfigXML.Save($JabberConfigFilePath)    
}