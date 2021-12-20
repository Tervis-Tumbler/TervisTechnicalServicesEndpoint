$EndpointTypes = [PSCustomObject][Ordered]@{
    Name = "ContactCenterAgent"
    InstallScript = {
        Install-FedExCustomerTools -ComputerName $ComputerName
    }
    DefaultOU = "OU=Computers,OU=Sales,OU=Departments,DC=tervis,DC=prv"
    ChocolateyPackageGroupNames = "StandardOfficeEndpoint","ContactCenter"
},[PSCustomObject][Ordered]@{
    Name = "BartenderPrintStationKiosk"
    BaseName = "LabelPrint"
    DefaultOU = "OU=BartenderPCs,OU=IndustryPCs,DC=tervis,DC=prv"
},
[PSCustomObject][Ordered]@{
    Name = "CafeKiosk"
    BaseName = "Cafe"
    DefaultOU = "OU=Cafe Kiosks,OU=Human Resources,OU=Departments,DC=tervis,DC=prv"
    InstallScript = {
        Write-Verbose "Starting Cafe Kiosk install"
        New-TervisEndpointCafeKiosk -EndpointName $ComputerName 
    }
},
[PSCustomObject][Ordered]@{
    Name = "StandardOfficeEndpoint"
    ChocolateyPackageGroupNames = "StandardOfficeEndpoint"
    DefaultOU = "OU=Sandbox,DC=tervis,DC=prv"
    InstallScript = {
        Install-TervisStandardEndpointLocalChocolateyPackages -ComputerName $ComputerName
    }
},
[PSCustomObject][Ordered]@{
    Name = "SharedOfficeEndpoint"
    ChocolateyPackageGroupNames = "SharedOfficeEndpoint"
    DefaultOU = "OU=Sandbox,DC=tervis,DC=prv"
},
[PSCustomObject][Ordered]@{
    Name = "ShipStation"
    BaseName = "Ship"
    DefaultOU = "OU=Computers,OU=Shipping Stations,OU=Operations,OU=Departments,DC=tervis,DC=prv"
    InstallScript = {
        Write-Verbose "Starting Expeditor install"
        Install-WCSScaleSupport -ComputerName $ComputerName
        Install-TervisBartenderDesigner -ComputerName $ComputerName -Version 10
    }
    ChocolateyPackageGroupNames = "ShipStation"
},
[PSCustomObject][Ordered]@{
    Name = "IT"
    ChocolateyPackageGroupNames = "StandardOfficeEndpoint","IT"
    DefaultOU = "OU=Computers,OU=Information Technology,OU=Departments,DC=tervis,DC=prv"
},
[PSCustomObject][Ordered]@{
    Name = "MESAuditor"
    BaseName = "MESAuditor"
    ChocolateyPackageGroupNames = "StandardOfficeEndpoint"
    DefaultOU = "OU=Computers,OU=MES Auditors,OU=Operations,OU=Departments,DC=tervis,DC=prv"
    InstallScript = {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {            
            Remove-LocalGroupMember -Group Users -Member "TERVIS\Domain Users"
            Add-LocalGroupMember -Group Users -Member Privilege_MESAuditorStationUsers
        }
    }
},
[PSCustomObject][Ordered]@{
    Name = "MESStation"
    DefaultOU = "OU=ProductionFloor,OU=IndustryPCs,DC=tervis,DC=prv"
    InstallScript = {
        Write-Verbose "Restarting for Autologon"
        Restart-Computer -Wait -Force -ComputerName $ComputerName
    }
},
[PSCustomObject][Ordered]@{
    Name = "FillRoomSurface"
    ChocolateyPackageGroupNames = "FillRoomSurface"
    DefaultOU = "OU=FillRoom,OU=IndustryPCs,DC=tervis,DC=prv"
    InstallScript = {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AutoRotation" -Name Enable -Value 0
        }
        Write-Verbose "Restarting for Autologon"
        Restart-Computer -Wait -Force -ComputerName $ComputerName
    }
},
[PSCustomObject][Ordered]@{
    Name = "SurfaceMES"
    ChocolateyPackageGroupNames = "SurfaceMES"
    DefaultOU = "OU=SurfaceMES,OU=IndustryPCs,DC=tervis,DC=prv"
    InstallScript = {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AutoRotation" -Name Enable -Value 0
        }        
        Set-TervisEndpointPowerPlan -ComputerName $ComputerName -NoSleepOnBattery -MaximumBrightness
        Set-TervisAutoHotKeyF2PrintScript -ComputerName $ComputerName
        Set-TervisSurfaceMESKioskMode -ComputerName $ComputerName
        Write-Verbose "Restarting for Autologon"
        Restart-Computer -Wait -Force -ComputerName $ComputerName
    }
},
[PSCustomObject][Ordered]@{
    Name = "IQ2Welder"
    ChocolateyPackageGroupNames = "IQ2Welder"
    DefaultOU = "OU=IQ Explorer II,OU=Welder Stations,OU=Engineering,OU=Departments,DC=tervis,DC=prv"
    InstallScript = {
        Enable-TouchKeyboardOnWindows10Endpoint -ComputerName $ComputerName
        New-iQExplorerIIOptionsFile -ComputerName $ComputerName
        Write-Verbose "Restarting for Autologon"
        Restart-Computer -Wait -Force -ComputerName $ComputerName
        Install-DotNet35OnEndpoint -ComputerName $ComputerName
        Write-Warning "Weld tech will install desired iQ II version"
    }
},
[PSCustomObject][Ordered]@{
    Name = "StoresRegister"
    ChocolateyPackageGroupNames = "StoresRegister"
    DefaultOU = "OU=StoreRegisters_Win10,OU=IndustryPCs,DC=tervis,DC=prv"
    InstallScript = {
    }
},
[PSCustomObject][Ordered]@{
    Name = "StoresBackOffice"
    ChocolateyPackageGroupNames = "StoresBackOffice"
    DefaultOU = "OU=Back Office Computers,OU=Remote Store Computers,OU=Computers,OU=Stores,OU=Departments,DC=tervis,DC=prv"
    InstallScript = {
    }
},
[PSCustomObject][Ordered]@{
    Name = "HamTest"
    ChocolateyPackageGroupNames = ""
    DefaultOU = "OU=HamTest,OU=Test,DC=tervis,DC=prv"
    InstallScript = {
    }
},
[PSCustomObject][Ordered]@{
    Name = "DomainJoin"
    ChocolateyPackageGroupNames = ""
    DefaultOU = "OU=Sandbox,DC=tervis,DC=prv"
}