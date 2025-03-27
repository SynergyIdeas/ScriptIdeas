function Get-WEMPolicyTemplates {
    param (
        [Parameter(Mandatory=$true)]
        [string]$WEMInfraServer
    )
    
    try {
        # Connect to WEM
        Write-Host "Connecting to Citrix WEM Infrastructure Server: $WEMInfraServer..."
        $WEMConnection = Connect-WEM -Server $WEMInfraServer
        
        # Get WEM Group Policy Templates
        Write-Host "Retrieving WEM Group Policy Templates from $WEMInfraServer..."
        $policyTemplates = Get-WEMGroupPolicyTemplate
        
        # Format the results as a list of policy objects
        $policies = @()
        foreach ($template in $policyTemplates) {
            $policy = @{
                'id' = $template.Id
                'name' = $template.Name
                'description' = $template.Description
            }
            $policies += $policy
        }
        
        return $policies
    }
    catch {
        Write-Error "Failed to get WEM policy templates: $_"
        return $null
    }
    finally {
        # Disconnect from WEM
        if ($WEMConnection) {
            Disconnect-WEM
        }
    }
}# Export-CompareWEMGPO.ps1
# Script to export Citrix WEM policy to XML and compare with AD GPO backup XML

# Required modules
#Requires -Modules Citrix.WEM.SDK, GroupPolicy

function Get-ADGroupPolicies {
    param (
        [Parameter(Mandatory=$false)]
        [string]$Domain = $null
    )
    
    try {
        # Use current domain if none specified
        if (-not $Domain) {
            $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
        }
        
        Write-Host "Retrieving Group Policies from domain: $Domain..."
        $gpos = Get-GPO -All -Domain $Domain | Sort-Object DisplayName
        
        # Format the results as a list of policy objects
        $policies = @()
        foreach ($gpo in $gpos) {
            $policy = @{
                'id' = $gpo.Id.ToString()
                'name' = $gpo.DisplayName
                'description' = $gpo.Description
                'creationTime' = $gpo.CreationTime.ToString()
                'modificationTime' = $gpo.ModificationTime.ToString()
            }
            $policies += $policy
        }
        
        return $policies
    }
    catch {
        Write-Error "Failed to get AD Group Policies: $_"
        return $null
    }
}

function Export-ADGPOToXML {
    param (
        [Parameter(Mandatory=$true)]
        [string]$GPOId,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory=$false)]
        [string]$Domain = $null
    )
    
    try {
        # Use current domain if none specified
        if (-not $Domain) {
            $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
        }
        
        # Get the GPO
        Write-Host "Retrieving Group Policy with ID: $GPOId from domain: $Domain..."
        $gpo = Get-GPO -Guid $GPOId -Domain $Domain
        
        if (-not $gpo) {
            throw "Group Policy with ID $GPOId not found."
        }
        
        # Create temporary directory for backup
        $tempDir = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), [System.Guid]::NewGuid().ToString())
        New-Item -Path $tempDir -ItemType Directory -Force | Out-Null
        
        # Backup the GPO
        Write-Host "Backing up Group Policy: $($gpo.DisplayName)..."
        $backupId = Backup-GPO -Guid $GPOId -Domain $Domain -Path $tempDir
        
        # Find the backup folder
        $backupFolder = Join-Path -Path $tempDir -ChildPath "{$backupId}"
        
        # The bkupInfo.xml file contains metadata about the backup
        $bkupInfoPath = Join-Path -Path $backupFolder -ChildPath "bkupInfo.xml"
        
        # The XML file we're interested in is in the backup folder
        $gpoXmlPath = Join-Path -Path $backupFolder -ChildPath "gpreport.xml"
        
        if (-not (Test-Path $gpoXmlPath)) {
            throw "GPO XML file not found in backup folder."
        }
        
        # Copy to output location - use Force to overwrite if file exists
        Copy-Item -Path $gpoXmlPath -Destination $OutputPath -Force
        
        # Clean up temporary directory
        Remove-Item -Path $tempDir -Recurse -Force
        
        Write-Host "GPO exported to $OutputPath (overwritten if exists)"
        return $OutputPath
    }
    catch {
        Write-Error "Failed to export GPO: $_"
        return $null
    }
}

function Export-WEMPolicyToXML {
    param (
        [Parameter(Mandatory=$true)]
        [string]$WEMInfraServer,
        
        [Parameter(Mandatory=$true)]
        [string]$PolicyTemplateId,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputPath
    )
    
    try {
        # Connect to WEM
        Write-Host "Connecting to Citrix WEM Infrastructure Server: $WEMInfraServer..."
        $WEMConnection = Connect-WEM -Server $WEMInfraServer
        
        # Get WEM Group Policy Template
        Write-Host "Retrieving WEM Group Policy Template with ID: $PolicyTemplateId from $WEMInfraServer..."
        $policyTemplate = Get-WEMGroupPolicyTemplate -Id $PolicyTemplateId
        
        if (-not $policyTemplate) {
            throw "Group Policy Template with ID $PolicyTemplateId not found."
        }
        
        # Get registry settings from the policy template
        Write-Host "Getting registry settings from policy template: $($policyTemplate.Name)..."
        $registrySettings = Get-WEMGroupPolicyRegistryValue -TemplateId $PolicyTemplateId
        
        if (-not $registrySettings -or $registrySettings.Count -eq 0) {
            Write-Warning "No registry settings found in the policy template."
        }
        
        # Create XML structure
        $xmlSettings = @{
            'WEMPolicy' = @{
                'InfrastructureServer' = $WEMInfraServer
                'PolicyTemplate' = @{
                    'Id' = $policyTemplate.Id
                    'Name' = $policyTemplate.Name
                    'Description' = $policyTemplate.Description
                }
                'Settings' = @()
            }
        }
        
        # Convert registry settings to XML-friendly format
        foreach ($setting in $registrySettings) {
            $settingInfo = @{
                'Name' = $setting.Name
                'Value' = $setting.Value
                'Type' = $setting.Type
                'Path' = $setting.Path
            }
            
            $xmlSettings.WEMPolicy.Settings += $settingInfo
        }
        
        # Convert to XML and export
        $xmlContent = $xmlSettings | ConvertTo-Xml -Depth 5 -NoTypeInformation
        $xmlContent.Save($OutputPath)
        
        Write-Host "WEM policy exported to $OutputPath (overwritten if exists)"
        return $OutputPath
    }
    catch {
        Write-Error "Failed to export WEM policy: $_"
        return $null
    }
    finally {
        # Disconnect from WEM
        if ($WEMConnection) {
            Disconnect-WEM
        }
    }
}

function Compare-WEMWithGPO {
    param (
        [Parameter(Mandatory=$true)]
        [string]$WEMXmlPath,
        
        [Parameter(Mandatory=$true)]
        [string]$GPOXmlPath,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputXmlPath
    )
    
    try {
        # Load WEM XML
        Write-Host "Loading WEM XML from $WEMXmlPath..."
        [xml]$wemXml = Get-Content -Path $WEMXmlPath
        
        # Load GPO XML
        Write-Host "Loading GPO XML from $GPOXmlPath..."
        [xml]$gpoXml = Get-Content -Path $GPOXmlPath
        
        # Extract WEM registry settings
        $wemSettings = @{}
        foreach ($setting in $wemXml.Objects.Object.Property) {
            if ($setting.Name -eq "Settings") {
                foreach ($regSetting in $setting.Property) {
                    $name = $regSetting.Property | Where-Object { $_.Name -eq "Name" } | Select-Object -ExpandProperty "#text"
                    $value = $regSetting.Property | Where-Object { $_.Name -eq "Value" } | Select-Object -ExpandProperty "#text"
                    $path = $regSetting.Property | Where-Object { $_.Name -eq "Path" } | Select-Object -ExpandProperty "#text"
                    
                    # Only include the value part, not the HKLM/HKCU keys
                    $pathParts = $path -split '\\'
                    $valuePath = $pathParts[2..($pathParts.Length-1)] -join '\'
                    
                    $key = "$valuePath\$name"
                    $wemSettings[$key] = $value
                }
            }
        }
        
        # Extract GPO registry settings
        $gpoSettings = @{}
        $registrySettings = $gpoXml.GPO.Computer.ExtensionData.Extension.Policy
        
        foreach ($policy in $registrySettings) {
            if ($policy.Name -eq "Registry") {
                foreach ($regSetting in $policy.Registry) {
                    $name = $regSetting.Name
                    $value = $regSetting.Value
                    $keyPath = $regSetting.KeyPath
                    
                    # Remove HKLM/HKCU prefix
                    if ($keyPath -match "HKLM\\(.+)") {
                        $keyPath = $matches[1]
                    }
                    elseif ($keyPath -match "HKCU\\(.+)") {
                        $keyPath = $matches[1]
                    }
                    
                    $key = "$keyPath\$name"
                    $gpoSettings[$key] = $value
                }
            }
        }
        
        # Compare settings
        $differences = @{
            'OnlyInWEM' = @{}
            'OnlyInGPO' = @{}
            'DifferentValues' = @{}
            'Identical' = @{}
        }
        
        # Check WEM settings against GPO
        foreach ($key in $wemSettings.Keys) {
            if ($gpoSettings.ContainsKey($key)) {
                if ($wemSettings[$key] -eq $gpoSettings[$key]) {
                    $differences.Identical[$key] = $wemSettings[$key]
                }
                else {
                    $differences.DifferentValues[$key] = @{
                        'WEM' = $wemSettings[$key]
                        'GPO' = $gpoSettings[$key]
                    }
                }
            }
            else {
                $differences.OnlyInWEM[$key] = $wemSettings[$key]
            }
        }
        
        # Check for GPO settings not in WEM
        foreach ($key in $gpoSettings.Keys) {
            if (-not $wemSettings.ContainsKey($key)) {
                $differences.OnlyInGPO[$key] = $gpoSettings[$key]
            }
        }
        
        # Convert to XML and export
        $xmlDoc = New-Object System.Xml.XmlDocument
        $xmlDeclaration = $xmlDoc.CreateXmlDeclaration("1.0", "UTF-8", $null)
        $xmlDoc.AppendChild($xmlDeclaration) | Out-Null
        
        # Create root element
        $rootElement = $xmlDoc.CreateElement("ComparisonResults")
        $xmlDoc.AppendChild($rootElement) | Out-Null
        
        # Create sections for each category
        $categorySections = @("OnlyInWEM", "OnlyInGPO", "DifferentValues", "Identical")
        foreach ($category in $categorySections) {
            $categoryElement = $xmlDoc.CreateElement($category)
            $rootElement.AppendChild($categoryElement) | Out-Null
            
            if ($category -eq "DifferentValues") {
                foreach ($key in $differences.$category.Keys) {
                    $settingElement = $xmlDoc.CreateElement("Setting")
                    $categoryElement.AppendChild($settingElement) | Out-Null
                    
                    $keyElement = $xmlDoc.CreateElement("Key")
                    $keyElement.InnerText = $key
                    $settingElement.AppendChild($keyElement) | Out-Null
                    
                    $wemValueElement = $xmlDoc.CreateElement("WEMValue")
                    $wemValueElement.InnerText = $differences.$category[$key].WEM
                    $settingElement.AppendChild($wemValueElement) | Out-Null
                    
                    $gpoValueElement = $xmlDoc.CreateElement("GPOValue")
                    $gpoValueElement.InnerText = $differences.$category[$key].GPO
                    $settingElement.AppendChild($gpoValueElement) | Out-Null
                }
            } else {
                foreach ($key in $differences.$category.Keys) {
                    $settingElement = $xmlDoc.CreateElement("Setting")
                    $categoryElement.AppendChild($settingElement) | Out-Null
                    
                    $keyElement = $xmlDoc.CreateElement("Key")
                    $keyElement.InnerText = $key
                    $settingElement.AppendChild($keyElement) | Out-Null
                    
                    $valueElement = $xmlDoc.CreateElement("Value")
                    $valueElement.InnerText = $differences.$category[$key]
                    $settingElement.AppendChild($valueElement) | Out-Null
                }
            }
        }
        
        # Add summary section
        $summaryElement = $xmlDoc.CreateElement("Summary")
        $rootElement.AppendChild($summaryElement) | Out-Null
        
        $totalOnlyInWEM = $xmlDoc.CreateElement("TotalOnlyInWEM")
        $totalOnlyInWEM.InnerText = $differences.OnlyInWEM.Count
        $summaryElement.AppendChild($totalOnlyInWEM) | Out-Null
        
        $totalOnlyInGPO = $xmlDoc.CreateElement("TotalOnlyInGPO")
        $totalOnlyInGPO.InnerText = $differences.OnlyInGPO.Count
        $summaryElement.AppendChild($totalOnlyInGPO) | Out-Null
        
        $totalDifferent = $xmlDoc.CreateElement("TotalDifferent")
        $totalDifferent.InnerText = $differences.DifferentValues.Count
        $summaryElement.AppendChild($totalDifferent) | Out-Null
        
        $totalIdentical = $xmlDoc.CreateElement("TotalIdentical")
        $totalIdentical.InnerText = $differences.Identical.Count
        $summaryElement.AppendChild($totalIdentical) | Out-Null
        
        # Save the XML document (will overwrite if file exists)
        $xmlDoc.Save($OutputXmlPath)
        
        Write-Host "Comparison results saved to $OutputXmlPath (overwritten if exists)"
        return $OutputXmlPath
    }
    catch {
        Write-Error "Failed to compare WEM with GPO: $_"
        return $null
    }
}

# Export the functions so they can be called from the UI
Export-ModuleMember -Function Export-WEMPolicyToXML, Compare-WEMWithGPO, Get-WEMPolicyTemplates, Get-ADGroupPolicies, Export-ADGPOToXML
