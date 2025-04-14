#Requires -Version 3.0
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Exports Citrix Provisioning Services (PVS) configuration to XML files.

.DESCRIPTION
    This script exports PVS configuration components to XML files, organized by site.
    Each component (farms, sites, stores, collections, devices, etc.) is exported to its own XML file.
    The script includes detailed logging to track the export process.

.PARAMETER OutputPath
    The path where the exported XML files will be saved. Default is the current directory.

.PARAMETER LogPath
    The path where the log file will be saved. Default is the current directory.

.EXAMPLE
    .\Export-PVSConfiguration.ps1 -OutputPath "C:\PVSExport" -LogPath "C:\PVSExport\Logs"

.NOTES
    Author: Claude
    Version: 1.0
    Date: April 14, 2025
    Requires: Citrix PVS PowerShell SDK
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = (Get-Location).Path,
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = (Get-Location).Path
)

#region Functions

function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Info',
        
        [Parameter(Mandatory=$false)]
        [string]$LogFile = $script:LogFilePath
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        'Info'    { Write-Host $logEntry -ForegroundColor Cyan }
        'Warning' { Write-Host $logEntry -ForegroundColor Yellow }
        'Error'   { Write-Host $logEntry -ForegroundColor Red }
        'Success' { Write-Host $logEntry -ForegroundColor Green }
    }
    
    Add-Content -Path $LogFile -Value $logEntry
}

function Test-PVSModule {
    try {
        # Check if Citrix.PVS.SnapIn module is available
        if (Get-Module -Name Citrix.PVS.SnapIn -ListAvailable) {
            Import-Module Citrix.PVS.SnapIn
            Write-Log -Message "PVS PowerShell module found and imported successfully." -Level Success
            return $true
        }
        # Try to load the PVS snap-in (legacy approach)
        elseif (Get-PSSnapin -Name Citrix.PVS.SnapIn -Registered -ErrorAction SilentlyContinue) {
            Add-PSSnapin Citrix.PVS.SnapIn
            Write-Log -Message "PVS PowerShell snap-in found and added successfully." -Level Success
            return $true
        }
        else {
            Write-Log -Message "Cannot find PVS PowerShell module or snap-in. Please make sure PVS Console is installed." -Level Error
            return $false
        }
    }
    catch {
        Write-Log -Message "Error loading PVS PowerShell module/snap-in: $_" -Level Error
        return $false
    }
}

function Export-PVSFarm {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$OutputFolder
    )
    
    try {
        Write-Log -Message "Exporting Farm configuration..."
        $farmData = Get-PvsFarm
        if ($farmData) {
            $farmData | Export-Clixml -Path "$OutputFolder\Farm.xml" -Force
            Write-Log -Message "Farm configuration exported successfully to: $OutputFolder\Farm.xml" -Level Success
        }
        else {
            Write-Log -Message "No Farm configuration found to export." -Level Warning
        }
    }
    catch {
        Write-Log -Message "Error exporting Farm configuration: $_" -Level Error
    }
}

function Export-PVSSites {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$OutputFolder
    )
    
    try {
        Write-Log -Message "Exporting Sites configuration..."
        $sites = Get-PvsSite
        if ($sites) {
            $sites | Export-Clixml -Path "$OutputFolder\Sites.xml" -Force
            Write-Log -Message "Sites configuration exported successfully to: $OutputFolder\Sites.xml" -Level Success
            return $sites
        }
        else {
            Write-Log -Message "No Sites found to export." -Level Warning
            return $null
        }
    }
    catch {
        Write-Log -Message "Error exporting Sites configuration: $_" -Level Error
        return $null
    }
}

function Export-PVSStores {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$OutputFolder,
        
        [Parameter(Mandatory=$true)]
        [string]$SiteName
    )
    
    try {
        Write-Log -Message "Exporting Stores configuration for site '$SiteName'..."
        $stores = Get-PvsStore -SiteName $SiteName
        if ($stores) {
            $stores | Export-Clixml -Path "$OutputFolder\Stores.xml" -Force
            Write-Log -Message "Stores configuration exported successfully to: $OutputFolder\Stores.xml" -Level Success
        }
        else {
            Write-Log -Message "No Stores found to export for site '$SiteName'." -Level Warning
        }
    }
    catch {
        Write-Log -Message "Error exporting Stores configuration for site '$SiteName': $_" -Level Error
    }
}

function Export-PVSCollections {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$OutputFolder,
        
        [Parameter(Mandatory=$true)]
        [string]$SiteName
    )
    
    try {
        Write-Log -Message "Exporting Collections configuration for site '$SiteName'..."
        $collections = Get-PvsCollection -SiteName $SiteName
        if ($collections) {
            $collections | Export-Clixml -Path "$OutputFolder\Collections.xml" -Force
            Write-Log -Message "Collections configuration exported successfully to: $OutputFolder\Collections.xml" -Level Success
            return $collections
        }
        else {
            Write-Log -Message "No Collections found to export for site '$SiteName'." -Level Warning
            return $null
        }
    }
    catch {
        Write-Log -Message "Error exporting Collections configuration for site '$SiteName': $_" -Level Error
        return $null
    }
}

function Export-PVSDevices {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$OutputFolder,
        
        [Parameter(Mandatory=$true)]
        [string]$SiteName,
        
        [Parameter(Mandatory=$false)]
        [object]$Collections
    )
    
    try {
        Write-Log -Message "Exporting Devices configuration for site '$SiteName'..."
        
        if ($Collections) {
            # Export devices by collection
            foreach ($collection in $Collections) {
                $collectionName = $collection.Name
                Write-Log -Message "Exporting devices for collection '$collectionName'..."
                
                $collectionFolder = "$OutputFolder\Collections\$collectionName"
                if (-not (Test-Path $collectionFolder)) {
                    New-Item -Path $collectionFolder -ItemType Directory -Force | Out-Null
                }
                
                $devices = Get-PvsDevice -CollectionName $collectionName -SiteName $SiteName
                if ($devices) {
                    $devices | Export-Clixml -Path "$collectionFolder\Devices.xml" -Force
                    Write-Log -Message "Devices for collection '$collectionName' exported successfully." -Level Success
                }
                else {
                    Write-Log -Message "No devices found in collection '$collectionName'." -Level Warning
                }
            }
        }
        else {
            # Export all devices for the site
            $devices = Get-PvsDevice -SiteName $SiteName
            if ($devices) {
                $devices | Export-Clixml -Path "$OutputFolder\Devices.xml" -Force
                Write-Log -Message "All devices for site '$SiteName' exported successfully to: $OutputFolder\Devices.xml" -Level Success
            }
            else {
                Write-Log -Message "No devices found in site '$SiteName'." -Level Warning
            }
        }
    }
    catch {
        Write-Log -Message "Error exporting Devices configuration for site '$SiteName': $_" -Level Error
    }
}

function Export-PVSvDisks {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$OutputFolder,
        
        [Parameter(Mandatory=$true)]
        [string]$SiteName,
        
        [Parameter(Mandatory=$false)]
        [object]$Stores
    )
    
    try {
        Write-Log -Message "Exporting vDisks configuration for site '$SiteName'..."
        
        $vDisks = Get-PvsDiskInfo -SiteName $SiteName
        if ($vDisks) {
            $vDisks | Export-Clixml -Path "$OutputFolder\vDisks.xml" -Force
            Write-Log -Message "vDisks configuration exported successfully to: $OutputFolder\vDisks.xml" -Level Success
        }
        else {
            Write-Log -Message "No vDisks found to export for site '$SiteName'." -Level Warning
        }
        
        # Export vDisk versions
        $allvDisks = Get-PvsDisk -SiteName $SiteName
        if ($allvDisks) {
            $allvDisks | Export-Clixml -Path "$OutputFolder\vDiskDetails.xml" -Force
            Write-Log -Message "vDisk version details exported successfully to: $OutputFolder\vDiskDetails.xml" -Level Success
        }
    }
    catch {
        Write-Log -Message "Error exporting vDisks configuration for site '$SiteName': $_" -Level Error
    }
}

function Export-PVSServers {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$OutputFolder,
        
        [Parameter(Mandatory=$true)]
        [string]$SiteName
    )
    
    try {
        Write-Log -Message "Exporting Servers configuration for site '$SiteName'..."
        $servers = Get-PvsServer -SiteName $SiteName
        if ($servers) {
            $servers | Export-Clixml -Path "$OutputFolder\Servers.xml" -Force
            Write-Log -Message "Servers configuration exported successfully to: $OutputFolder\Servers.xml" -Level Success
        }
        else {
            Write-Log -Message "No Servers found to export for site '$SiteName'." -Level Warning
        }
    }
    catch {
        Write-Log -Message "Error exporting Servers configuration for site '$SiteName': $_" -Level Error
    }
}

function Export-PVSFarmViews {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$OutputFolder
    )
    
    try {
        # We are explicitly skipping this as per requirements
        Write-Log -Message "Skipping Farm Views export as per requirements." -Level Info
    }
    catch {
        Write-Log -Message "Error in Farm Views export function: $_" -Level Error
    }
}

function Export-PVSAuthGroups {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$OutputFolder,
        
        [Parameter(Mandatory=$true)]
        [string]$SiteName
    )
    
    try {
        Write-Log -Message "Exporting Auth Groups configuration for site '$SiteName'..."
        $authGroups = Get-PvsAuthGroup -SiteName $SiteName
        if ($authGroups) {
            $authGroups | Export-Clixml -Path "$OutputFolder\AuthGroups.xml" -Force
            Write-Log -Message "Auth Groups configuration exported successfully to: $OutputFolder\AuthGroups.xml" -Level Success
        }
        else {
            Write-Log -Message "No Auth Groups found to export for site '$SiteName'." -Level Warning
        }
    }
    catch {
        Write-Log -Message "Error exporting Auth Groups configuration for site '$SiteName': $_" -Level Error
    }
}

#endregion

#region Script Execution

# Setup logging
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$script:LogFilePath = Join-Path $LogPath "PVSExport_$timestamp.log"

# Create log and export directories if they don't exist
if (-not (Test-Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
}
if (-not (Test-Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

# Start logging
Write-Log -Message "===== PVS Configuration Export Started =====" -Level Info
Write-Log -Message "Export path: $OutputPath" -Level Info
Write-Log -Message "Log path: $LogPath" -Level Info

# Check for PVS module
if (-not (Test-PVSModule)) {
    Write-Log -Message "Required PVS PowerShell module not found. Exiting script." -Level Error
    return
}

# Create main export folder with timestamp
$mainExportFolder = Join-Path $OutputPath "PVSExport_$timestamp"
New-Item -Path $mainExportFolder -ItemType Directory -Force | Out-Null
Write-Log -Message "Created main export folder: $mainExportFolder" -Level Info

# Export Farm configuration
Export-PVSFarm -OutputFolder $mainExportFolder

# Export sites
$sites = Export-PVSSites -OutputFolder $mainExportFolder

if ($sites) {
    foreach ($site in $sites) {
        $siteName = $site.SiteName
        Write-Log -Message "Processing site: $siteName" -Level Info
        
        # Create site-specific folder
        $siteFolder = Join-Path $mainExportFolder $siteName
        New-Item -Path $siteFolder -ItemType Directory -Force | Out-Null
        
        # Export site components
        $stores = Get-PvsStore -SiteName $siteName
        Export-PVSStores -OutputFolder $siteFolder -SiteName $siteName
        $collections = Export-PVSCollections -OutputFolder $siteFolder -SiteName $siteName
        Export-PVSDevices -OutputFolder $siteFolder -SiteName $siteName -Collections $collections
        Export-PVSvDisks -OutputFolder $siteFolder -SiteName $siteName -Stores $stores
        Export-PVSServers -OutputFolder $siteFolder -SiteName $siteName
        Export-PVSAuthGroups -OutputFolder $siteFolder -SiteName $siteName
    }
}

Write-Log -Message "===== PVS Configuration Export Completed =====" -Level Success
Write-Log -Message "Export location: $mainExportFolder" -Level Success

#endregion
