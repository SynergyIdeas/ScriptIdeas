# Citrix PVS Export Script
# This script exports PVS configuration to XML files with detailed logging
# Each configuration area is exported separately and each site has its own configuration files

# Set error action preference
$ErrorActionPreference = "Stop"

# Function to write log messages
function Write-Log {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [Parameter(Mandatory = $false)]
        [ValidateSet("INFO", "WARNING", "ERROR")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Output to console
    switch ($Level) {
        "INFO" { Write-Host $logMessage -ForegroundColor Green }
        "WARNING" { Write-Host $logMessage -ForegroundColor Yellow }
        "ERROR" { Write-Host $logMessage -ForegroundColor Red }
    }
    
    # Output to log file
    Add-Content -Path "$exportPath\PVSExport_$(Get-Date -Format 'yyyyMMdd').log" -Value $logMessage
}

# Function to create directory if it doesn't exist
function Ensure-Directory {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    
    if (-not (Test-Path -Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
        Write-Log "Created directory: $Path"
    }
}

# Set export path (current directory by default)
$exportPath = Join-Path -Path $PWD -ChildPath "PVSExport_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
Ensure-Directory -Path $exportPath

Write-Log "PVS Export started. Export directory: $exportPath"

try {
    # Make sure PVS SnapIn is loaded
    if (-not (Get-PSSnapin -Name Citrix.PVS.SnapIn -ErrorAction SilentlyContinue)) {
        Add-PSSnapin Citrix.PVS.SnapIn
        Write-Log "Added Citrix.PVS.SnapIn"
    }
    
    # Check connection to PVS
    try {
        $farms = Get-PvsFarm
        Write-Log "Successfully connected to PVS"
    }
    catch {
        Write-Log "Failed to connect to PVS. Please make sure you are running this script on a PVS server or have the PVS console installed." "ERROR"
        Write-Log "Error details: $_" "ERROR"
        exit 1
    }
    
    # Get all sites
    $sites = Get-PvsSite
    Write-Log "Found $($sites.Count) PVS site(s)"
    
    foreach ($site in $sites) {
        $siteName = $site.SiteName
        Write-Log "Processing site: $siteName"
        
        # Create site-specific directory
        $siteExportPath = Join-Path -Path $exportPath -ChildPath $siteName
        Ensure-Directory -Path $siteExportPath
        
        # Export site information
        $site | Export-Clixml -Path "$siteExportPath\site.xml"
        Write-Log "Exported site configuration for: $siteName"
        
        # Export collections for this site
        $collections = Get-PvsCollection -SiteName $siteName
        $collections | Export-Clixml -Path "$siteExportPath\collections.xml"
        Write-Log "Exported $($collections.Count) collections for site: $siteName"
        
        # Export stores for this site
        $stores = Get-PvsStore -SiteName $siteName
        $stores | Export-Clixml -Path "$siteExportPath\stores.xml"
        Write-Log "Exported $($stores.Count) stores for site: $siteName"
        
        # Create a directory for device collections
        $devicesPath = Join-Path -Path $siteExportPath -ChildPath "Devices"
        Ensure-Directory -Path $devicesPath
        
        # Export devices for each collection
        foreach ($collection in $collections) {
            $collectionName = $collection.CollectionName
            $devices = Get-PvsDevice -CollectionName $collectionName -SiteName $siteName
            $devices | Export-Clixml -Path "$devicesPath\$collectionName.xml"
            Write-Log "Exported $($devices.Count) devices for collection: $collectionName"
        }
        
        # Create a directory for vDisks
        $vDisksPath = Join-Path -Path $siteExportPath -ChildPath "vDisks"
        Ensure-Directory -Path $vDisksPath
        
        # Export vDisks for each store
        foreach ($store in $stores) {
            $storeName = $store.StoreName
            $vDisks = Get-PvsDiskLocator -StoreName $storeName -SiteName $siteName
            
            # Export each vDisk separately (not using views)
            foreach ($vDisk in $vDisks) {
                $diskLocatorName = $vDisk.DiskLocatorName
                $diskLocatorId = $vDisk.DiskLocatorId
                
                # Export vDisk configuration (using DiskLocatorId parameter)
                $vDiskInfo = Get-PvsDiskLocator -DiskLocatorId $diskLocatorId
                $vDiskInfo | Export-Clixml -Path "$vDisksPath\${storeName}_${diskLocatorName}.xml"
                
                # Export vDisk versions
                $vDiskVersions = Get-PvsDiskVersion -DiskLocatorId $diskLocatorId
                $vDiskVersions | Export-Clixml -Path "$vDisksPath\${storeName}_${diskLocatorName}_versions.xml"
                
                Write-Log "Exported vDisk: $diskLocatorName (Store: $storeName) with $($vDiskVersions.Count) versions"
            }
        }
        
        # Export servers for this site
        $servers = Get-PvsServer -SiteName $siteName
        $servers | Export-Clixml -Path "$siteExportPath\servers.xml"
        Write-Log "Exported $($servers.Count) servers for site: $siteName"
        
        # Export site properties (using Get-PvsSite since there's no dedicated Get-PvsSiteProperty cmdlet)
        $siteProperties = Get-PvsSite -SiteName $siteName | Select-Object DefaultCollectionName, DefaultDiskUpdateDeviceName, DefaultVhdBlockSize, DefaultWriteCacheType, Description, SiteId, SiteName
        $siteProperties | Export-Clixml -Path "$siteExportPath\siteProperties.xml"
        Write-Log "Exported site properties for: $siteName"
        
        # Export auth groups
        $authGroups = Get-PvsAuthGroup -SiteName $siteName
        $authGroups | Export-Clixml -Path "$siteExportPath\authGroups.xml"
        Write-Log "Exported $($authGroups.Count) auth groups for site: $siteName"
    }
    
    # Export farm configuration
    $farm = Get-PvsFarm
    $farm | Export-Clixml -Path "$exportPath\farm.xml"
    Write-Log "Exported farm configuration"
    
    # Export farm properties (using Get-PvsFarm since there's no dedicated Get-PvsFarmProperty cmdlet)
    $farmProperties = Get-PvsFarm | Select-Object DefaultSiteName, FarmId, FarmName, Description, AutoAddEnabled
    $farmProperties | Export-Clixml -Path "$exportPath\farmProperties.xml"
    Write-Log "Exported farm properties"
    
    # Export audit trail configuration
    $auditTrail = Get-PvsAuditTrail
    $auditTrail | Export-Clixml -Path "$exportPath\auditTrail.xml"
    Write-Log "Exported audit trail configuration"
    
    Write-Log "PVS Export completed successfully"
}
catch {
    Write-Log "An error occurred during the export process: $_" "ERROR"
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" "ERROR"
    exit 1
}
