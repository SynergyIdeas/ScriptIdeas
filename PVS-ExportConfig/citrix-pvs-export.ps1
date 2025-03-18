# Citrix PVS Configuration Export Script
# This script exports the entire Citrix Provisioning Services configuration to XML files

# Set up logging
$logFile = "C:\PVSExport\PVSExport_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$exportPath = "C:\PVSExport\$(Get-Date -Format 'yyyyMMdd_HHmmss')"

# Create export directory if it doesn't exist
if (!(Test-Path $exportPath)) {
    New-Item -Path $exportPath -ItemType Directory -Force | Out-Null
}

# Function for logging
function Write-Log {
    param (
        [string]$Message
    )
    
    $timeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timeStamp - $Message" | Out-File -FilePath $logFile -Append
    Write-Host "$timeStamp - $Message"
}

Write-Log "Starting Citrix PVS configuration export"

# Check for PVS PowerShell snap-in
try {
    if (!(Get-PSSnapin -Name Citrix.PVS.SnapIn -ErrorAction SilentlyContinue)) {
        Add-PSSnapin Citrix.PVS.SnapIn
        Write-Log "Added Citrix PVS SnapIn"
    }
}
catch {
    Write-Log "ERROR: Failed to load Citrix PVS SnapIn. Is PVS Console installed? Error: $_"
    exit 1
}

# Get PVS farm information
try {
    $farmViews = Get-PvsFarmView
    Write-Log "Successfully connected to PVS farm"
    
    # Export Farm Information
    $farmInfo = Get-PvsFarm
    $farmInfo | Export-Clixml -Path "$exportPath\Farm.xml"
    Write-Log "Exported Farm configuration to $exportPath\Farm.xml"
    
    # Export Sites
    $sites = Get-PvsSite
    $sites | Export-Clixml -Path "$exportPath\Sites.xml"
    Write-Log "Exported $($sites.Count) Sites to $exportPath\Sites.xml"
    
    # Export Servers
    $servers = Get-PvsServer
    $servers | Export-Clixml -Path "$exportPath\Servers.xml"
    Write-Log "Exported $($servers.Count) Servers to $exportPath\Servers.xml"
    
    # Export Stores
    $stores = Get-PvsStore
    $stores | Export-Clixml -Path "$exportPath\Stores.xml"
    Write-Log "Exported $($stores.Count) Stores to $exportPath\Stores.xml"
    
    # Export Collections and Devices per Site
    foreach ($site in $sites) {
        $siteName = $site.SiteName
        Write-Log "Processing site: $siteName"
        
        # Export Collections for this site
        $collections = Get-PvsCollection -SiteName $siteName
        $collections | Export-Clixml -Path "$exportPath\Collections_$siteName.xml"
        Write-Log "Exported $($collections.Count) Collections for site $siteName"
        
        # Export Devices for each Collection in this site
        foreach ($collection in $collections) {
            $collectionName = $collection.CollectionName
            $devices = Get-PvsDevice -CollectionName $collectionName -SiteName $siteName
            $devices | Export-Clixml -Path "$exportPath\Devices_${siteName}_${collectionName}.xml"
            Write-Log "Exported $($devices.Count) Devices for collection $collectionName in site $siteName"
        }
        
        # Export all vDisks for this site
        $vDisks = Get-PvsDiskInfo -SiteName $siteName
        $vDisks | Export-Clixml -Path "$exportPath\vDisks_$siteName.xml"
        Write-Log "Exported $($vDisks.Count) vDisks for site $siteName"
        
        # Export all vDisk versions for each vDisk
        foreach ($vDisk in $vDisks) {
            $vDiskName = $vDisk.Name
            $vDiskVersions = Get-PvsDiskVersion -DiskLocatorName $vDiskName -SiteName $siteName
            $vDiskVersions | Export-Clixml -Path "$exportPath\vDiskVersions_${siteName}_${vDiskName}.xml"
            Write-Log "Exported $($vDiskVersions.Count) versions for vDisk $vDiskName in site $siteName"
        }
    }
    
    # Export Site Views
    $siteViews = Get-PvsSiteView
    $siteViews | Export-Clixml -Path "$exportPath\SiteViews.xml"
    Write-Log "Exported $($siteViews.Count) Site Views to $exportPath\SiteViews.xml"
    
    # Export Farm Views
    $farmViews | Export-Clixml -Path "$exportPath\FarmViews.xml"
    Write-Log "Exported $($farmViews.Count) Farm Views to $exportPath\FarmViews.xml"
    
    # Export Authentication
    $auth = Get-PvsAuthGroup
    $auth | Export-Clixml -Path "$exportPath\AuthGroups.xml"
    Write-Log "Exported $($auth.Count) Authentication Groups to $exportPath\AuthGroups.xml"
    
    # Export Properties
    $farmProperties = Get-PvsConnection
    $farmProperties | Export-Clixml -Path "$exportPath\FarmProperties.xml"
    Write-Log "Exported Farm Properties to $exportPath\FarmProperties.xml"
    
    # Create a summary report
    $summary = @{
        ExportDate = Get-Date
        FarmName = $farmInfo.FarmName
        SiteCount = $sites.Count
        ServerCount = $servers.Count
        StoreCount = $stores.Count
        CollectionsTotal = ($collections | Measure-Object).Count
        DevicesTotal = ($devices | Measure-Object).Count
        vDisksTotal = ($vDisks | Measure-Object).Count
    }
    
    $summary | Export-Clixml -Path "$exportPath\Summary.xml"
    Write-Log "Created summary report at $exportPath\Summary.xml"
    
    # Create a compressed archive of all exports
    try {
        Compress-Archive -Path "$exportPath\*" -DestinationPath "$exportPath.zip" -CompressionLevel Optimal
        Write-Log "Created compressed archive of all exports at $exportPath.zip"
    }
    catch {
        Write-Log "WARNING: Could not create compressed archive: $_"
    }
    
    Write-Log "PVS configuration export completed successfully"
    Write-Host "Export completed. Files are available at: $exportPath" -ForegroundColor Green
    Write-Host "Compressed archive: $exportPath.zip" -ForegroundColor Green
}
catch {
    Write-Log "ERROR: Failed to export PVS configuration: $_"
    Write-Host "Export failed. See log file for details: $logFile" -ForegroundColor Red
    exit 1
}
