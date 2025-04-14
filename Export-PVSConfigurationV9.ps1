# Function to export PVS Device configuration
function Export-PVSDevices {
    Write-Log "Starting export of PVS Device configuration" "INFO"
    
    try {
        $sites = Get-PvsSite
        
        # Create a directory for devices
        $deviceFolder = Join-Path -Path $OutputFolder -ChildPath "Devices"
        if (!(Test-Path -Path $deviceFolder)) {
            New-Item -ItemType Directory -Path $deviceFolder | Out-Null
            Write-Log "Created devices folder: $deviceFolder" "INFO"
        }
        
        foreach ($site in $sites) {
            $siteName = $site.SiteName
            Write-Log "Exporting devices for site: $siteName" "INFO"
            
            $devices = Get-PvsDevice -SiteName $siteName
            if ($devices) {
                # Export all devices for the site to a reference file
                $siteDevicesFile = Join-Path -Path $OutputFolder -ChildPath "DevicesList_${siteName}.xml"
                $devices | Export-Clixml -Path $siteDevicesFile
                Write-Log "Successfully exported list of $($devices.Count) PVS Devices for site $siteName to $siteDevicesFile" "SUCCESS"
                
                # Group devices by collection for better organization
                $devicesByCollection = $devices | Group-Object -Property CollectionName
                
                foreach ($collectionGroup in $devicesByCollection) {
                    $collectionName = $collectionGroup.Name
                    $collectionDevices = $collectionGroup.Group
                    $deviceCount = $collectionDevices.Count
                    
                    Write-Log "Exporting $deviceCount devices for collection: $collectionName" "INFO"
                    
                    $safeCollectionName = ($collectionName -replace '[\\\/\:\*\?\"\<\>\|]', '_')
                    $collectionDevicesFile = Join-Path -Path $deviceFolder -ChildPath "Devices_${siteName}_${safeCollectionName}.xml"
                    $collectionDevices | Export-Clixml -Path $collectionDevicesFile
                    Write-Log "Successfully exported $deviceCount devices for collection $collectionName to $collectionDevicesFile" "SUCCESS"
                    
                    # If there are many devices in a collection, also split by groups of 100
                    if ($deviceCount -gt 100) {
                        Write-Log "Collection $collectionName has more than 100 devices, splitting into smaller files" "INFO"
                        
                        $batchSize = 100
                        $batches = [Math]::Ceiling($deviceCount / $batchSize)
                        
                        for ($i = 0; $i -lt $batches; $i++) {
                            $start = $i * $batchSize
                            $end = [Math]::Min(($i + 1) * $batchSize - 1, $deviceCount - 1)
                            $batchDevices = $collectionDevices[$start..$end]
                            
                            $batchFile = Join-Path -Path $deviceFolder -ChildPath "Devices_${siteName}_${safeCollectionName}_batch$($i+1).xml"
                            Write-Log "Exporting batch $($i+1) of $batches (devices $($start+1) to $($end+1)) to $batchFile" "INFO"
                            
                            try {
                                $batchDevices | Export-Clixml -Path $batchFile
                                Write-Log "Successfully exported batch $($i+1) for collection $collectionName" "SUCCESS"
                            }
                            catch {
                                Write-Log "Failed to export batch $($i+1) for collection $collectionName: $_" "ERROR"
                            }
                        }
                    }
                }
            } else {
                Write-Log "No PVS Devices found to export for site $siteName" "WARNING"
            }
        }
    }
    catch {
        Write-Log "Error exporting PVS Devices: $_" "ERROR"
    }
}# Citrix PVS Configuration Export Script
# This script exports the entire Citrix PVS configuration to XML files
# Each configuration area is exported to a separate XML file

# Script Parameters
param (
    [Parameter(Mandatory=$false)]
    [string]$OutputFolder = ".\PVSExport_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
    
    [Parameter(Mandatory=$false)]
    [string]$LogFile = ".\PVSExport_$(Get-Date -Format 'yyyyMMdd_HHmmss').log",
    
    [Parameter(Mandatory=$false)]
    [string]$PVSServer = $env:COMPUTERNAME,
    
    [Parameter(Mandatory=$false)]
    [bool]$ExportFarms = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$ExportSites = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$ExportStores = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$ExportCollections = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$ExportDevices = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$ExportvDisks = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$ExportViews = $true
)

# Function to write log entries
function Write-Log {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    
    # Output to console with color coding
    switch ($Level) {
        "INFO"    { Write-Host $LogEntry -ForegroundColor Cyan }
        "WARNING" { Write-Host $LogEntry -ForegroundColor Yellow }
        "ERROR"   { Write-Host $LogEntry -ForegroundColor Red }
        "SUCCESS" { Write-Host $LogEntry -ForegroundColor Green }
    }
    
    # Write to log file
    Add-Content -Path $LogFile -Value $LogEntry
}

# Function to check if Citrix PVS PowerShell snap-in is loaded
function Import-PVSSnapin {
    try {
        # Check if snap-in is already loaded
        if (!(Get-PSSnapin -Name Citrix.PVS.SnapIn -ErrorAction SilentlyContinue)) {
            # Load the PVS snap-in
            Add-PSSnapin Citrix.PVS.SnapIn
            Write-Log "Citrix PVS PowerShell snap-in loaded successfully" "SUCCESS"
        } else {
            Write-Log "Citrix PVS PowerShell snap-in is already loaded" "INFO"
        }
        return $true
    }
    catch {
        Write-Log "Failed to load Citrix PVS PowerShell snap-in: $_" "ERROR"
        return $false
    }
}

# Function to create output folder if it doesn't exist
function New-OutputFolder {
    try {
        if (!(Test-Path -Path $OutputFolder)) {
            New-Item -ItemType Directory -Path $OutputFolder | Out-Null
            Write-Log "Created output folder: $OutputFolder" "SUCCESS"
        } else {
            Write-Log "Output folder already exists: $OutputFolder" "INFO"
        }
        return $true
    }
    catch {
        Write-Log "Failed to create output folder: $_" "ERROR"
        return $false
    }
}

# Function to export PVS Farm configuration
function Export-PVSFarms {
    Write-Log "Starting export of PVS Farm configuration" "INFO"
    
    try {
        $farms = Get-PvsFarm
        if ($farms) {
            # Create a directory for farms
            $farmFolder = Join-Path -Path $OutputFolder -ChildPath "Farms"
            if (!(Test-Path -Path $farmFolder)) {
                New-Item -ItemType Directory -Path $farmFolder | Out-Null
                Write-Log "Created farms folder: $farmFolder" "INFO"
            }
            
            # Export farm list for reference
            $farmListFile = Join-Path -Path $OutputFolder -ChildPath "FarmsList.xml"
            $farms | Export-Clixml -Path $farmListFile
            Write-Log "Successfully exported list of $($farms.Count) PVS Farms to $farmListFile" "SUCCESS"
            
            # Export each farm to a separate file
            foreach ($farm in $farms) {
                $farmName = $farm.FarmName
                Write-Log "Exporting configuration for farm: $farmName" "INFO"
                
                # Export Farm to separate file
                $farmFile = Join-Path -Path $farmFolder -ChildPath ("Farm_" + $farmName + ".xml")
                $farm | Export-Clixml -Path $farmFile
                Write-Log "Successfully exported farm $farmName to $farmFile" "SUCCESS"
            }
        } else {
            Write-Log "No PVS Farms found to export" "WARNING"
        }
    }
    catch {
        Write-Log "Error exporting PVS Farms: $_" "ERROR"
    }
}

# Function to export PVS Site configuration
function Export-PVSSites {
    Write-Log "Starting export of PVS Site configuration" "INFO"
    
    try {
        $sites = Get-PvsSite
        if ($sites) {
            # Create a directory for sites
            $siteFolder = Join-Path -Path $OutputFolder -ChildPath "Sites"
            if (!(Test-Path -Path $siteFolder)) {
                New-Item -ItemType Directory -Path $siteFolder | Out-Null
                Write-Log "Created sites folder: $siteFolder" "INFO"
            }
            
            # Export site list for reference
            $siteListFile = Join-Path -Path $OutputFolder -ChildPath "SitesList.xml"
            $sites | Export-Clixml -Path $siteListFile
            Write-Log "Successfully exported list of $($sites.Count) PVS Sites to $siteListFile" "SUCCESS"
            
            # Export each site to a separate file
            foreach ($site in $sites) {
                $siteName = $site.SiteName
                Write-Log "Exporting configuration for site: $siteName" "INFO"
                
                # Export Site to separate file
                $siteFile = Join-Path -Path $siteFolder -ChildPath ("Site_" + $siteName + ".xml")
                $site | Export-Clixml -Path $siteFile
                Write-Log "Successfully exported site $siteName to $siteFile" "SUCCESS"
                
                # Export Site servers
                try {
                    $servers = Get-PvsServer -SiteName $siteName
                    if ($servers) {
                        $serverFile = Join-Path -Path $siteFolder -ChildPath ("Servers_" + $siteName + ".xml")
                        $servers | Export-Clixml -Path $serverFile
                        Write-Log "Successfully exported $($servers.Count) PVS Servers for site $siteName to $serverFile" "SUCCESS"
                    } else {
                        Write-Log "No PVS Servers found to export for site $siteName" "WARNING"
                    }
                }
                catch {
                    Write-Log "Error exporting PVS Servers for site $siteName: $_" "ERROR"
                }
            }
        } else {
            Write-Log "No PVS Sites found to export" "WARNING"
        }
    }
    catch {
        Write-Log "Error exporting PVS Sites: $_" "ERROR"
    }
}

# Function to export PVS Store configuration
function Export-PVSStores {
    Write-Log "Starting export of PVS Store configuration" "INFO"
    
    try {
        $stores = Get-PvsStore
        if ($stores) {
            # Create a directory for stores
            $storeFolder = Join-Path -Path $OutputFolder -ChildPath "Stores"
            if (!(Test-Path -Path $storeFolder)) {
                New-Item -ItemType Directory -Path $storeFolder | Out-Null
                Write-Log "Created stores folder: $storeFolder" "INFO"
            }
            
            # Export store list for reference
            $storeListFile = Join-Path -Path $OutputFolder -ChildPath "StoresList.xml"
            $stores | Export-Clixml -Path $storeListFile
            Write-Log "Successfully exported list of $($stores.Count) PVS Stores to $storeListFile" "SUCCESS"
            
            # Export each store to a separate file
            foreach ($store in $stores) {
                $storeName = $store.StoreName
                $siteName = $store.SiteName
                
                Write-Log "Exporting configuration for store: $storeName (Site: $siteName)" "INFO"
                
                # Export Store to separate file
                $storeFile = Join-Path -Path $storeFolder -ChildPath "Store_${siteName}_${storeName}.xml"
                $store | Export-Clixml -Path $storeFile
                Write-Log "Successfully exported store $storeName to $storeFile" "SUCCESS"
            }
        } else {
            Write-Log "No PVS Stores found to export" "WARNING"
        }
    }
    catch {
        Write-Log "Error exporting PVS Stores: $_" "ERROR"
    }
}

# Function to export PVS Collection configuration
function Export-PVSCollections {
    Write-Log "Starting export of PVS Collection configuration" "INFO"
    
    try {
        $sites = Get-PvsSite
        
        # Create a directory for collections
        $collectionFolder = Join-Path -Path $OutputFolder -ChildPath "Collections"
        if (!(Test-Path -Path $collectionFolder)) {
            New-Item -ItemType Directory -Path $collectionFolder | Out-Null
            Write-Log "Created collections folder: $collectionFolder" "INFO"
        }
        
        foreach ($site in $sites) {
            $siteName = $site.SiteName
            Write-Log "Exporting collections for site: $siteName" "INFO"
            
            $collections = Get-PvsCollection -SiteName $siteName
            if ($collections) {
                # Export all collections for the site to a reference file
                $siteCollectionsFile = Join-Path -Path $OutputFolder -ChildPath "CollectionsList_${siteName}.xml"
                $collections | Export-Clixml -Path $siteCollectionsFile
                Write-Log "Successfully exported list of $($collections.Count) PVS Collections for site $siteName to $siteCollectionsFile" "SUCCESS"
                
                # Export each collection to a separate file
                foreach ($collection in $collections) {
                    $collectionName = $collection.CollectionName
                    Write-Log "Exporting collection: $collectionName" "INFO"
                    
                    # Export Collection to separate file
                    $safeCollectionName = ($collectionName -replace '[\\\/\:\*\?\"\<\>\|]', '_')
                    $collectionFile = Join-Path -Path $collectionFolder -ChildPath "Collection_${siteName}_${safeCollectionName}.xml"
                    $collection | Export-Clixml -Path $collectionFile
                    Write-Log "Successfully exported collection $collectionName to $collectionFile" "SUCCESS"
                }
            } else {
                Write-Log "No PVS Collections found to export for site $siteName" "WARNING"
            }
        }
    }
    catch {
        Write-Log "Error exporting PVS Collections: $_" "ERROR"
    }
}

# Function to export PVS Device configuration
function Export-PVSDevices {
    Write-Log "Starting export of PVS Device configuration" "INFO"
    
    try {
        $sites = Get-PvsSite
        foreach ($site in $sites) {
            $siteName = $site.SiteName
            Write-Log "Exporting devices for site: $siteName" "INFO"
            
            $devices = Get-PvsDevice -SiteName $siteName
            if ($devices) {
                $deviceFile = Join-Path -Path $OutputFolder -ChildPath "Devices_$($siteName).xml"
                $devices | Export-Clixml -Path $deviceFile
                Write-Log "Successfully exported $($devices.Count) PVS Devices for site $siteName to $deviceFile" "SUCCESS"
            } else {
                Write-Log "No PVS Devices found to export for site $siteName" "WARNING"
            }
        }
    }
    catch {
        Write-Log "Error exporting PVS Devices: $_" "ERROR"
    }
}

# Function to export PVS vDisk configuration
function Export-PVSvDisks {
    Write-Log "Starting export of PVS vDisk configuration" "INFO"
    
    try {
        Write-Log "Retrieving all vDisks from PVS environment..." "INFO"
        $vDisks = Get-PvsDiskInfo
        Write-Log "Retrieved $(if($vDisks){$vDisks.Count}else{0}) vDisks from PVS environment" "INFO"
        
        if ($vDisks) {
            # Create a directory for vDisks
            $vDiskFolder = Join-Path -Path $OutputFolder -ChildPath "vDisks"
            if (!(Test-Path -Path $vDiskFolder)) {
                New-Item -ItemType Directory -Path $vDiskFolder | Out-Null
                Write-Log "Created vDisks folder: $vDiskFolder" "INFO"
            }
            
            # Export vDisk list for reference
            $vDiskListFile = Join-Path -Path $OutputFolder -ChildPath "vDisksList.xml"
            $vDisks | Export-Clixml -Path $vDiskListFile
            Write-Log "Successfully exported list of $($vDisks.Count) PVS vDisks to $vDiskListFile" "SUCCESS"
            
            # Group vDisks by store
            $vDisksByStore = $vDisks | Group-Object -Property StoreName
            
            foreach ($storeGroup in $vDisksByStore) {
                $storeName = $storeGroup.Name
                $storeVDisks = $storeGroup.Group
                
                Write-Log "Exporting $($storeVDisks.Count) vDisks for store: $storeName" "INFO"
                
                # Export Store vDisks to separate file
                $safeStoreName = ($storeName -replace '[\\\/\:\*\?\"\<\>\|]', '_')
                $storeVDisksFile = Join-Path -Path $vDiskFolder -ChildPath "vDisks_Store_${safeStoreName}.xml"
                $storeVDisks | Export-Clixml -Path $storeVDisksFile
                Write-Log "Successfully exported vDisks for store $storeName to $storeVDisksFile" "SUCCESS"
            }
            
            # Export vDisk versions
            Write-Log "Starting export of vDisk versions" "INFO"
            
            # Create a directory for vDisk versions
            $vDiskVersionFolder = Join-Path -Path $OutputFolder -ChildPath "vDiskVersions"
            if (!(Test-Path -Path $vDiskVersionFolder)) {
                New-Item -ItemType Directory -Path $vDiskVersionFolder | Out-Null
                Write-Log "Created vDisk versions folder: $vDiskVersionFolder" "INFO"
            }
            
            $processedDisks = 0
            $totalDisks = $vDisks.Count
            
            foreach ($vDisk in $vDisks) {
                $processedDisks++
                $diskLocatorId = $vDisk.DiskLocatorId
                $diskName = $vDisk.Name
                $storeName = $vDisk.StoreName
                $siteName = $vDisk.SiteName
                
                Write-Log "Processing vDisk [$processedDisks of $totalDisks]: '$diskName' in store '$storeName' (DiskLocatorId: $diskLocatorId)" "INFO"
                
                try {
                    Write-Log "Retrieving versions for vDisk '$diskName'..." "INFO"
                    $versions = Get-PvsDiskVersion -DiskLocatorId $diskLocatorId -ErrorAction Stop
                    
                    if ($versions) {
                        $versionCount = $versions.Count
                        Write-Log "Found $versionCount versions for vDisk '$diskName'" "INFO"
                        
                        # Log a summary of versions found
                        $versionNumbers = $versions | ForEach-Object { $_.Version } | Sort-Object
                        Write-Log "Version numbers found for '$diskName': $($versionNumbers -join ', ')" "INFO"
                        
                        # Export versions to a separate file for each vDisk
                        $safeFileName = ($diskName -replace '[\\\/\:\*\?\"\<\>\|]', '_')
                        $safeStoreName = ($storeName -replace '[\\\/\:\*\?\"\<\>\|]', '_')
                        $vDiskVersionFile = Join-Path -Path $vDiskVersionFolder -ChildPath "Versions_${safeStoreName}_${safeFileName}.xml"
                        
                        try {
                            $versions | Export-Clixml -Path $vDiskVersionFile
                            Write-Log "Successfully exported $versionCount versions for vDisk '$diskName' to $vDiskVersionFile" "SUCCESS"
                        }
                        catch {
                            Write-Log "Error exporting versions for vDisk '$diskName' to file: $_" "ERROR"
                        }
                    } else {
                        Write-Log "No versions found for vDisk '$diskName'" "WARNING"
                    }
                }
                catch {
                    Write-Log "Error retrieving versions for vDisk '$diskName': $_" "ERROR"
                    # Additional diagnostic information
                    Write-Log "Diagnostic info for failed vDisk: StoreName='$storeName', SiteName='$siteName', DiskLocatorId='$diskLocatorId'" "ERROR"
                    
                    # Try alternative approach if the main one fails
                    try {
                        Write-Log "Attempting alternative method to get versions for '$diskName'..." "INFO"
                        $altVersions = Get-PvsDiskVersion -Name $diskName -StoreName $storeName -SiteName $siteName -ErrorAction Stop
                        
                        if ($altVersions) {
                            Write-Log "Alternative method successful: Found $($altVersions.Count) versions" "SUCCESS"
                            
                            # Export versions to a separate file
                            $safeFileName = ($diskName -replace '[\\\/\:\*\?\"\<\>\|]', '_')
                            $safeStoreName = ($storeName -replace '[\\\/\:\*\?\"\<\>\|]', '_')
                            $vDiskVersionFile = Join-Path -Path $vDiskVersionFolder -ChildPath "Versions_${safeStoreName}_${safeFileName}_alt.xml"
                            
                            try {
                                $altVersions | Export-Clixml -Path $vDiskVersionFile
                                Write-Log "Successfully exported $($altVersions.Count) versions for vDisk '$diskName' using alternative method" "SUCCESS"
                            }
                            catch {
                                Write-Log "Error exporting versions using alternative method for vDisk '$diskName': $_" "ERROR"
                            }
                        } else {
                            Write-Log "Alternative method returned no versions" "WARNING"
                        }
                    }
                    catch {
                        Write-Log "Alternative method also failed: $_" "ERROR"
                    }
                }
                
                # Perform cleanup to prevent memory issues with large exports
                if ($processedDisks % 10 -eq 0) {
                    Write-Log "Performing memory cleanup after processing $processedDisks vDisks" "INFO"
                    # Clear variables that are no longer needed
                    $versions = $null
                    $versionNumbers = $null
                    [System.GC]::Collect()
                }
            }
        } else {
            Write-Log "No PVS vDisks found to export" "WARNING"
        }
    }
    catch {
        Write-Log "Error exporting PVS vDisks: $_" "ERROR"
    }
    
    Write-Log "Completed vDisk and vDisk version export process" "INFO"
}diskLocatorId)" "INFO"
                
                try {
                    Write-Log "Retrieving versions for vDisk '$diskName'..." "INFO"
                    $versions = Get-PvsDiskVersion -DiskLocatorId $diskLocatorId -ErrorAction Stop
                    
                    if ($versions) {
                        $versionCount = $versions.Count
                        Write-Log "Found $versionCount versions for vDisk '$diskName'" "INFO"
                        
                        # Log a summary of versions found
                        $versionNumbers = $versions | ForEach-Object { $_.Version } | Sort-Object
                        Write-Log "Version numbers found for '$diskName': $($versionNumbers -join ', ')" "INFO"
                        
                        # Export versions to a separate file for each vDisk
                        $safeFileName = ($diskName -replace '[\\\/\:\*\?\"\<\>\|]', '_')
                        $vDiskVersionFile = Join-Path -Path $vDiskVersionFolder -ChildPath "Versions_${storeName}_${safeFileName}.xml"
                        
                        try {
                            $versions | Export-Clixml -Path $vDiskVersionFile
                            Write-Log "Successfully exported $versionCount versions for vDisk '$diskName' to $vDiskVersionFile" "SUCCESS"
                        }
                        catch {
                            Write-Log "Error exporting versions for vDisk '$diskName' to file: $_" "ERROR"
                        }
                    } else {
                        Write-Log "No versions found for vDisk '$diskName'" "WARNING"
                    }
                }
                catch {
                    Write-Log "Error retrieving versions for vDisk '$diskName': $_" "ERROR"
                    # Additional diagnostic information
                    Write-Log "Diagnostic info for failed vDisk: StoreName='$storeName', SiteName='$siteName', DiskLocatorId='$diskLocatorId'" "ERROR"
                    
                    # Try alternative approach if the main one fails
                    try {
                        Write-Log "Attempting alternative method to get versions for '$diskName'..." "INFO"
                        $altVersions = Get-PvsDiskVersion -Name $diskName -StoreName $storeName -SiteName $siteName -ErrorAction Stop
                        
                        if ($altVersions) {
                            Write-Log "Alternative method successful: Found $($altVersions.Count) versions" "SUCCESS"
                            
                            # Export versions to a separate file
                            $safeFileName = ($diskName -replace '[\\\/\:\*\?\"\<\>\|]', '_')
                            $vDiskVersionFile = Join-Path -Path $vDiskVersionFolder -ChildPath "Versions_${storeName}_${safeFileName}_alt.xml"
                            
                            try {
                                $altVersions | Export-Clixml -Path $vDiskVersionFile
                                Write-Log "Successfully exported $($altVersions.Count) versions for vDisk '$diskName' using alternative method" "SUCCESS"
                            }
                            catch {
                                Write-Log "Error exporting versions using alternative method for vDisk '$diskName': $_" "ERROR"
                            }
                        } else {
                            Write-Log "Alternative method returned no versions" "WARNING"
                        }
                    }
                    catch {
                        Write-Log "Alternative method also failed: $_" "ERROR"
                    }
                }
                
                # Perform cleanup to prevent memory issues with large exports
                if ($processedDisks % 10 -eq 0) {
                    Write-Log "Performing memory cleanup after processing $processedDisks vDisks" "INFO"
                    # Clear variables that are no longer needed
                    $versions = $null
                    $versionNumbers = $null
                    [System.GC]::Collect()
                }
            }
        } else {
            Write-Log "No PVS vDisks found to export" "WARNING"
        }
    }
    catch {
        Write-Log "Error exporting PVS vDisks: $_" "ERROR"
    }
    
    Write-Log "Completed vDisk and vDisk version export process" "INFO"
}

# Function to export PVS Views configuration
function Export-PVSViews {
    Write-Log "Starting export of PVS Views configuration" "INFO"
    
    try {
        $views = Get-PvsView
        if ($views) {
            # Create a directory for views
            $viewFolder = Join-Path -Path $OutputFolder -ChildPath "Views"
            if (!(Test-Path -Path $viewFolder)) {
                New-Item -ItemType Directory -Path $viewFolder | Out-Null
                Write-Log "Created views folder: $viewFolder" "INFO"
            }
            
            # Export view list for reference
            $viewListFile = Join-Path -Path $OutputFolder -ChildPath "ViewsList.xml"
            $views | Export-Clixml -Path $viewListFile
            Write-Log "Successfully exported list of $($views.Count) PVS Views to $viewListFile" "SUCCESS"
            
            # Export each view to a separate file
            foreach ($view in $views) {
                $viewName = $view.ViewName
                Write-Log "Exporting configuration for view: $viewName" "INFO"
                
                $safeViewName = ($viewName -replace '[\\\/\:\*\?\"\<\>\|]', '_')
                $viewFile = Join-Path -Path $viewFolder -ChildPath "View_${safeViewName}.xml"
                $view | Export-Clixml -Path $viewFile
                Write-Log "Successfully exported view $viewName to $viewFile" "SUCCESS"
            }
        } else {
            Write-Log "No PVS Views found to export" "WARNING"
        }
    }
    catch {
        Write-Log "Error exporting PVS Views: $_" "ERROR"
    }
}

# Main execution
Write-Log "Starting Citrix PVS Configuration Export Script" "INFO"
Write-Log "Output folder: $OutputFolder" "INFO"
Write-Log "Log file: $LogFile" "INFO"
Write-Log "PVS Server: $PVSServer" "INFO"

# Initialize PVS environment
if (!(Import-PVSSnapin)) {
    Write-Log "Failed to initialize PVS environment. Exiting script." "ERROR"
    exit 1
}

# Create output folder
if (!(New-OutputFolder)) {
    Write-Log "Failed to create output folder. Exiting script." "ERROR"
    exit 1
}

# Export each configuration component based on parameters
if ($ExportFarms) {
    Export-PVSFarms
}

if ($ExportSites) {
    Export-PVSSites
}

if ($ExportStores) {
    Export-PVSStores
}

if ($ExportCollections) {
    Export-PVSCollections
}

if ($ExportDevices) {
    Export-PVSDevices
}

if ($ExportvDisks) {
    Export-PVSvDisks
}

if ($ExportViews) {
    Export-PVSViews
}

# Create summary file with export details
$summary = @{
    ExportDate = Get-Date
    PVSServer = $PVSServer
    ExportedComponents = @{
        Farms = $ExportFarms
        Sites = $ExportSites
        Stores = $ExportStores
        Collections = $ExportCollections
        Devices = $ExportDevices
        vDisks = $ExportvDisks
        Views = $ExportViews
    }
}

$summaryFile = Join-Path -Path $OutputFolder -ChildPath "ExportSummary.xml"
$summary | Export-Clixml -Path $summaryFile
Write-Log "Export summary created at $summaryFile" "SUCCESS"

Write-Log "Citrix PVS Configuration Export completed successfully" "SUCCESS"
