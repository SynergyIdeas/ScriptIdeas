# Citrix PVS Configuration Import Script
# This script imports the Citrix PVS configuration from XML files previously exported

# Script Parameters
param (
    [Parameter(Mandatory=$true)]
    [string]$ImportFolder,
    
    [Parameter(Mandatory=$false)]
    [string]$LogFile = $(Join-Path -Path "." -ChildPath "PVSImport_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"),
    
    [Parameter(Mandatory=$false)]
    [bool]$ImportFarms = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$ImportSites = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$ImportStores = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$ImportCollections = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$ImportDevices = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$ImportvDisks = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$ImportViews = $true,
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
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

# Main execution
Write-Log "Starting Citrix PVS Configuration Import Script" "INFO"
Write-Log "Import folder: $ImportFolder" "INFO"
Write-Log "Log file: $LogFile" "INFO"
Write-Log "WhatIf mode: $WhatIf" "INFO"

# Initialize PVS environment
if (!(Import-PVSSnapin)) {
    Write-Log "Failed to initialize PVS environment. Exiting script." "ERROR"
    exit 1
}

# Validate import folder
if (!(Validate-ImportFolder)) {
    Write-Log "Failed to validate import folder. Exiting script." "ERROR"
    exit 1
}

# Try to load summary file for information
$summaryFile = Join-Path -Path $ImportFolder -ChildPath "ExportSummary.xml"
if (Test-Path -Path $summaryFile) {
    try {
        $summary = Import-Clixml -Path $summaryFile
        Write-Log "Found export summary file, original export was created on: $($summary.ExportDate)" "INFO"
        Write-Log "Original PVS Server: $($summary.PVSServer)" "INFO"
    }
    catch {
        Write-Log "Error reading export summary file: $_" "WARNING"
    }
}

# Import each configuration component based on parameters
if ($ImportFarms) {
    Import-PVSFarms
}

if ($ImportSites) {
    Import-PVSSites
}

if ($ImportStores) {
    Import-PVSStores
}

if ($ImportCollections) {
    Import-PVSCollections
}

if ($ImportDevices) {
    Import-PVSDevices
}

if ($ImportvDisks) {
    Import-PVSvDisks
}

if ($ImportViews) {
    Import-PVSViews
}

# Create summary file with import details
$importSummary = @{
    ImportDate = Get-Date
    SourceFolder = $ImportFolder
    ImportedComponents = @{
        Farms = $ImportFarms
        Sites = $ImportSites
        Stores = $ImportStores
        Collections = $ImportCollections
        Devices = $ImportDevices
        vDisks = $ImportvDisks
        Views = $ImportViews
    }
    WhatIfMode = $WhatIf
}

$importSummaryFile = ".\PVSImportSummary_$(Get-Date -Format 'yyyyMMdd_HHmmss').xml"
$importSummary | Export-Clixml -Path $importSummaryFile
Write-Log "Import summary created at $importSummaryFile" "SUCCESS"

Write-Log "Citrix PVS Configuration Import completed successfully" "SUCCESS"

# Provide reminders for manual steps
Write-Log "---------------------------------------------------------------" "INFO"
Write-Log "IMPORTANT: The following items may require manual configuration:" "WARNING"
Write-Log "1. vDisk files (VHD/VHDX) must be manually copied to the appropriate store locations" "WARNING"
Write-Log "2. Authentication and permissions should be verified" "WARNING"
Write-Log "3. Server configurations specific to your environment may need adjustment" "WARNING"
Write-Log "4. PVS services may need to be restarted to apply all changes" "WARNING"
Write-Log "---------------------------------------------------------------" "INFO"

# Function to check if the import folder exists and contains the necessary files
function Validate-ImportFolder {
    try {
        if (!(Test-Path -Path $ImportFolder)) {
            Write-Log "Import folder does not exist: $ImportFolder" "ERROR"
            return $false
        }
        
        # Check for summary file
        $summaryFile = Join-Path -Path $ImportFolder -ChildPath "ExportSummary.xml"
        if (!(Test-Path -Path $summaryFile)) {
            Write-Log "Export summary file not found in import folder: $summaryFile" "WARNING"
            # Continue anyway, but warn the user
        }
        
        return $true
    }
    catch {
        Write-Log "Error validating import folder: $_" "ERROR"
        return $false
    }
}

# Function to import PVS Farm configuration
function Import-PVSFarms {
    Write-Log "Starting import of PVS Farm configuration" "INFO"
    
    $farmFile = Join-Path -Path $ImportFolder -ChildPath "Farms.xml"
    if (!(Test-Path -Path $farmFile)) {
        Write-Log "Farm configuration file not found: $farmFile" "ERROR"
        return
    }
    
    try {
        $farms = Import-Clixml -Path $farmFile
        Write-Log "Found $($farms.Count) farms to import" "INFO"
        
        foreach ($farm in $farms) {
            $farmName = $farm.FarmName
            
            # Check if farm already exists
            $existingFarm = Get-PvsFarm -FarmName $farmName -ErrorAction SilentlyContinue
            
            if ($existingFarm) {
                Write-Log "Farm '$farmName' already exists, updating configuration" "WARNING"
                if (!$WhatIf) {
                    # Update farm properties
                    $updateParams = @{
                        FarmName = $farmName
                    }
                    
                    # Add other properties that can be updated
                    if ($farm.Description) { $updateParams.Add("Description", $farm.Description) }
                    if ($farm.AutoAddEnabled -ne $null) { $updateParams.Add("AutoAddEnabled", $farm.AutoAddEnabled) }
                    if ($farm.AuditingEnabled -ne $null) { $updateParams.Add("AuditingEnabled", $farm.AuditingEnabled) }
                    if ($farm.DefaultSiteName) { $updateParams.Add("DefaultSiteName", $farm.DefaultSiteName) }
                    
                    Set-PvsFarm @updateParams
                    Write-Log "Updated Farm '$farmName'" "SUCCESS"
                } else {
                    Write-Log "WhatIf: Would update Farm '$farmName'" "INFO"
                }
            } else {
                if (!$WhatIf) {
                    # Create new farm
                    $newParams = @{
                        FarmName = $farmName
                    }
                    
                    # Add other properties
                    if ($farm.Description) { $newParams.Add("Description", $farm.Description) }
                    if ($farm.AutoAddEnabled -ne $null) { $newParams.Add("AutoAddEnabled", $farm.AutoAddEnabled) }
                    if ($farm.AuditingEnabled -ne $null) { $newParams.Add("AuditingEnabled", $farm.AuditingEnabled) }
                    
                    New-PvsFarm @newParams
                    Write-Log "Created new Farm '$farmName'" "SUCCESS"
                } else {
                    Write-Log "WhatIf: Would create new Farm '$farmName'" "INFO"
                }
            }
        }
    }
    catch {
        Write-Log "Error importing PVS Farms: $_" "ERROR"
    }
}

# Function to import PVS Site configuration
function Import-PVSSites {
    Write-Log "Starting import of PVS Site configuration" "INFO"
    
    $siteFile = Join-Path -Path $ImportFolder -ChildPath "Sites.xml"
    if (!(Test-Path -Path $siteFile)) {
        Write-Log "Site configuration file not found: $siteFile" "ERROR"
        return
    }
    
    try {
        $sites = Import-Clixml -Path $siteFile
        Write-Log "Found $($sites.Count) sites to import" "INFO"
        
        foreach ($site in $sites) {
            $siteName = $site.SiteName
            $farmName = $site.FarmName
            
            # Check if site already exists
            $existingSite = Get-PvsSite -SiteName $siteName -ErrorAction SilentlyContinue
            
            if ($existingSite) {
                Write-Log "Site '$siteName' already exists, updating configuration" "WARNING"
                if (!$WhatIf) {
                    # Update site properties
                    $updateParams = @{
                        SiteName = $siteName
                    }
                    
                    # Add other properties that can be updated
                    if ($site.Description) { $updateParams.Add("Description", $site.Description) }
                    if ($site.DefaultCollectionName) { $updateParams.Add("DefaultCollectionName", $site.DefaultCollectionName) }
                    if ($site.InventoryFilePollingInterval -ne $null) { $updateParams.Add("InventoryFilePollingInterval", $site.InventoryFilePollingInterval) }
                    
                    Set-PvsSite @updateParams
                    Write-Log "Updated Site '$siteName'" "SUCCESS"
                } else {
                    Write-Log "WhatIf: Would update Site '$siteName'" "INFO"
                }
            } else {
                if (!$WhatIf) {
                    # Create new site
                    $newParams = @{
                        SiteName = $siteName
                        FarmName = $farmName
                    }
                    
                    # Add other properties
                    if ($site.Description) { $newParams.Add("Description", $site.Description) }
                    if ($site.DefaultCollectionName) { $newParams.Add("DefaultCollectionName", $site.DefaultCollectionName) }
                    
                    New-PvsSite @newParams
                    Write-Log "Created new Site '$siteName' in Farm '$farmName'" "SUCCESS"
                } else {
                    Write-Log "WhatIf: Would create new Site '$siteName' in Farm '$farmName'" "INFO"
                }
            }
            
            # Import Site servers if available
            $serverFile = Join-Path -Path $ImportFolder -ChildPath "Servers_$($siteName).xml"
            if (Test-Path -Path $serverFile) {
                Import-PVSServers -SiteName $siteName -ServerFile $serverFile
            }
        }
    }
    catch {
        Write-Log "Error importing PVS Sites: $_" "ERROR"
    }
}

# Function to import PVS Servers for a site
function Import-PVSServers {
    param (
        [string]$SiteName,
        [string]$ServerFile
    )
    
    Write-Log "Starting import of PVS Servers for site $SiteName" "INFO"
    
    try {
        $servers = Import-Clixml -Path $ServerFile
        Write-Log "Found $($servers.Count) servers to import for site $SiteName" "INFO"
        
        foreach ($server in $servers) {
            $serverName = $server.ServerName
            
            # Check if server already exists
            $existingServer = Get-PvsServer -ServerName $serverName -SiteName $SiteName -ErrorAction SilentlyContinue
            
            if ($existingServer) {
                Write-Log "Server '$serverName' already exists in site '$SiteName', updating configuration" "WARNING"
                if (!$WhatIf) {
                    # Update server properties
                    $updateParams = @{
                        ServerName = $serverName
                        SiteName = $SiteName
                    }
                    
                    # Add other properties that can be updated
                    if ($server.Description) { $updateParams.Add("Description", $server.Description) }
                    if ($server.AdMaxPasswordAge -ne $null) { $updateParams.Add("AdMaxPasswordAge", $server.AdMaxPasswordAge) }
                    if ($server.LogLevel -ne $null) { $updateParams.Add("LogLevel", $server.LogLevel) }
                    
                    Set-PvsServer @updateParams
                    Write-Log "Updated Server '$serverName' in Site '$SiteName'" "SUCCESS"
                } else {
                    Write-Log "WhatIf: Would update Server '$serverName' in Site '$SiteName'" "INFO"
                }
            } else {
                if (!$WhatIf) {
                    # Create new server
                    $newParams = @{
                        ServerName = $serverName
                        SiteName = $SiteName
                    }
                    
                    # Add other properties
                    if ($server.Description) { $newParams.Add("Description", $server.Description) }
                    
                    New-PvsServer @newParams
                    Write-Log "Added Server '$serverName' to Site '$SiteName'" "SUCCESS"
                } else {
                    Write-Log "WhatIf: Would add Server '$serverName' to Site '$SiteName'" "INFO"
                }
            }
        }
    }
    catch {
        Write-Log "Error importing PVS Servers for site $SiteName: $_" "ERROR"
    }
}

# Function to import PVS Store configuration
function Import-PVSStores {
    Write-Log "Starting import of PVS Store configuration" "INFO"
    
    $storeFile = Join-Path -Path $ImportFolder -ChildPath "Stores.xml"
    if (!(Test-Path -Path $storeFile)) {
        Write-Log "Store configuration file not found: $storeFile" "ERROR"
        return
    }
    
    try {
        $stores = Import-Clixml -Path $storeFile
        Write-Log "Found $($stores.Count) stores to import" "INFO"
        
        foreach ($store in $stores) {
            $storeName = $store.StoreName
            $siteName = $store.SiteName
            
            # Check if store already exists
            $existingStore = Get-PvsStore -StoreName $storeName -SiteName $siteName -ErrorAction SilentlyContinue
            
            if ($existingStore) {
                Write-Log "Store '$storeName' already exists in site '$siteName', updating configuration" "WARNING"
                if (!$WhatIf) {
                    # Update store properties
                    $updateParams = @{
                        StoreName = $storeName
                        SiteName = $siteName
                    }
                    
                    # Add other properties that can be updated
                    if ($store.Description) { $updateParams.Add("Description", $store.Description) }
                    if ($store.Path) { $updateParams.Add("Path", $store.Path) }
                    if ($store.CachePath) { $updateParams.Add("CachePath", $store.CachePath) }
                    
                    Set-PvsStore @updateParams
                    Write-Log "Updated Store '$storeName' in Site '$siteName'" "SUCCESS"
                } else {
                    Write-Log "WhatIf: Would update Store '$storeName' in Site '$siteName'" "INFO"
                }
            } else {
                if (!$WhatIf) {
                    # Create new store
                    $newParams = @{
                        StoreName = $storeName
                        SiteName = $siteName
                    }
                    
                    # Add other properties
                    if ($store.Description) { $newParams.Add("Description", $store.Description) }
                    if ($store.Path) { $newParams.Add("Path", $store.Path) }
                    if ($store.CachePath) { $newParams.Add("CachePath", $store.CachePath) }
                    
                    New-PvsStore @newParams
                    Write-Log "Created new Store '$storeName' in Site '$siteName'" "SUCCESS"
                } else {
                    Write-Log "WhatIf: Would create new Store '$storeName' in Site '$siteName'" "INFO"
                }
            }
        }
    }
    catch {
        Write-Log "Error importing PVS Stores: $_" "ERROR"
    }
}

# Function to import PVS Collection configuration
function Import-PVSCollections {
    Write-Log "Starting import of PVS Collection configuration" "INFO"
    
    $sites = Get-PvsSite
    foreach ($site in $sites) {
        $siteName = $site.SiteName
        $collectionFile = Join-Path -Path $ImportFolder -ChildPath "Collections_$($siteName).xml"
        
        if (!(Test-Path -Path $collectionFile)) {
            Write-Log "Collection configuration file not found for site $siteName: $collectionFile" "WARNING"
            continue
        }
        
        try {
            $collections = Import-Clixml -Path $collectionFile
            Write-Log "Found $($collections.Count) collections to import for site $siteName" "INFO"
            
            foreach ($collection in $collections) {
                $collectionName = $collection.CollectionName
                
                # Check if collection already exists
                $existingCollection = Get-PvsCollection -CollectionName $collectionName -SiteName $siteName -ErrorAction SilentlyContinue
                
                if ($existingCollection) {
                    Write-Log "Collection '$collectionName' already exists in site '$siteName', updating configuration" "WARNING"
                    if (!$WhatIf) {
                        # Update collection properties
                        $updateParams = @{
                            CollectionName = $collectionName
                            SiteName = $siteName
                        }
                        
                        # Add other properties that can be updated
                        if ($collection.Description) { $updateParams.Add("Description", $collection.Description) }
                        if ($collection.TemplateDeviceName) { $updateParams.Add("TemplateDeviceName", $collection.TemplateDeviceName) }
                        if ($collection.AutoAddNumberLength -ne $null) { $updateParams.Add("AutoAddNumberLength", $collection.AutoAddNumberLength) }
                        
                        Set-PvsCollection @updateParams
                        Write-Log "Updated Collection '$collectionName' in Site '$siteName'" "SUCCESS"
                    } else {
                        Write-Log "WhatIf: Would update Collection '$collectionName' in Site '$siteName'" "INFO"
                    }
                } else {
                    if (!$WhatIf) {
                        # Create new collection
                        $newParams = @{
                            CollectionName = $collectionName
                            SiteName = $siteName
                        }
                        
                        # Add other properties
                        if ($collection.Description) { $newParams.Add("Description", $collection.Description) }
                        if ($collection.TemplateDeviceName) { $newParams.Add("TemplateDeviceName", $collection.TemplateDeviceName) }
                        
                        New-PvsCollection @newParams
                        Write-Log "Created new Collection '$collectionName' in Site '$siteName'" "SUCCESS"
                    } else {
                        Write-Log "WhatIf: Would create new Collection '$collectionName' in Site '$siteName'" "INFO"
                    }
                }
            }
        }
        catch {
            Write-Log "Error importing PVS Collections for site $siteName: $_" "ERROR"
        }
    }
}

# Function to import PVS vDisk configuration
function Import-PVSvDisks {
    Write-Log "Starting import of PVS vDisk configuration" "INFO"
    
    $vDiskFile = Join-Path -Path $ImportFolder -ChildPath "vDisks.xml"
    if (!(Test-Path -Path $vDiskFile)) {
        Write-Log "vDisk configuration file not found: $vDiskFile" "ERROR"
        return
    }
    
    try {
        $vDisks = Import-Clixml -Path $vDiskFile
        Write-Log "Found $($vDisks.Count) vDisks to import" "INFO"
        
        foreach ($vDisk in $vDisks) {
            $diskLocatorName = $vDisk.Name
            $siteName = $vDisk.SiteName
            $storeName = $vDisk.StoreName
            
            # Check if vDisk already exists
            $existingDisk = Get-PvsDiskInfo -Name $diskLocatorName -SiteName $siteName -StoreName $storeName -ErrorAction SilentlyContinue
            
            if ($existingDisk) {
                Write-Log "vDisk '$diskLocatorName' already exists in store '$storeName', updating configuration" "WARNING"
                if (!$WhatIf) {
                    # Update vDisk properties
                    $updateParams = @{
                        Name = $diskLocatorName
                        SiteName = $siteName
                        StoreName = $storeName
                    }
                    
                    # Add other properties that can be updated
                    if ($vDisk.Description) { $updateParams.Add("Description", $vDisk.Description) }
                    if ($vDisk.MenuText) { $updateParams.Add("MenuText", $vDisk.MenuText) }
                    if ($vDisk.Enabled -ne $null) { $updateParams.Add("Enabled", $vDisk.Enabled) }
                    if ($vDisk.WriteCacheType -ne $null) { $updateParams.Add("WriteCacheType", $vDisk.WriteCacheType) }
                    
                    Set-PvsDiskInfo @updateParams
                    Write-Log "Updated vDisk '$diskLocatorName' in Store '$storeName'" "SUCCESS"
                } else {
                    Write-Log "WhatIf: Would update vDisk '$diskLocatorName' in Store '$storeName'" "INFO"
                }
            } else {
                Write-Log "vDisk '$diskLocatorName' not found in store '$storeName'. Note: vDisks need to be manually added with their VHD/VHDX files" "WARNING"
            }
        }
        
        # Import vDisk versions if available
        $vDiskVersionFile = Join-Path -Path $ImportFolder -ChildPath "vDiskVersions.xml"
        if (Test-Path -Path $vDiskVersionFile) {
            try {
                $vDiskVersions = Import-Clixml -Path $vDiskVersionFile
                Write-Log "Found $($vDiskVersions.Count) vDisk versions to import" "INFO"
                Write-Log "Note: vDisk versions are informational only and cannot be automatically imported" "WARNING"
            }
            catch {
                Write-Log "Error importing vDisk versions: $_" "ERROR"
            }
        }
    }
    catch {
        Write-Log "Error importing PVS vDisks: $_" "ERROR"
    }
}

# Function to import PVS Views configuration
function Import-PVSViews {
    Write-Log "Starting import of PVS Views configuration" "INFO"
    
    $viewFile = Join-Path -Path $ImportFolder -ChildPath "Views.xml"
    if (!(Test-Path -Path $viewFile)) {
        Write-Log "Views configuration file not found: $viewFile" "ERROR"
        return
    }
    
    try {
        $views = Import-Clixml -Path $viewFile
        Write-Log "Found $($views.Count) views to import" "INFO"
        
        foreach ($view in $views) {
            $viewName = $view.ViewName
            
            # Check if view already exists
            $existingView = Get-PvsView -ViewName $viewName -ErrorAction SilentlyContinue
            
            if ($existingView) {
                Write-Log "View '$viewName' already exists, updating configuration" "WARNING"
                if (!$WhatIf) {
                    # Update view properties
                    $updateParams = @{
                        ViewName = $viewName
                    }
                    
                    # Add other properties that can be updated
                    if ($view.Description) { $updateParams.Add("Description", $view.Description) }
                    if ($view.Fields) { $updateParams.Add("Fields", $view.Fields) }
                    
                    Set-PvsView @updateParams
                    Write-Log "Updated View '$viewName'" "SUCCESS"
                } else {
                    Write-Log "WhatIf: Would update View '$viewName'" "INFO"
                }
            } else {
                if (!$WhatIf) {
                    # Create new view
                    $newParams = @{
                        ViewName = $viewName
                    }
                    
                    # Add other properties
                    if ($view.Description) { $newParams.Add("Description", $view.Description) }
                    if ($view.Fields) { $newParams.Add("Fields", $view.Fields) }
                    
                    New-PvsView @newParams
                    Write-Log "Created new View '$viewName'" "SUCCESS"
                } else {
                    Write-Log "WhatIf: Would create new View '$viewName'" "INFO"
                }
            }
        }
    }
    catch {
        Write-Log "Error importing PVS Views: $_" "ERROR"
    }
}

# Function to import PVS Device configuration
function Import-PVSDevices {
    Write-Log "Starting import of PVS Device configuration" "INFO"
    
    $sites = Get-PvsSite
    foreach ($site in $sites) {
        $siteName = $site.SiteName
        $deviceFile = Join-Path -Path $ImportFolder -ChildPath "Devices_$($siteName).xml"
        
        if (!(Test-Path -Path $deviceFile)) {
            Write-Log "Device configuration file not found for site $siteName: $deviceFile" "WARNING"
            continue
        }
        
        try {
            $devices = Import-Clixml -Path $deviceFile
            Write-Log "Found $($devices.Count) devices to import for site $siteName" "INFO"
            
            foreach ($device in $devices) {
                $deviceName = $device.DeviceName
                $collectionName = $device.CollectionName
                
                # Check if device already exists
                $existingDevice = Get-PvsDevice -DeviceName $deviceName -SiteName $siteName -ErrorAction SilentlyContinue
                
                if ($existingDevice) {
                    Write-Log "Device '$deviceName' already exists in site '$siteName', updating configuration" "WARNING"
                    if (!$WhatIf) {
                        # Update device properties
                        $updateParams = @{
                            DeviceName = $deviceName
                            SiteName = $siteName
                        }
                        
                        # Add other properties that can be updated
                        if ($device.Description) { $updateParams.Add("Description", $device.Description) }
                        if ($device.CollectionName) { $updateParams.Add("CollectionName", $device.CollectionName) }
                        if ($device.DiskLocatorName) { $updateParams.Add("DiskLocatorName", $device.DiskLocatorName) }
                        if ($device.StoreName) { $updateParams.Add("StoreName", $device.StoreName) }
                        if ($device.BootFrom -ne $null) { $updateParams.Add("BootFrom", $device.BootFrom) }
                        if ($device.Active -ne $null) { $updateParams.Add("Active", $device.Active) }
                        
                        Set-PvsDevice @updateParams
                        Write-Log "Updated Device '$deviceName' in Site '$siteName'" "SUCCESS"
                    } else {
                        Write-Log "WhatIf: Would update Device '$deviceName' in Site '$siteName'" "INFO"
                    }
                } else {
                    if (!$WhatIf) {
                        # Ensure collection exists first
                        $collection = Get-PvsCollection -CollectionName $collectionName -SiteName $siteName -ErrorAction SilentlyContinue
                        if (!$collection) {
                            Write-Log "Collection '$collectionName' not found in site '$siteName', cannot add device '$deviceName'" "ERROR"
                            continue
                        }
                        
                        # Create new device
                        $newParams = @{
                            DeviceName = $deviceName
                            SiteName = $siteName
                            CollectionName = $collectionName
                        }
                        
                        # Add other properties
                        if ($device.Description) { $newParams.Add("Description", $device.Description) }
                        if ($device.DiskLocatorName) { $newParams.Add("DiskLocatorName", $device.DiskLocatorName) }
                        if ($device.StoreName) { $newParams.Add("StoreName", $device.StoreName) }
                        if ($device.MAC) { $newParams.Add("DeviceMac", $device.MAC) }
                        
                        New-PvsDevice @newParams
                        Write-Log "Created new Device '$deviceName' in Collection '$collectionName' in Site '$siteName'" "SUCCESS"
                    } else {
                        Write-Log "WhatIf: Would create new Device '$deviceName' in Collection '$collectionName' in Site '$siteName'" "INFO"
                    }
                }
            }
        }
        catch {
            Write-Log "Error importing PVS Devices for site $siteName: $_" "ERROR"
        }
    }
}