# Citrix PVS Configuration Import Script
# This script imports a previously exported Citrix Provisioning Services configuration from XML files

param (
    [Parameter(Mandatory=$true)]
    [string]$ImportPath,
    
    [Parameter(Mandatory=$false)]
    [switch]$ForceOverwrite = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipConfirmation = $false
)

# Set up logging
$logFile = "C:\PVSImport\PVSImport_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Create log directory if it doesn't exist
if (!(Test-Path "C:\PVSImport")) {
    New-Item -Path "C:\PVSImport" -ItemType Directory -Force | Out-Null
}

# Function for logging
function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timeStamp - [$Level] - $Message" | Out-File -FilePath $logFile -Append
    
    switch ($Level) {
        "ERROR" { Write-Host "$timeStamp - $Message" -ForegroundColor Red }
        "WARNING" { Write-Host "$timeStamp - $Message" -ForegroundColor Yellow }
        "SUCCESS" { Write-Host "$timeStamp - $Message" -ForegroundColor Green }
        default { Write-Host "$timeStamp - $Message" }
    }
}

Write-Log "Starting Citrix PVS configuration import from: $ImportPath"

# Check if ImportPath exists
if (!(Test-Path $ImportPath)) {
    Write-Log "ERROR: Import path $ImportPath does not exist" -Level "ERROR"
    exit 1
}

# Check for PVS PowerShell snap-in
try {
    if (!(Get-PSSnapin -Name Citrix.PVS.SnapIn -ErrorAction SilentlyContinue)) {
        Add-PSSnapin Citrix.PVS.SnapIn
        Write-Log "Added Citrix PVS SnapIn"
    }
}
catch {
    Write-Log "ERROR: Failed to load Citrix PVS SnapIn. Is PVS Console installed? Error: $_" -Level "ERROR"
    exit 1
}

# Function to prompt for confirmation
function Get-Confirmation {
    param (
        [string]$Message
    )
    
    if ($SkipConfirmation) {
        return $true
    }
    
    $confirmation = Read-Host "$Message (Y/N)"
    return $confirmation -eq "Y" -or $confirmation -eq "y"
}

# Import Farm configuration
function Import-PVSFarm {
    $farmFile = Join-Path $ImportPath "Farm.xml"
    
    if (!(Test-Path $farmFile)) {
        Write-Log "WARNING: Farm configuration file not found at $farmFile" -Level "WARNING"
        return
    }
    
    try {
        $existingFarm = Get-PvsFarm
        
        if ($existingFarm -and !$ForceOverwrite) {
            $proceed = Get-Confirmation "A PVS Farm already exists. Do you want to proceed with importing farm settings?"
            
            if (!$proceed) {
                Write-Log "Farm import skipped by user"
                return
            }
        }
        
        $farmConfig = Import-Clixml -Path $farmFile
        Write-Log "Imported farm configuration data from $farmFile"
        
        # We can't recreate a farm, but we can update its properties
        Set-PvsFarm -FarmName $farmConfig.FarmName -Description $farmConfig.Description
        Write-Log "Updated Farm properties" -Level "SUCCESS"
    }
    catch {
        Write-Log "ERROR: Failed to import farm configuration: $_" -Level "ERROR"
    }
}

# Import Sites
function Import-PVSSites {
    $sitesFile = Join-Path $ImportPath "Sites.xml"
    
    if (!(Test-Path $sitesFile)) {
        Write-Log "WARNING: Sites configuration file not found at $sitesFile" -Level "WARNING"
        return
    }
    
    try {
        $sitesConfig = Import-Clixml -Path $sitesFile
        Write-Log "Imported sites configuration data from $sitesFile"
        
        foreach ($site in $sitesConfig) {
            $siteName = $site.SiteName
            $existingSite = Get-PvsSite -SiteName $siteName -ErrorAction SilentlyContinue
            
            if ($existingSite) {
                Write-Log "Site '$siteName' already exists"
                
                if ($ForceOverwrite) {
                    Set-PvsSite -SiteName $siteName -Description $site.Description
                    Write-Log "Updated Site '$siteName' properties" -Level "SUCCESS"
                }
            }
            else {
                New-PvsSite -SiteName $siteName -Description $site.Description
                Write-Log "Created new Site: '$siteName'" -Level "SUCCESS"
            }
        }
    }
    catch {
        Write-Log "ERROR: Failed to import sites configuration: $_" -Level "ERROR"
    }
}

# Import Stores
function Import-PVSStores {
    $storesFile = Join-Path $ImportPath "Stores.xml"
    
    if (!(Test-Path $storesFile)) {
        Write-Log "WARNING: Stores configuration file not found at $storesFile" -Level "WARNING"
        return
    }
    
    try {
        $storesConfig = Import-Clixml -Path $storesFile
        Write-Log "Imported stores configuration data from $storesFile"
        
        foreach ($store in $storesConfig) {
            $storeName = $store.StoreName
            $existingStore = Get-PvsStore -StoreName $storeName -ErrorAction SilentlyContinue
            
            if ($existingStore) {
                Write-Log "Store '$storeName' already exists"
                
                if ($ForceOverwrite) {
                    Set-PvsStore -StoreName $storeName -Path $store.Path -Description $store.Description
                    Write-Log "Updated Store '$storeName' properties" -Level "SUCCESS"
                }
            }
            else {
                New-PvsStore -StoreName $storeName -Path $store.Path -Description $store.Description
                Write-Log "Created new Store: '$storeName'" -Level "SUCCESS"
            }
        }
    }
    catch {
        Write-Log "ERROR: Failed to import stores configuration: $_" -Level "ERROR"
    }
}

# Import Servers
function Import-PVSServers {
    $serversFile = Join-Path $ImportPath "Servers.xml"
    
    if (!(Test-Path $serversFile)) {
        Write-Log "WARNING: Servers configuration file not found at $serversFile" -Level "WARNING"
        return
    }
    
    try {
        $serversConfig = Import-Clixml -Path $serversFile
        Write-Log "Imported servers configuration data from $serversFile"
        
        foreach ($server in $serversConfig) {
            $serverName = $server.ServerName
            $siteName = $server.SiteName
            $existingServer = Get-PvsServer -ServerName $serverName -SiteName $siteName -ErrorAction SilentlyContinue
            
            if ($existingServer) {
                Write-Log "Server '$serverName' already exists in site '$siteName'"
                
                if ($ForceOverwrite) {
                    # Update server properties as needed
                    Set-PvsServer -ServerName $serverName -SiteName $siteName -Description $server.Description
                    Write-Log "Updated Server '$serverName' properties" -Level "SUCCESS"
                }
            }
            else {
                # Check if this is the current server, if so add it to the site
                if ($serverName -eq [System.Net.Dns]::GetHostName()) {
                    Add-PvsServerToSite -ServerName $serverName -SiteName $siteName
                    Set-PvsServer -ServerName $serverName -SiteName $siteName -Description $server.Description
                    Write-Log "Added current server '$serverName' to site '$siteName'" -Level "SUCCESS"
                }
                else {
                    Write-Log "Server '$serverName' not found in the farm and is not the current server. Cannot add remote servers." -Level "WARNING"
                }
            }
        }
    }
    catch {
        Write-Log "ERROR: Failed to import servers configuration: $_" -Level "ERROR"
    }
}

# Import Collections for each Site
function Import-PVSCollections {
    $sites = Get-PvsSite
    
    foreach ($site in $sites) {
        $siteName = $site.SiteName
        $collectionsFile = Join-Path $ImportPath "Collections_$siteName.xml"
        
        if (!(Test-Path $collectionsFile)) {
            Write-Log "WARNING: Collections file not found for site '$siteName' at $collectionsFile" -Level "WARNING"
            continue
        }
        
        try {
            $collectionsConfig = Import-Clixml -Path $collectionsFile
            Write-Log "Imported collections configuration data for site '$siteName'"
            
            foreach ($collection in $collectionsConfig) {
                $collectionName = $collection.CollectionName
                $existingCollection = Get-PvsCollection -CollectionName $collectionName -SiteName $siteName -ErrorAction SilentlyContinue
                
                if ($existingCollection) {
                    Write-Log "Collection '$collectionName' already exists in site '$siteName'"
                    
                    if ($ForceOverwrite) {
                        Set-PvsCollection -CollectionName $collectionName -SiteName $siteName -Description $collection.Description
                        Write-Log "Updated Collection '$collectionName' properties" -Level "SUCCESS"
                    }
                }
                else {
                    New-PvsCollection -CollectionName $collectionName -SiteName $siteName -Description $collection.Description
                    Write-Log "Created new Collection: '$collectionName' in site '$siteName'" -Level "SUCCESS"
                }
            }
        }
        catch {
            Write-Log "ERROR: Failed to import collections for site '$siteName': $_" -Level "ERROR"
        }
    }
}

# Import vDisks for each Site
function Import-PVSvDisks {
    $sites = Get-PvsSite
    
    foreach ($site in $sites) {
        $siteName = $site.SiteName
        $vDisksFile = Join-Path $ImportPath "vDisks_$siteName.xml"
        
        if (!(Test-Path $vDisksFile)) {
            Write-Log "WARNING: vDisks file not found for site '$siteName' at $vDisksFile" -Level "WARNING"
            continue
        }
        
        try {
            $vDisksConfig = Import-Clixml -Path $vDisksFile
            Write-Log "Imported vDisks configuration data for site '$siteName'"
            
            # Note: This only imports vDisk metadata. The actual vDisk files must exist in the store path
            Write-Log "WARNING: The actual vDisk files must exist in the appropriate store paths. This script only imports the vDisk metadata." -Level "WARNING"
            
            foreach ($vDisk in $vDisksConfig) {
                $vDiskName = $vDisk.Name
                $storeName = $vDisk.StoreName
                
                $existingvDisk = Get-PvsDiskInfo -Name $vDiskName -StoreName $storeName -SiteName $siteName -ErrorAction SilentlyContinue
                
                if ($existingvDisk) {
                    Write-Log "vDisk '$vDiskName' already exists in store '$storeName'"
                    
                    if ($ForceOverwrite) {
                        # Update vDisk properties
                        Set-PvsDisk -Name $vDiskName -StoreName $storeName -SiteName $siteName -Description $vDisk.Description
                        Write-Log "Updated vDisk '$vDiskName' properties" -Level "SUCCESS"
                    }
                }
                else {
                    # Note: New-PvsDiskLocator is used for importing existing vDisks
                    Write-Log "vDisk '$vDiskName' needs to be created with New-PvsDiskLocator. Verify the vDisk file exists in the store path." -Level "WARNING"
                    # This is tricky because it requires the physical vDisk file to exist
                }
            }
        }
        catch {
            Write-Log "ERROR: Failed to import vDisks for site '$siteName': $_" -Level "ERROR"
        }
    }
}

# Import Devices for each Collection
function Import-PVSDevices {
    $sites = Get-PvsSite
    
    foreach ($site in $sites) {
        $siteName = $site.SiteName
        $collections = Get-PvsCollection -SiteName $siteName
        
        foreach ($collection in $collections) {
            $collectionName = $collection.CollectionName
            $devicesFile = Join-Path $ImportPath "Devices_${siteName}_${collectionName}.xml"
            
            if (!(Test-Path $devicesFile)) {
                Write-Log "WARNING: Devices file not found for collection '$collectionName' in site '$siteName' at $devicesFile" -Level "WARNING"
                continue
            }
            
            try {
                $devicesConfig = Import-Clixml -Path $devicesFile
                Write-Log "Imported devices configuration data for collection '$collectionName' in site '$siteName'"
                
                foreach ($device in $devicesConfig) {
                    $deviceName = $device.DeviceName
                    $deviceMac = $device.DeviceMac
                    
                    $existingDevice = Get-PvsDevice -DeviceName $deviceName -SiteName $siteName -ErrorAction SilentlyContinue
                    
                    if ($existingDevice) {
                        Write-Log "Device '$deviceName' already exists in site '$siteName'"
                        
                        if ($ForceOverwrite) {
                            # Update device properties
                            Set-PvsDevice -DeviceName $deviceName -Description $device.Description
                            Write-Log "Updated Device '$deviceName' properties" -Level "SUCCESS"
                        }
                    }
                    else {
                        # Create new device
                        New-PvsDevice -DeviceName $deviceName -DeviceMac $deviceMac -CollectionName $collectionName -SiteName $siteName -Description $device.Description
                        Write-Log "Created new Device: '$deviceName' in collection '$collectionName'" -Level "SUCCESS"
                        
                        # If the device had an assigned vDisk, assign it
                        if ($device.DiskLocatorName) {
                            try {
                                Set-PvsDeviceBootstrap -DeviceName $deviceName -DiskLocatorName $device.DiskLocatorName -SiteName $siteName
                                Write-Log "Assigned vDisk '$($device.DiskLocatorName)' to device '$deviceName'" -Level "SUCCESS"
                            }
                            catch {
                                Write-Log "WARNING: Failed to assign vDisk to device '$deviceName': $_" -Level "WARNING"
                            }
                        }
                    }
                }
            }
            catch {
                Write-Log "ERROR: Failed to import devices for collection '$collectionName' in site '$siteName': $_" -Level "ERROR"
            }
        }
    }
}

# Import SiteViews
function Import-PVSSiteViews {
    $siteViewsFile = Join-Path $ImportPath "SiteViews.xml"
    
    if (!(Test-Path $siteViewsFile)) {
        Write-Log "WARNING: SiteViews configuration file not found at $siteViewsFile" -Level "WARNING"
        return
    }
    
    try {
        $siteViewsConfig = Import-Clixml -Path $siteViewsFile
        Write-Log "Imported SiteViews configuration data from $siteViewsFile"
        
        foreach ($siteView in $siteViewsConfig) {
            $siteViewName = $siteView.SiteViewName
            $siteName = $siteView.SiteName
            
            $existingSiteView = Get-PvsSiteView -SiteViewName $siteViewName -SiteName $siteName -ErrorAction SilentlyContinue
            
            if ($existingSiteView) {
                Write-Log "SiteView '$siteViewName' already exists in site '$siteName'"
                
                if ($ForceOverwrite) {
                    # Update site view properties
                    Set-PvsSiteView -SiteViewName $siteViewName -SiteName $siteName -Description $siteView.Description
                    Write-Log "Updated SiteView '$siteViewName' properties" -Level "SUCCESS"
                }
            }
            else {
                # Create new site view
                New-PvsSiteView -SiteViewName $siteViewName -SiteName $siteName -Description $siteView.Description
                Write-Log "Created new SiteView: '$siteViewName' in site '$siteName'" -Level "SUCCESS"
            }
        }
    }
    catch {
        Write-Log "ERROR: Failed to import SiteViews configuration: $_" -Level "ERROR"
    }
}

# Import FarmViews
function Import-PVSFarmViews {
    $farmViewsFile = Join-Path $ImportPath "FarmViews.xml"
    
    if (!(Test-Path $farmViewsFile)) {
        Write-Log "WARNING: FarmViews configuration file not found at $farmViewsFile" -Level "WARNING"
        return
    }
    
    try {
        $farmViewsConfig = Import-Clixml -Path $farmViewsFile
        Write-Log "Imported FarmViews configuration data from $farmViewsFile"
        
        foreach ($farmView in $farmViewsConfig) {
            $farmViewName = $farmView.FarmViewName
            
            $existingFarmView = Get-PvsFarmView -FarmViewName $farmViewName -ErrorAction SilentlyContinue
            
            if ($existingFarmView) {
                Write-Log "FarmView '$farmViewName' already exists"
                
                if ($ForceOverwrite) {
                    # Update farm view properties
                    Set-PvsFarmView -FarmViewName $farmViewName -Description $farmView.Description
                    Write-Log "Updated FarmView '$farmViewName' properties" -Level "SUCCESS"
                }
            }
            else {
                # Create new farm view
                New-PvsFarmView -FarmViewName $farmViewName -Description $farmView.Description
                Write-Log "Created new FarmView: '$farmViewName'" -Level "SUCCESS"
            }
        }
    }
    catch {
        Write-Log "ERROR: Failed to import FarmViews configuration: $_" -Level "ERROR"
    }
}

# Import AuthGroups
function Import-PVSAuthGroups {
    $authGroupsFile = Join-Path $ImportPath "AuthGroups.xml"
    
    if (!(Test-Path $authGroupsFile)) {
        Write-Log "WARNING: AuthGroups configuration file not found at $authGroupsFile" -Level "WARNING"
        return
    }
    
    try {
        $authGroupsConfig = Import-Clixml -Path $authGroupsFile
        Write-Log "Imported AuthGroups configuration data from $authGroupsFile"
        
        foreach ($authGroup in $authGroupsConfig) {
            $authGroupName = $authGroup.AuthGroupName
            
            $existingAuthGroup = Get-PvsAuthGroup -Name $authGroupName -ErrorAction SilentlyContinue
            
            if ($existingAuthGroup) {
                Write-Log "AuthGroup '$authGroupName' already exists"
                
                if ($ForceOverwrite) {
                    # Update auth group properties
                    Set-PvsAuthGroup -Name $authGroupName -Description $authGroup.Description
                    Write-Log "Updated AuthGroup '$authGroupName' properties" -Level "SUCCESS"
                }
            }
            else {
                # Create new auth group
                New-PvsAuthGroup -Name $authGroupName -Description $authGroup.Description
                Write-Log "Created new AuthGroup: '$authGroupName'" -Level "SUCCESS"
            }
        }
    }
    catch {
        Write-Log "ERROR: Failed to import AuthGroups configuration: $_" -Level "ERROR"
    }
}

# Main import function
function Start-PVSImport {
    Write-Log "Beginning PVS import process..." -Level "SUCCESS"
    
    # Import components in dependency order
    Import-PVSFarm
    Import-PVSSites
    Import-PVSStores
    Import-PVSServers
    Import-PVSCollections
    Import-PVSvDisks
    Import-PVSDevices
    Import-PVSSiteViews
    Import-PVSFarmViews
    Import-PVSAuthGroups
    
    Write-Log "PVS import process completed" -Level "SUCCESS"
    Write-Host "Import completed. Check log file for details: $logFile" -ForegroundColor Green
}

# Run the import
Start-PVSImport
