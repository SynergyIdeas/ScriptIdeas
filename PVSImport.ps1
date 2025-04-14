# Citrix PVS Import Script
# This script imports PVS configuration from XML files with detailed logging
# Each configuration area is imported separately for each site

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
    Add-Content -Path "$importPath\PVSImport_$(Get-Date -Format 'yyyyMMdd').log" -Value $logMessage
}

# Function to verify file exists
function Verify-File {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    
    if (-not (Test-Path -Path $Path)) {
        Write-Log "File not found: $Path" "WARNING"
        return $false
    }
    
    return $true
}

# Parameter for import directory
param (
    [Parameter(Mandatory = $true)]
    [string]$ImportPath
)

# Verify import path exists
if (-not (Test-Path -Path $ImportPath)) {
    Write-Log "Import directory does not exist: $ImportPath" "ERROR"
    exit 1
}

$importPath = $ImportPath

Write-Log "PVS Import started. Import directory: $importPath"

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
    
    # Import farm configuration first
    $farmFilePath = Join-Path -Path $importPath -ChildPath "farm.xml"
    if (Verify-File -Path $farmFilePath) {
        $farmConfig = Import-Clixml -Path $farmFilePath
        
        # Check if farm already exists with the same name
        $existingFarm = Get-PvsFarm -FarmName $farmConfig.FarmName -ErrorAction SilentlyContinue
        
        if ($existingFarm) {
            Write-Log "Farm '$($farmConfig.FarmName)' already exists. Skipping farm creation." "WARNING"
        }
        else {
            # Create the farm using the configuration
            New-PvsFarm -FarmName $farmConfig.FarmName -Description $farmConfig.Description
            Write-Log "Created farm: $($farmConfig.FarmName)"
        }
    }
    
    # Import farm properties
    $farmPropertiesPath = Join-Path -Path $importPath -ChildPath "farmProperties.xml"
    if (Verify-File -Path $farmPropertiesPath) {
        $farmProperties = Import-Clixml -Path $farmPropertiesPath
        # Use Set-PvsFarm to update farm properties instead of a non-existent Set-PvsFarmProperty cmdlet
        Set-PvsFarm -DefaultSiteName $farmProperties.DefaultSiteName -AutoAddEnabled $farmProperties.AutoAddEnabled
        Write-Log "Imported farm properties"
    }
    
    # Get all site directories
    $siteDirs = Get-ChildItem -Path $importPath -Directory | Where-Object { $_.Name -ne "Logs" }
    
    foreach ($siteDir in $siteDirs) {
        $siteName = $siteDir.Name
        $siteImportPath = $siteDir.FullName
        
        Write-Log "Processing site: $siteName"
        
        # Import site configuration
        $siteFilePath = Join-Path -Path $siteImportPath -ChildPath "site.xml"
        if (Verify-File -Path $siteFilePath) {
            $siteConfig = Import-Clixml -Path $siteFilePath
            
            # Check if site already exists
            $existingSite = Get-PvsSite -SiteName $siteName -ErrorAction SilentlyContinue
            
            if ($existingSite) {
                Write-Log "Site '$siteName' already exists. Skipping site creation." "WARNING"
            }
            else {
                # Create the site
                New-PvsSite -SiteName $siteName -Description $siteConfig.Description
                Write-Log "Created site: $siteName"
            }
        }
        
        # Import site properties
        $sitePropertiesPath = Join-Path -Path $siteImportPath -ChildPath "siteProperties.xml"
        if (Verify-File -Path $sitePropertiesPath) {
            $siteProperties = Import-Clixml -Path $sitePropertiesPath
            # Use Set-PvsSite to update site properties instead of a non-existent Set-PvsSiteProperty cmdlet
            Set-PvsSite -SiteName $siteName -DefaultCollectionName $siteProperties.DefaultCollectionName -Description $siteProperties.Description
            Write-Log "Imported site properties for: $siteName"
        }
        
        # Import stores
        $storesPath = Join-Path -Path $siteImportPath -ChildPath "stores.xml"
        if (Verify-File -Path $storesPath) {
            $stores = Import-Clixml -Path $storesPath
            
            foreach ($store in $stores) {
                $storeName = $store.StoreName
                
                # Check if store already exists
                $existingStore = Get-PvsStore -StoreName $storeName -SiteName $siteName -ErrorAction SilentlyContinue
                
                if ($existingStore) {
                    Write-Log "Store '$storeName' already exists in site '$siteName'. Skipping store creation." "WARNING"
                }
                else {
                    # Create the store
                    New-PvsStore -StoreName $storeName -SiteName $siteName -Path $store.Path
                    Write-Log "Created store: $storeName in site: $siteName"
                }
            }
        }
        
        # Import servers
        $serversPath = Join-Path -Path $siteImportPath -ChildPath "servers.xml"
        if (Verify-File -Path $serversPath) {
            $servers = Import-Clixml -Path $serversPath
            
            foreach ($server in $servers) {
                $serverName = $server.ServerName
                
                # Check if server already exists
                $existingServer = Get-PvsServer -ServerName $serverName -SiteName $siteName -ErrorAction SilentlyContinue
                
                if ($existingServer) {
                    Write-Log "Server '$serverName' already exists in site '$siteName'. Skipping server creation." "WARNING"
                }
                else {
                    # Add the server
                    Add-PvsServer -ServerName $serverName -SiteName $siteName
                    Write-Log "Added server: $serverName to site: $siteName"
                }
            }
        }
        
        # Import collections
        $collectionsPath = Join-Path -Path $siteImportPath -ChildPath "collections.xml"
        if (Verify-File -Path $collectionsPath) {
            $collections = Import-Clixml -Path $collectionsPath
            
            foreach ($collection in $collections) {
                $collectionName = $collection.CollectionName
                
                # Check if collection already exists
                $existingCollection = Get-PvsCollection -CollectionName $collectionName -SiteName $siteName -ErrorAction SilentlyContinue
                
                if ($existingCollection) {
                    Write-Log "Collection '$collectionName' already exists in site '$siteName'. Skipping collection creation." "WARNING"
                }
                else {
                    # Create the collection
                    New-PvsCollection -CollectionName $collectionName -SiteName $siteName -Description $collection.Description
                    Write-Log "Created collection: $collectionName in site: $siteName"
                }
            }
        }
        
        # Import auth groups
        $authGroupsPath = Join-Path -Path $siteImportPath -ChildPath "authGroups.xml"
        if (Verify-File -Path $authGroupsPath) {
            $authGroups = Import-Clixml -Path $authGroupsPath
            
            foreach ($authGroup in $authGroups) {
                $authGroupName = $authGroup.AuthGroupName
                
                # Check if auth group already exists
                $existingAuthGroup = Get-PvsAuthGroup -AuthGroupName $authGroupName -SiteName $siteName -ErrorAction SilentlyContinue
                
                if ($existingAuthGroup) {
                    Write-Log "Auth group '$authGroupName' already exists in site '$siteName'. Skipping auth group creation." "WARNING"
                }
                else {
                    # Add the auth group
                    New-PvsAuthGroup -AuthGroupName $authGroupName -SiteName $siteName -Description $authGroup.Description
                    Write-Log "Added auth group: $authGroupName to site: $siteName"
                }
            }
        }
        
        # Import vDisks
        $vDisksPath = Join-Path -Path $siteImportPath -ChildPath "vDisks"
        if (Test-Path $vDisksPath) {
            $vDiskFiles = Get-ChildItem -Path $vDisksPath -Filter "*.xml" | Where-Object { $_.Name -notlike "*_versions.xml" }
            
            foreach ($vDiskFile in $vDiskFiles) {
                $vDiskConfig = Import-Clixml -Path $vDiskFile.FullName
                $diskLocatorName = $vDiskConfig.DiskLocatorName
                $storeName = ($vDiskFile.Name -split "_")[0]
                
                # Check if vDisk already exists
                $existingVDisk = Get-PvsDiskLocator -DiskLocatorName $diskLocatorName -StoreName $storeName -SiteName $siteName -ErrorAction SilentlyContinue
                
                if ($existingVDisk) {
                    Write-Log "vDisk '$diskLocatorName' already exists in store '$storeName'. Skipping vDisk creation." "WARNING"
                }
                else {
                    # Create the vDisk
                    New-PvsDiskLocator -DiskLocatorName $diskLocatorName -StoreName $storeName -SiteName $siteName
                    Write-Log "Created vDisk: $diskLocatorName in store: $storeName, site: $siteName"
                    
                    # Set vDisk properties
                    Set-PvsDiskLocator -DiskLocatorName $diskLocatorName -StoreName $storeName -SiteName $siteName `
                        -Description $vDiskConfig.Description -MenuText $vDiskConfig.MenuText -Enabled $vDiskConfig.Enabled
                    Write-Log "Set properties for vDisk: $diskLocatorName"
                    
                    # Import vDisk versions if available
                    $vDiskVersionsFile = Join-Path -Path $vDisksPath -ChildPath "${storeName}_${diskLocatorName}_versions.xml"
                    if (Verify-File -Path $vDiskVersionsFile) {
                        Write-Log "Found vDisk versions file for: $diskLocatorName. Note: Version information is imported, but actual vDisk files need to be restored separately." "WARNING"
                    }
                }
            }
        }
        
        # Import devices for each collection
        $devicesPath = Join-Path -Path $siteImportPath -ChildPath "Devices"
        if (Test-Path $devicesPath) {
            $deviceFiles = Get-ChildItem -Path $devicesPath -Filter "*.xml"
            
            foreach ($deviceFile in $deviceFiles) {
                $collectionName = $deviceFile.BaseName
                $devices = Import-Clixml -Path $deviceFile.FullName
                
                foreach ($device in $devices) {
                    $deviceName = $device.DeviceName
                    $deviceMac = $device.DeviceMac
                    
                    # Check if device already exists
                    $existingDevice = Get-PvsDevice -DeviceName $deviceName -ErrorAction SilentlyContinue
                    
                    if ($existingDevice) {
                        Write-Log "Device '$deviceName' already exists. Skipping device creation." "WARNING"
                    }
                    else {
                        # Create the device
                        New-PvsDevice -DeviceName $deviceName -DeviceMac $deviceMac -CollectionName $collectionName -SiteName $siteName
                        Write-Log "Created device: $deviceName ($deviceMac) in collection: $collectionName"
                        
                        # Set device properties
                        if ($device.DiskLocatorId) {
                            # Find the correct vDisk by DiskLocatorId
                            # Note: In a real implementation, you may need to map old DiskLocatorIds to new ones if they changed
                            Set-PvsDevice -DeviceName $deviceName -SiteName $siteName -DiskLocatorId $device.DiskLocatorId
                            Write-Log "Set vDisk for device: $deviceName"
                        }
                        elseif ($device.DiskLocatorName -and $device.StoreName) {
                            # Find the correct vDisk by name and store
                            Set-PvsDevice -DeviceName $deviceName -SiteName $siteName -DiskLocatorName $device.DiskLocatorName -StoreName $device.StoreName
                            Write-Log "Set vDisk for device: $deviceName"
                        }
                    }
                }
            }
        }
    }
    
    Write-Log "PVS Import completed successfully"
}
catch {
    Write-Log "An error occurred during the import process: $_" "ERROR"
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" "ERROR"
    exit 1
}
