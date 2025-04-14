# Citrix PVS Export Configuration Script
# This script exports Citrix Provisioning Services configurations to a specified location
# Features:
# - Detailed logging
# - Ability to skip sites during export
# - Comprehensive error handling
# - Progress tracking

param (
    [Parameter(Mandatory=$false)]
    [string]$ExportPath = "D:\PVSExport",
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = "D:\PVSExport\Logs",
    
    [Parameter(Mandatory=$false)]
    [string[]]$SkipSites = @(),
    
    [Parameter(Mandatory=$false)]
    [switch]$Interactive = $true
)

# Initialize Script
$ErrorActionPreference = "Stop"
$ScriptStartTime = Get-Date
$LogFile = Join-Path -Path $LogPath -ChildPath "PVSExport_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Ensure Log directory exists
if (-not (Test-Path -Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
}

# Ensure Export directory exists
if (-not (Test-Path -Path $ExportPath)) {
    New-Item -Path $ExportPath -ItemType Directory -Force | Out-Null
}

# Logging Function
function Write-Log {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    
    # Write to console with color based on level
    switch ($Level) {
        "INFO"    { Write-Host $LogMessage -ForegroundColor Cyan }
        "WARNING" { Write-Host $LogMessage -ForegroundColor Yellow }
        "ERROR"   { Write-Host $LogMessage -ForegroundColor Red }
        "SUCCESS" { Write-Host $LogMessage -ForegroundColor Green }
    }
    
    # Write to log file
    Add-Content -Path $LogFile -Value $LogMessage
}

# Import Citrix PVS Snapin
function Import-PVSSnapin {
    try {
        Write-Log "Loading Citrix PVS PowerShell Snapin..." -Level INFO
        Add-PSSnapin Citrix.PVS.SnapIn -ErrorAction Stop
        Write-Log "Citrix PVS PowerShell Snapin loaded successfully." -Level SUCCESS
        return $true
    }
    catch {
        Write-Log "Failed to load Citrix PVS PowerShell Snapin: $_" -Level ERROR
        return $false
    }
}

# Test PVS Connection
function Test-PVSConnection {
    try {
        Write-Log "Testing connection to PVS Farm..." -Level INFO
        $PVSFarm = Get-PvsFarm
        if ($PVSFarm) {
            Write-Log "Successfully connected to PVS Farm: $($PVSFarm.Name)" -Level SUCCESS
            return $true
        }
        else {
            Write-Log "No PVS Farm found." -Level ERROR
            return $false
        }
    }
    catch {
        Write-Log "Failed to connect to PVS Farm: $_" -Level ERROR
        return $false
    }
}

# Export PVS Configuration
function Export-PVSConfiguration {
    Write-Log "Starting PVS configuration export..." -Level INFO
    
    try {
        # Create timestamped export directory
        $ExportTimestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $ExportDir = Join-Path -Path $ExportPath -ChildPath "PVSExport_$ExportTimestamp"
        New-Item -Path $ExportDir -ItemType Directory -Force | Out-Null
        Write-Log "Export directory created: $ExportDir" -Level INFO
        
        # Export Farm Configuration
        Write-Log "Exporting Farm configuration..." -Level INFO
        $Farm = Get-PvsFarm
        $Farm | Export-Clixml -Path (Join-Path -Path $ExportDir -ChildPath "Farm.xml")
        Write-Log "Farm configuration exported successfully." -Level SUCCESS
        
        # Export Sites
        Write-Log "Retrieving all PVS Sites..." -Level INFO
        $Sites = Get-PvsSite
        Write-Log "Found $($Sites.Count) Sites in the Farm." -Level INFO
        
        # If in interactive mode, prompt for each site
        $SitesToExport = @()
        $SitesToSkip = @()

        if ($Interactive) {
            Write-Host "`n=== Site Selection ===" -ForegroundColor Cyan
            Write-Host "Select which sites to export:" -ForegroundColor Cyan
            
            foreach ($Site in $Sites) {
                $SiteName = $Site.SiteName
                
                # Skip sites that were explicitly specified in SkipSites parameter
                if ($SkipSites -contains $SiteName) {
                    Write-Host "Site: $SiteName (Skipped by parameter)" -ForegroundColor Yellow
                    $SitesToSkip += $SiteName
                    continue
                }
                
                $response = ""
                while ($response -notmatch '^[YyNn]
            
            # Export Collections
            Write-Log "Exporting Collections for Site: $($Site.SiteName)" -Level INFO
            $Collections = Get-PvsCollection -SiteName $Site.SiteName
            if ($Collections) {
                $CollectionsDir = Join-Path -Path $SiteDir -ChildPath "Collections"
                New-Item -Path $CollectionsDir -ItemType Directory -Force | Out-Null
                
                foreach ($Collection in $Collections) {
                    Write-Log "Exporting Collection: $($Collection.CollectionName)" -Level INFO
                    $Collection | Export-Clixml -Path (Join-Path -Path $CollectionsDir -ChildPath "$($Collection.CollectionName).xml")
                    
                    # Export Devices in Collection
                    $Devices = Get-PvsDevice -CollectionName $Collection.CollectionName -SiteName $Site.SiteName
                    if ($Devices) {
                        $DevicesDir = Join-Path -Path $CollectionsDir -ChildPath "$($Collection.CollectionName)_Devices"
                        New-Item -Path $DevicesDir -ItemType Directory -Force | Out-Null
                        
                        foreach ($Device in $Devices) {
                            $Device | Export-Clixml -Path (Join-Path -Path $DevicesDir -ChildPath "$($Device.DeviceName).xml")
                        }
                        Write-Log "Exported $($Devices.Count) devices for Collection: $($Collection.CollectionName)" -Level SUCCESS
                    }
                }
                Write-Log "Exported $($Collections.Count) Collections for Site: $($Site.SiteName)" -Level SUCCESS
            }
            
            # Export Stores
            Write-Log "Exporting Stores for Site: $($Site.SiteName)" -Level INFO
            $Stores = Get-PvsStore -SiteName $Site.SiteName
            if ($Stores) {
                $StoresDir = Join-Path -Path $SiteDir -ChildPath "Stores"
                New-Item -Path $StoresDir -ItemType Directory -Force | Out-Null
                
                foreach ($Store in $Stores) {
                    Write-Log "Exporting Store: $($Store.StoreName)" -Level INFO
                    $Store | Export-Clixml -Path (Join-Path -Path $StoresDir -ChildPath "$($Store.StoreName).xml")
                    
                    # Export vDisks in Store
                    try {
                        # First get disk locators, which provide the link between stores and vDisks
                        $DiskLocators = Get-PvsDiskLocator -StoreName $Store.StoreName -SiteName $Site.SiteName -ErrorAction Stop
                        if ($DiskLocators) {
                            $vDisksDir = Join-Path -Path $StoresDir -ChildPath "$($Store.StoreName)_vDisks"
                            New-Item -Path $vDisksDir -ItemType Directory -Force | Out-Null
                            
                            foreach ($DiskLocator in $DiskLocators) {
                                try {
                                    # Get full disk info for each disk locator
                                    $vDisk = Get-PvsDiskInfo -DiskLocatorName $DiskLocator.DiskLocatorName -StoreName $Store.StoreName -SiteName $Site.SiteName -ErrorAction Stop
                                    $vDisk | Export-Clixml -Path (Join-Path -Path $vDisksDir -ChildPath "$($DiskLocator.DiskLocatorName).xml")
                                    
                                    # Export vDisk Versions
                                    $vDiskVersions = Get-PvsDiskVersion -DiskLocatorName $DiskLocator.DiskLocatorName -StoreName $Store.StoreName -SiteName $Site.SiteName -ErrorAction Stop
                                    if ($vDiskVersions) {
                                        $vDiskVersionsDir = Join-Path -Path $vDisksDir -ChildPath "$($DiskLocator.DiskLocatorName)_Versions"
                                        New-Item -Path $vDiskVersionsDir -ItemType Directory -Force | Out-Null
                                        
                                        foreach ($vDiskVersion in $vDiskVersions) {
                                            $vDiskVersion | Export-Clixml -Path (Join-Path -Path $vDiskVersionsDir -ChildPath "v$($vDiskVersion.Version).xml")
                                        }
                                        Write-Log "Exported $($vDiskVersions.Count) versions for vDisk: $($DiskLocator.DiskLocatorName)" -Level SUCCESS
                                    }
                                }
                                catch {
                                    Write-Log "Warning: Failed to export vDisk information for $($DiskLocator.DiskLocatorName): $_" -Level WARNING
                                }
                            }
                            Write-Log "Exported $($DiskLocators.Count) vDisks for Store: $($Store.StoreName)" -Level SUCCESS
                        }
                    }
                    catch {
                        Write-Log "Warning: Failed to export vDisks for Store $($Store.StoreName): $_" -Level WARNING
                    }
                        Write-Log "Exported $($vDisks.Count) vDisks for Store: $($Store.StoreName)" -Level SUCCESS
                    }
                }
                Write-Log "Exported $($Stores.Count) Stores for Site: $($Site.SiteName)" -Level SUCCESS
            }
            
            # Export Servers
            Write-Log "Exporting Servers for Site: $($Site.SiteName)" -Level INFO
            $Servers = Get-PvsServer -SiteName $Site.SiteName
            if ($Servers) {
                $ServersDir = Join-Path -Path $SiteDir -ChildPath "Servers"
                New-Item -Path $ServersDir -ItemType Directory -Force | Out-Null
                
                foreach ($Server in $Servers) {
                    Write-Log "Exporting Server: $($Server.ServerName)" -Level INFO
                    $Server | Export-Clixml -Path (Join-Path -Path $ServersDir -ChildPath "$($Server.ServerName).xml")
                    
                    # Export Server Store access
                    $ServerStores = Get-PvsServerStore -ServerName $Server.ServerName -SiteName $Site.SiteName
                    if ($ServerStores) {
                        $ServerStoresDir = Join-Path -Path $ServersDir -ChildPath "$($Server.ServerName)_Stores"
                        New-Item -Path $ServerStoresDir -ItemType Directory -Force | Out-Null
                        
                        foreach ($ServerStore in $ServerStores) {
                            $ServerStore | Export-Clixml -Path (Join-Path -Path $ServerStoresDir -ChildPath "$($ServerStore.StoreName).xml")
                        }
                        Write-Log "Exported $($ServerStores.Count) store connections for Server: $($Server.ServerName)" -Level SUCCESS
                    }
                }
                Write-Log "Exported $($Servers.Count) Servers for Site: $($Site.SiteName)" -Level SUCCESS
            }
            
            # Export Site properties
            Write-Log "Exporting Site properties for Site: $($Site.SiteName)" -Level INFO
            try {
                # Export AuthGroups
                $AuthGroups = Get-PvsAuthGroup -SiteName $Site.SiteName
                if ($AuthGroups) {
                    $AuthGroupsDir = Join-Path -Path $SiteDir -ChildPath "AuthGroups"
                    New-Item -Path $AuthGroupsDir -ItemType Directory -Force | Out-Null
                    
                    foreach ($AuthGroup in $AuthGroups) {
                        $AuthGroup | Export-Clixml -Path (Join-Path -Path $AuthGroupsDir -ChildPath "$($AuthGroup.AuthGroupName).xml")
                    }
                    Write-Log "Exported $($AuthGroups.Count) authentication groups for Site: $($Site.SiteName)" -Level SUCCESS
                }
            }
            catch {
                Write-Log "Warning: Could not export AuthGroups: $_" -Level WARNING
            }
            
            Write-Log "Completed export for Site: $($Site.SiteName)" -Level SUCCESS
        }
        
        # Export summary file
        $Summary = @{
            ExportTime = $ScriptStartTime
            ExportPath = $ExportDir
            ExportedSites = $SitesToExport
            SkippedSites = $SitesToSkip
            TotalSites = $Sites.Count
            ExportedSitesCount = $SitesToExport.Count
            FarmName = $Farm.FarmName
            InteractiveMode = $Interactive
        }
        
        $Summary | Export-Clixml -Path (Join-Path -Path $ExportDir -ChildPath "ExportSummary.xml")
        
        Write-Log "PVS configuration export completed successfully." -Level SUCCESS
        Write-Log "Export location: $ExportDir" -Level INFO
        
        return $ExportDir
    }
    catch {
        Write-Log "Failed to export PVS configuration: $_" -Level ERROR
        return $null
    }
}

# Main Script Execution
Write-Log "===== PVS Configuration Export Script Started =====" -Level INFO
Write-Log "Export Path: $ExportPath" -Level INFO
if ($Interactive) {
    Write-Log "Running in Interactive Mode - will prompt for each site" -Level INFO
}
elseif ($SkipSites.Count -gt 0) {
    Write-Log "Sites to skip: $($SkipSites -join ', ')" -Level INFO
}

# Load PVS Snapin
if (-not (Import-PVSSnapin)) {
    Write-Log "Failed to load required PVS Snapin. Script terminated." -Level ERROR
    exit 1
}

# Test PVS Connection
if (-not (Test-PVSConnection)) {
    Write-Log "Failed to connect to PVS. Ensure PVS is installed and configured. Script terminated." -Level ERROR
    exit 1
}

# Perform Export
$ExportDir = Export-PVSConfiguration
if ($ExportDir) {
    Write-Log "Export completed successfully to: $ExportDir" -Level SUCCESS
}
else {
    Write-Log "Export operation failed." -Level ERROR
    exit 1
}

$ScriptEndTime = Get-Date
$ExecutionTime = New-TimeSpan -Start $ScriptStartTime -End $ScriptEndTime
Write-Log "===== PVS Configuration Export Script Completed =====" -Level INFO
Write-Log "Total execution time: $($ExecutionTime.Hours) hours, $($ExecutionTime.Minutes) minutes, $($ExecutionTime.Seconds) seconds" -Level INFO

# Output export path for easy reference
Write-Host "`nExport successfully completed to: $ExportDir" -ForegroundColor Green
Write-Host "You can use this path as the ImportPath parameter for the Import script." -ForegroundColor Cyan
if ($Interactive) {
    Write-Host "`nSites exported: $($SitesToExport -join ', ')" -ForegroundColor Green
    if ($SitesToSkip.Count -gt 0) {
        Write-Host "Sites skipped: $($SitesToSkip -join ', ')" -ForegroundColor Yellow
    }
}
) {
                    $response = Read-Host "Export site '$SiteName'? (Y/N)"
                    if ($response -notmatch '^[YyNn]
            
            # Export Collections
            Write-Log "Exporting Collections for Site: $($Site.SiteName)" -Level INFO
            $Collections = Get-PvsCollection -SiteName $Site.SiteName
            if ($Collections) {
                $CollectionsDir = Join-Path -Path $SiteDir -ChildPath "Collections"
                New-Item -Path $CollectionsDir -ItemType Directory -Force | Out-Null
                
                foreach ($Collection in $Collections) {
                    Write-Log "Exporting Collection: $($Collection.CollectionName)" -Level INFO
                    $Collection | Export-Clixml -Path (Join-Path -Path $CollectionsDir -ChildPath "$($Collection.CollectionName).xml")
                    
                    # Export Devices in Collection
                    $Devices = Get-PvsDevice -CollectionName $Collection.CollectionName -SiteName $Site.SiteName
                    if ($Devices) {
                        $DevicesDir = Join-Path -Path $CollectionsDir -ChildPath "$($Collection.CollectionName)_Devices"
                        New-Item -Path $DevicesDir -ItemType Directory -Force | Out-Null
                        
                        foreach ($Device in $Devices) {
                            $Device | Export-Clixml -Path (Join-Path -Path $DevicesDir -ChildPath "$($Device.DeviceName).xml")
                        }
                        Write-Log "Exported $($Devices.Count) devices for Collection: $($Collection.CollectionName)" -Level SUCCESS
                    }
                }
                Write-Log "Exported $($Collections.Count) Collections for Site: $($Site.SiteName)" -Level SUCCESS
            }
            
            # Export Stores
            Write-Log "Exporting Stores for Site: $($Site.SiteName)" -Level INFO
            $Stores = Get-PvsStore -SiteName $Site.SiteName
            if ($Stores) {
                $StoresDir = Join-Path -Path $SiteDir -ChildPath "Stores"
                New-Item -Path $StoresDir -ItemType Directory -Force | Out-Null
                
                foreach ($Store in $Stores) {
                    Write-Log "Exporting Store: $($Store.StoreName)" -Level INFO
                    $Store | Export-Clixml -Path (Join-Path -Path $StoresDir -ChildPath "$($Store.StoreName).xml")
                    
                    # Export vDisks in Store
                    try {
                        # First get disk locators, which provide the link between stores and vDisks
                        $DiskLocators = Get-PvsDiskLocator -StoreName $Store.StoreName -SiteName $Site.SiteName -ErrorAction Stop
                        if ($DiskLocators) {
                            $vDisksDir = Join-Path -Path $StoresDir -ChildPath "$($Store.StoreName)_vDisks"
                            New-Item -Path $vDisksDir -ItemType Directory -Force | Out-Null
                            
                            foreach ($DiskLocator in $DiskLocators) {
                                try {
                                    # Get full disk info for each disk locator
                                    $vDisk = Get-PvsDiskInfo -DiskLocatorName $DiskLocator.DiskLocatorName -StoreName $Store.StoreName -SiteName $Site.SiteName -ErrorAction Stop
                                    $vDisk | Export-Clixml -Path (Join-Path -Path $vDisksDir -ChildPath "$($DiskLocator.DiskLocatorName).xml")
                                    
                                    # Export vDisk Versions
                                    $vDiskVersions = Get-PvsDiskVersion -DiskLocatorName $DiskLocator.DiskLocatorName -StoreName $Store.StoreName -SiteName $Site.SiteName -ErrorAction Stop
                                    if ($vDiskVersions) {
                                        $vDiskVersionsDir = Join-Path -Path $vDisksDir -ChildPath "$($DiskLocator.DiskLocatorName)_Versions"
                                        New-Item -Path $vDiskVersionsDir -ItemType Directory -Force | Out-Null
                                        
                                        foreach ($vDiskVersion in $vDiskVersions) {
                                            $vDiskVersion | Export-Clixml -Path (Join-Path -Path $vDiskVersionsDir -ChildPath "v$($vDiskVersion.Version).xml")
                                        }
                                        Write-Log "Exported $($vDiskVersions.Count) versions for vDisk: $($DiskLocator.DiskLocatorName)" -Level SUCCESS
                                    }
                                }
                                catch {
                                    Write-Log "Warning: Failed to export vDisk information for $($DiskLocator.DiskLocatorName): $_" -Level WARNING
                                }
                            }
                            Write-Log "Exported $($DiskLocators.Count) vDisks for Store: $($Store.StoreName)" -Level SUCCESS
                        }
                    }
                    catch {
                        Write-Log "Warning: Failed to export vDisks for Store $($Store.StoreName): $_" -Level WARNING
                    }
                        Write-Log "Exported $($vDisks.Count) vDisks for Store: $($Store.StoreName)" -Level SUCCESS
                    }
                }
                Write-Log "Exported $($Stores.Count) Stores for Site: $($Site.SiteName)" -Level SUCCESS
            }
            
            # Export Servers
            Write-Log "Exporting Servers for Site: $($Site.SiteName)" -Level INFO
            $Servers = Get-PvsServer -SiteName $Site.SiteName
            if ($Servers) {
                $ServersDir = Join-Path -Path $SiteDir -ChildPath "Servers"
                New-Item -Path $ServersDir -ItemType Directory -Force | Out-Null
                
                foreach ($Server in $Servers) {
                    Write-Log "Exporting Server: $($Server.ServerName)" -Level INFO
                    $Server | Export-Clixml -Path (Join-Path -Path $ServersDir -ChildPath "$($Server.ServerName).xml")
                    
                    # Export Server Store access
                    $ServerStores = Get-PvsServerStore -ServerName $Server.ServerName -SiteName $Site.SiteName
                    if ($ServerStores) {
                        $ServerStoresDir = Join-Path -Path $ServersDir -ChildPath "$($Server.ServerName)_Stores"
                        New-Item -Path $ServerStoresDir -ItemType Directory -Force | Out-Null
                        
                        foreach ($ServerStore in $ServerStores) {
                            $ServerStore | Export-Clixml -Path (Join-Path -Path $ServerStoresDir -ChildPath "$($ServerStore.StoreName).xml")
                        }
                        Write-Log "Exported $($ServerStores.Count) store connections for Server: $($Server.ServerName)" -Level SUCCESS
                    }
                }
                Write-Log "Exported $($Servers.Count) Servers for Site: $($Site.SiteName)" -Level SUCCESS
            }
            
            # Export Site properties
            Write-Log "Exporting Site properties for Site: $($Site.SiteName)" -Level INFO
            try {
                # Export AuthGroups
                $AuthGroups = Get-PvsAuthGroup -SiteName $Site.SiteName
                if ($AuthGroups) {
                    $AuthGroupsDir = Join-Path -Path $SiteDir -ChildPath "AuthGroups"
                    New-Item -Path $AuthGroupsDir -ItemType Directory -Force | Out-Null
                    
                    foreach ($AuthGroup in $AuthGroups) {
                        $AuthGroup | Export-Clixml -Path (Join-Path -Path $AuthGroupsDir -ChildPath "$($AuthGroup.AuthGroupName).xml")
                    }
                    Write-Log "Exported $($AuthGroups.Count) authentication groups for Site: $($Site.SiteName)" -Level SUCCESS
                }
            }
            catch {
                Write-Log "Warning: Could not export AuthGroups: $_" -Level WARNING
            }
            
            Write-Log "Completed export for Site: $($Site.SiteName)" -Level SUCCESS
        }
        
        # Export summary file
        $Summary = @{
            ExportTime = $ScriptStartTime
            ExportPath = $ExportDir
            ExportedSites = $Sites | Where-Object { $SkipSites -notcontains $_.SiteName } | Select-Object -ExpandProperty SiteName
            SkippedSites = $SkipSites
            TotalSites = $Sites.Count
            ExportedSitesCount = ($Sites | Where-Object { $SkipSites -notcontains $_.SiteName }).Count
            FarmName = $Farm.FarmName
        }
        
        $Summary | Export-Clixml -Path (Join-Path -Path $ExportDir -ChildPath "ExportSummary.xml")
        
        Write-Log "PVS configuration export completed successfully." -Level SUCCESS
        Write-Log "Export location: $ExportDir" -Level INFO
        
        return $ExportDir
    }
    catch {
        Write-Log "Failed to export PVS configuration: $_" -Level ERROR
        return $null
    }
}

# Main Script Execution
Write-Log "===== PVS Configuration Export Script Started =====" -Level INFO
Write-Log "Export Path: $ExportPath" -Level INFO
if ($SkipSites.Count -gt 0) {
    Write-Log "Sites to skip: $($SkipSites -join ', ')" -Level INFO
}

# Load PVS Snapin
if (-not (Import-PVSSnapin)) {
    Write-Log "Failed to load required PVS Snapin. Script terminated." -Level ERROR
    exit 1
}

# Test PVS Connection
if (-not (Test-PVSConnection)) {
    Write-Log "Failed to connect to PVS. Ensure PVS is installed and configured. Script terminated." -Level ERROR
    exit 1
}

# Perform Export
$ExportDir = Export-PVSConfiguration
if ($ExportDir) {
    Write-Log "Export completed successfully to: $ExportDir" -Level SUCCESS
}
else {
    Write-Log "Export operation failed." -Level ERROR
    exit 1
}

$ScriptEndTime = Get-Date
$ExecutionTime = New-TimeSpan -Start $ScriptStartTime -End $ScriptEndTime
Write-Log "===== PVS Configuration Export Script Completed =====" -Level INFO
Write-Log "Total execution time: $($ExecutionTime.Hours) hours, $($ExecutionTime.Minutes) minutes, $($ExecutionTime.Seconds) seconds" -Level INFO

# Output export path for easy reference
Write-Host "`nExport successfully completed to: $ExportDir" -ForegroundColor Green
Write-Host "You can use this path as the ImportPath parameter for the Import script." -ForegroundColor Cyan
) {
                        Write-Host "Please enter Y or N" -ForegroundColor Yellow
                    }
                }
                
                if ($response -match '^[Yy]
            
            # Export Collections
            Write-Log "Exporting Collections for Site: $($Site.SiteName)" -Level INFO
            $Collections = Get-PvsCollection -SiteName $Site.SiteName
            if ($Collections) {
                $CollectionsDir = Join-Path -Path $SiteDir -ChildPath "Collections"
                New-Item -Path $CollectionsDir -ItemType Directory -Force | Out-Null
                
                foreach ($Collection in $Collections) {
                    Write-Log "Exporting Collection: $($Collection.CollectionName)" -Level INFO
                    $Collection | Export-Clixml -Path (Join-Path -Path $CollectionsDir -ChildPath "$($Collection.CollectionName).xml")
                    
                    # Export Devices in Collection
                    $Devices = Get-PvsDevice -CollectionName $Collection.CollectionName -SiteName $Site.SiteName
                    if ($Devices) {
                        $DevicesDir = Join-Path -Path $CollectionsDir -ChildPath "$($Collection.CollectionName)_Devices"
                        New-Item -Path $DevicesDir -ItemType Directory -Force | Out-Null
                        
                        foreach ($Device in $Devices) {
                            $Device | Export-Clixml -Path (Join-Path -Path $DevicesDir -ChildPath "$($Device.DeviceName).xml")
                        }
                        Write-Log "Exported $($Devices.Count) devices for Collection: $($Collection.CollectionName)" -Level SUCCESS
                    }
                }
                Write-Log "Exported $($Collections.Count) Collections for Site: $($Site.SiteName)" -Level SUCCESS
            }
            
            # Export Stores
            Write-Log "Exporting Stores for Site: $($Site.SiteName)" -Level INFO
            $Stores = Get-PvsStore -SiteName $Site.SiteName
            if ($Stores) {
                $StoresDir = Join-Path -Path $SiteDir -ChildPath "Stores"
                New-Item -Path $StoresDir -ItemType Directory -Force | Out-Null
                
                foreach ($Store in $Stores) {
                    Write-Log "Exporting Store: $($Store.StoreName)" -Level INFO
                    $Store | Export-Clixml -Path (Join-Path -Path $StoresDir -ChildPath "$($Store.StoreName).xml")
                    
                    # Export vDisks in Store
                    try {
                        # First get disk locators, which provide the link between stores and vDisks
                        $DiskLocators = Get-PvsDiskLocator -StoreName $Store.StoreName -SiteName $Site.SiteName -ErrorAction Stop
                        if ($DiskLocators) {
                            $vDisksDir = Join-Path -Path $StoresDir -ChildPath "$($Store.StoreName)_vDisks"
                            New-Item -Path $vDisksDir -ItemType Directory -Force | Out-Null
                            
                            foreach ($DiskLocator in $DiskLocators) {
                                try {
                                    # Get full disk info for each disk locator
                                    $vDisk = Get-PvsDiskInfo -DiskLocatorName $DiskLocator.DiskLocatorName -StoreName $Store.StoreName -SiteName $Site.SiteName -ErrorAction Stop
                                    $vDisk | Export-Clixml -Path (Join-Path -Path $vDisksDir -ChildPath "$($DiskLocator.DiskLocatorName).xml")
                                    
                                    # Export vDisk Versions
                                    $vDiskVersions = Get-PvsDiskVersion -DiskLocatorName $DiskLocator.DiskLocatorName -StoreName $Store.StoreName -SiteName $Site.SiteName -ErrorAction Stop
                                    if ($vDiskVersions) {
                                        $vDiskVersionsDir = Join-Path -Path $vDisksDir -ChildPath "$($DiskLocator.DiskLocatorName)_Versions"
                                        New-Item -Path $vDiskVersionsDir -ItemType Directory -Force | Out-Null
                                        
                                        foreach ($vDiskVersion in $vDiskVersions) {
                                            $vDiskVersion | Export-Clixml -Path (Join-Path -Path $vDiskVersionsDir -ChildPath "v$($vDiskVersion.Version).xml")
                                        }
                                        Write-Log "Exported $($vDiskVersions.Count) versions for vDisk: $($DiskLocator.DiskLocatorName)" -Level SUCCESS
                                    }
                                }
                                catch {
                                    Write-Log "Warning: Failed to export vDisk information for $($DiskLocator.DiskLocatorName): $_" -Level WARNING
                                }
                            }
                            Write-Log "Exported $($DiskLocators.Count) vDisks for Store: $($Store.StoreName)" -Level SUCCESS
                        }
                    }
                    catch {
                        Write-Log "Warning: Failed to export vDisks for Store $($Store.StoreName): $_" -Level WARNING
                    }
                        Write-Log "Exported $($vDisks.Count) vDisks for Store: $($Store.StoreName)" -Level SUCCESS
                    }
                }
                Write-Log "Exported $($Stores.Count) Stores for Site: $($Site.SiteName)" -Level SUCCESS
            }
            
            # Export Servers
            Write-Log "Exporting Servers for Site: $($Site.SiteName)" -Level INFO
            $Servers = Get-PvsServer -SiteName $Site.SiteName
            if ($Servers) {
                $ServersDir = Join-Path -Path $SiteDir -ChildPath "Servers"
                New-Item -Path $ServersDir -ItemType Directory -Force | Out-Null
                
                foreach ($Server in $Servers) {
                    Write-Log "Exporting Server: $($Server.ServerName)" -Level INFO
                    $Server | Export-Clixml -Path (Join-Path -Path $ServersDir -ChildPath "$($Server.ServerName).xml")
                    
                    # Export Server Store access
                    $ServerStores = Get-PvsServerStore -ServerName $Server.ServerName -SiteName $Site.SiteName
                    if ($ServerStores) {
                        $ServerStoresDir = Join-Path -Path $ServersDir -ChildPath "$($Server.ServerName)_Stores"
                        New-Item -Path $ServerStoresDir -ItemType Directory -Force | Out-Null
                        
                        foreach ($ServerStore in $ServerStores) {
                            $ServerStore | Export-Clixml -Path (Join-Path -Path $ServerStoresDir -ChildPath "$($ServerStore.StoreName).xml")
                        }
                        Write-Log "Exported $($ServerStores.Count) store connections for Server: $($Server.ServerName)" -Level SUCCESS
                    }
                }
                Write-Log "Exported $($Servers.Count) Servers for Site: $($Site.SiteName)" -Level SUCCESS
            }
            
            # Export Site properties
            Write-Log "Exporting Site properties for Site: $($Site.SiteName)" -Level INFO
            try {
                # Export AuthGroups
                $AuthGroups = Get-PvsAuthGroup -SiteName $Site.SiteName
                if ($AuthGroups) {
                    $AuthGroupsDir = Join-Path -Path $SiteDir -ChildPath "AuthGroups"
                    New-Item -Path $AuthGroupsDir -ItemType Directory -Force | Out-Null
                    
                    foreach ($AuthGroup in $AuthGroups) {
                        $AuthGroup | Export-Clixml -Path (Join-Path -Path $AuthGroupsDir -ChildPath "$($AuthGroup.AuthGroupName).xml")
                    }
                    Write-Log "Exported $($AuthGroups.Count) authentication groups for Site: $($Site.SiteName)" -Level SUCCESS
                }
            }
            catch {
                Write-Log "Warning: Could not export AuthGroups: $_" -Level WARNING
            }
            
            Write-Log "Completed export for Site: $($Site.SiteName)" -Level SUCCESS
        }
        
        # Export summary file
        $Summary = @{
            ExportTime = $ScriptStartTime
            ExportPath = $ExportDir
            ExportedSites = $Sites | Where-Object { $SkipSites -notcontains $_.SiteName } | Select-Object -ExpandProperty SiteName
            SkippedSites = $SkipSites
            TotalSites = $Sites.Count
            ExportedSitesCount = ($Sites | Where-Object { $SkipSites -notcontains $_.SiteName }).Count
            FarmName = $Farm.FarmName
        }
        
        $Summary | Export-Clixml -Path (Join-Path -Path $ExportDir -ChildPath "ExportSummary.xml")
        
        Write-Log "PVS configuration export completed successfully." -Level SUCCESS
        Write-Log "Export location: $ExportDir" -Level INFO
        
        return $ExportDir
    }
    catch {
        Write-Log "Failed to export PVS configuration: $_" -Level ERROR
        return $null
    }
}

# Main Script Execution
Write-Log "===== PVS Configuration Export Script Started =====" -Level INFO
Write-Log "Export Path: $ExportPath" -Level INFO
if ($SkipSites.Count -gt 0) {
    Write-Log "Sites to skip: $($SkipSites -join ', ')" -Level INFO
}

# Load PVS Snapin
if (-not (Import-PVSSnapin)) {
    Write-Log "Failed to load required PVS Snapin. Script terminated." -Level ERROR
    exit 1
}

# Test PVS Connection
if (-not (Test-PVSConnection)) {
    Write-Log "Failed to connect to PVS. Ensure PVS is installed and configured. Script terminated." -Level ERROR
    exit 1
}

# Perform Export
$ExportDir = Export-PVSConfiguration
if ($ExportDir) {
    Write-Log "Export completed successfully to: $ExportDir" -Level SUCCESS
}
else {
    Write-Log "Export operation failed." -Level ERROR
    exit 1
}

$ScriptEndTime = Get-Date
$ExecutionTime = New-TimeSpan -Start $ScriptStartTime -End $ScriptEndTime
Write-Log "===== PVS Configuration Export Script Completed =====" -Level INFO
Write-Log "Total execution time: $($ExecutionTime.Hours) hours, $($ExecutionTime.Minutes) minutes, $($ExecutionTime.Seconds) seconds" -Level INFO

# Output export path for easy reference
Write-Host "`nExport successfully completed to: $ExportDir" -ForegroundColor Green
Write-Host "You can use this path as the ImportPath parameter for the Import script." -ForegroundColor Cyan
) {
                    Write-Host "Site: $SiteName will be exported" -ForegroundColor Green
                    $SitesToExport += $SiteName
                } else {
                    Write-Host "Site: $SiteName will be skipped" -ForegroundColor Yellow
                    $SitesToSkip += $SiteName
                }
            }
            
            Write-Host "`nSelected $($SitesToExport.Count) sites for export" -ForegroundColor Cyan
            if ($SitesToSkip.Count -gt 0) {
                Write-Host "Skipping $($SitesToSkip.Count) sites" -ForegroundColor Yellow
            }
            
            # Confirm export
            Write-Host "`nSites to export: $($SitesToExport -join ', ')" -ForegroundColor Green
            $confirm = ""
            while ($confirm -notmatch '^[YyNn]
            
            # Export Collections
            Write-Log "Exporting Collections for Site: $($Site.SiteName)" -Level INFO
            $Collections = Get-PvsCollection -SiteName $Site.SiteName
            if ($Collections) {
                $CollectionsDir = Join-Path -Path $SiteDir -ChildPath "Collections"
                New-Item -Path $CollectionsDir -ItemType Directory -Force | Out-Null
                
                foreach ($Collection in $Collections) {
                    Write-Log "Exporting Collection: $($Collection.CollectionName)" -Level INFO
                    $Collection | Export-Clixml -Path (Join-Path -Path $CollectionsDir -ChildPath "$($Collection.CollectionName).xml")
                    
                    # Export Devices in Collection
                    $Devices = Get-PvsDevice -CollectionName $Collection.CollectionName -SiteName $Site.SiteName
                    if ($Devices) {
                        $DevicesDir = Join-Path -Path $CollectionsDir -ChildPath "$($Collection.CollectionName)_Devices"
                        New-Item -Path $DevicesDir -ItemType Directory -Force | Out-Null
                        
                        foreach ($Device in $Devices) {
                            $Device | Export-Clixml -Path (Join-Path -Path $DevicesDir -ChildPath "$($Device.DeviceName).xml")
                        }
                        Write-Log "Exported $($Devices.Count) devices for Collection: $($Collection.CollectionName)" -Level SUCCESS
                    }
                }
                Write-Log "Exported $($Collections.Count) Collections for Site: $($Site.SiteName)" -Level SUCCESS
            }
            
            # Export Stores
            Write-Log "Exporting Stores for Site: $($Site.SiteName)" -Level INFO
            $Stores = Get-PvsStore -SiteName $Site.SiteName
            if ($Stores) {
                $StoresDir = Join-Path -Path $SiteDir -ChildPath "Stores"
                New-Item -Path $StoresDir -ItemType Directory -Force | Out-Null
                
                foreach ($Store in $Stores) {
                    Write-Log "Exporting Store: $($Store.StoreName)" -Level INFO
                    $Store | Export-Clixml -Path (Join-Path -Path $StoresDir -ChildPath "$($Store.StoreName).xml")
                    
                    # Export vDisks in Store
                    try {
                        # First get disk locators, which provide the link between stores and vDisks
                        $DiskLocators = Get-PvsDiskLocator -StoreName $Store.StoreName -SiteName $Site.SiteName -ErrorAction Stop
                        if ($DiskLocators) {
                            $vDisksDir = Join-Path -Path $StoresDir -ChildPath "$($Store.StoreName)_vDisks"
                            New-Item -Path $vDisksDir -ItemType Directory -Force | Out-Null
                            
                            foreach ($DiskLocator in $DiskLocators) {
                                try {
                                    # Get full disk info for each disk locator
                                    $vDisk = Get-PvsDiskInfo -DiskLocatorName $DiskLocator.DiskLocatorName -StoreName $Store.StoreName -SiteName $Site.SiteName -ErrorAction Stop
                                    $vDisk | Export-Clixml -Path (Join-Path -Path $vDisksDir -ChildPath "$($DiskLocator.DiskLocatorName).xml")
                                    
                                    # Export vDisk Versions
                                    $vDiskVersions = Get-PvsDiskVersion -DiskLocatorName $DiskLocator.DiskLocatorName -StoreName $Store.StoreName -SiteName $Site.SiteName -ErrorAction Stop
                                    if ($vDiskVersions) {
                                        $vDiskVersionsDir = Join-Path -Path $vDisksDir -ChildPath "$($DiskLocator.DiskLocatorName)_Versions"
                                        New-Item -Path $vDiskVersionsDir -ItemType Directory -Force | Out-Null
                                        
                                        foreach ($vDiskVersion in $vDiskVersions) {
                                            $vDiskVersion | Export-Clixml -Path (Join-Path -Path $vDiskVersionsDir -ChildPath "v$($vDiskVersion.Version).xml")
                                        }
                                        Write-Log "Exported $($vDiskVersions.Count) versions for vDisk: $($DiskLocator.DiskLocatorName)" -Level SUCCESS
                                    }
                                }
                                catch {
                                    Write-Log "Warning: Failed to export vDisk information for $($DiskLocator.DiskLocatorName): $_" -Level WARNING
                                }
                            }
                            Write-Log "Exported $($DiskLocators.Count) vDisks for Store: $($Store.StoreName)" -Level SUCCESS
                        }
                    }
                    catch {
                        Write-Log "Warning: Failed to export vDisks for Store $($Store.StoreName): $_" -Level WARNING
                    }
                        Write-Log "Exported $($vDisks.Count) vDisks for Store: $($Store.StoreName)" -Level SUCCESS
                    }
                }
                Write-Log "Exported $($Stores.Count) Stores for Site: $($Site.SiteName)" -Level SUCCESS
            }
            
            # Export Servers
            Write-Log "Exporting Servers for Site: $($Site.SiteName)" -Level INFO
            $Servers = Get-PvsServer -SiteName $Site.SiteName
            if ($Servers) {
                $ServersDir = Join-Path -Path $SiteDir -ChildPath "Servers"
                New-Item -Path $ServersDir -ItemType Directory -Force | Out-Null
                
                foreach ($Server in $Servers) {
                    Write-Log "Exporting Server: $($Server.ServerName)" -Level INFO
                    $Server | Export-Clixml -Path (Join-Path -Path $ServersDir -ChildPath "$($Server.ServerName).xml")
                    
                    # Export Server Store access
                    $ServerStores = Get-PvsServerStore -ServerName $Server.ServerName -SiteName $Site.SiteName
                    if ($ServerStores) {
                        $ServerStoresDir = Join-Path -Path $ServersDir -ChildPath "$($Server.ServerName)_Stores"
                        New-Item -Path $ServerStoresDir -ItemType Directory -Force | Out-Null
                        
                        foreach ($ServerStore in $ServerStores) {
                            $ServerStore | Export-Clixml -Path (Join-Path -Path $ServerStoresDir -ChildPath "$($ServerStore.StoreName).xml")
                        }
                        Write-Log "Exported $($ServerStores.Count) store connections for Server: $($Server.ServerName)" -Level SUCCESS
                    }
                }
                Write-Log "Exported $($Servers.Count) Servers for Site: $($Site.SiteName)" -Level SUCCESS
            }
            
            # Export Site properties
            Write-Log "Exporting Site properties for Site: $($Site.SiteName)" -Level INFO
            try {
                # Export AuthGroups
                $AuthGroups = Get-PvsAuthGroup -SiteName $Site.SiteName
                if ($AuthGroups) {
                    $AuthGroupsDir = Join-Path -Path $SiteDir -ChildPath "AuthGroups"
                    New-Item -Path $AuthGroupsDir -ItemType Directory -Force | Out-Null
                    
                    foreach ($AuthGroup in $AuthGroups) {
                        $AuthGroup | Export-Clixml -Path (Join-Path -Path $AuthGroupsDir -ChildPath "$($AuthGroup.AuthGroupName).xml")
                    }
                    Write-Log "Exported $($AuthGroups.Count) authentication groups for Site: $($Site.SiteName)" -Level SUCCESS
                }
            }
            catch {
                Write-Log "Warning: Could not export AuthGroups: $_" -Level WARNING
            }
            
            Write-Log "Completed export for Site: $($Site.SiteName)" -Level SUCCESS
        }
        
        # Export summary file
        $Summary = @{
            ExportTime = $ScriptStartTime
            ExportPath = $ExportDir
            ExportedSites = $Sites | Where-Object { $SkipSites -notcontains $_.SiteName } | Select-Object -ExpandProperty SiteName
            SkippedSites = $SkipSites
            TotalSites = $Sites.Count
            ExportedSitesCount = ($Sites | Where-Object { $SkipSites -notcontains $_.SiteName }).Count
            FarmName = $Farm.FarmName
        }
        
        $Summary | Export-Clixml -Path (Join-Path -Path $ExportDir -ChildPath "ExportSummary.xml")
        
        Write-Log "PVS configuration export completed successfully." -Level SUCCESS
        Write-Log "Export location: $ExportDir" -Level INFO
        
        return $ExportDir
    }
    catch {
        Write-Log "Failed to export PVS configuration: $_" -Level ERROR
        return $null
    }
}

# Main Script Execution
Write-Log "===== PVS Configuration Export Script Started =====" -Level INFO
Write-Log "Export Path: $ExportPath" -Level INFO
if ($SkipSites.Count -gt 0) {
    Write-Log "Sites to skip: $($SkipSites -join ', ')" -Level INFO
}

# Load PVS Snapin
if (-not (Import-PVSSnapin)) {
    Write-Log "Failed to load required PVS Snapin. Script terminated." -Level ERROR
    exit 1
}

# Test PVS Connection
if (-not (Test-PVSConnection)) {
    Write-Log "Failed to connect to PVS. Ensure PVS is installed and configured. Script terminated." -Level ERROR
    exit 1
}

# Perform Export
$ExportDir = Export-PVSConfiguration
if ($ExportDir) {
    Write-Log "Export completed successfully to: $ExportDir" -Level SUCCESS
}
else {
    Write-Log "Export operation failed." -Level ERROR
    exit 1
}

$ScriptEndTime = Get-Date
$ExecutionTime = New-TimeSpan -Start $ScriptStartTime -End $ScriptEndTime
Write-Log "===== PVS Configuration Export Script Completed =====" -Level INFO
Write-Log "Total execution time: $($ExecutionTime.Hours) hours, $($ExecutionTime.Minutes) minutes, $($ExecutionTime.Seconds) seconds" -Level INFO

# Output export path for easy reference
Write-Host "`nExport successfully completed to: $ExportDir" -ForegroundColor Green
Write-Host "You can use this path as the ImportPath parameter for the Import script." -ForegroundColor Cyan
) {
                $confirm = Read-Host "Continue with export? (Y/N)"
                if ($confirm -notmatch '^[YyNn]
            
            # Export Collections
            Write-Log "Exporting Collections for Site: $($Site.SiteName)" -Level INFO
            $Collections = Get-PvsCollection -SiteName $Site.SiteName
            if ($Collections) {
                $CollectionsDir = Join-Path -Path $SiteDir -ChildPath "Collections"
                New-Item -Path $CollectionsDir -ItemType Directory -Force | Out-Null
                
                foreach ($Collection in $Collections) {
                    Write-Log "Exporting Collection: $($Collection.CollectionName)" -Level INFO
                    $Collection | Export-Clixml -Path (Join-Path -Path $CollectionsDir -ChildPath "$($Collection.CollectionName).xml")
                    
                    # Export Devices in Collection
                    $Devices = Get-PvsDevice -CollectionName $Collection.CollectionName -SiteName $Site.SiteName
                    if ($Devices) {
                        $DevicesDir = Join-Path -Path $CollectionsDir -ChildPath "$($Collection.CollectionName)_Devices"
                        New-Item -Path $DevicesDir -ItemType Directory -Force | Out-Null
                        
                        foreach ($Device in $Devices) {
                            $Device | Export-Clixml -Path (Join-Path -Path $DevicesDir -ChildPath "$($Device.DeviceName).xml")
                        }
                        Write-Log "Exported $($Devices.Count) devices for Collection: $($Collection.CollectionName)" -Level SUCCESS
                    }
                }
                Write-Log "Exported $($Collections.Count) Collections for Site: $($Site.SiteName)" -Level SUCCESS
            }
            
            # Export Stores
            Write-Log "Exporting Stores for Site: $($Site.SiteName)" -Level INFO
            $Stores = Get-PvsStore -SiteName $Site.SiteName
            if ($Stores) {
                $StoresDir = Join-Path -Path $SiteDir -ChildPath "Stores"
                New-Item -Path $StoresDir -ItemType Directory -Force | Out-Null
                
                foreach ($Store in $Stores) {
                    Write-Log "Exporting Store: $($Store.StoreName)" -Level INFO
                    $Store | Export-Clixml -Path (Join-Path -Path $StoresDir -ChildPath "$($Store.StoreName).xml")
                    
                    # Export vDisks in Store
                    try {
                        # First get disk locators, which provide the link between stores and vDisks
                        $DiskLocators = Get-PvsDiskLocator -StoreName $Store.StoreName -SiteName $Site.SiteName -ErrorAction Stop
                        if ($DiskLocators) {
                            $vDisksDir = Join-Path -Path $StoresDir -ChildPath "$($Store.StoreName)_vDisks"
                            New-Item -Path $vDisksDir -ItemType Directory -Force | Out-Null
                            
                            foreach ($DiskLocator in $DiskLocators) {
                                try {
                                    # Get full disk info for each disk locator
                                    $vDisk = Get-PvsDiskInfo -DiskLocatorName $DiskLocator.DiskLocatorName -StoreName $Store.StoreName -SiteName $Site.SiteName -ErrorAction Stop
                                    $vDisk | Export-Clixml -Path (Join-Path -Path $vDisksDir -ChildPath "$($DiskLocator.DiskLocatorName).xml")
                                    
                                    # Export vDisk Versions
                                    $vDiskVersions = Get-PvsDiskVersion -DiskLocatorName $DiskLocator.DiskLocatorName -StoreName $Store.StoreName -SiteName $Site.SiteName -ErrorAction Stop
                                    if ($vDiskVersions) {
                                        $vDiskVersionsDir = Join-Path -Path $vDisksDir -ChildPath "$($DiskLocator.DiskLocatorName)_Versions"
                                        New-Item -Path $vDiskVersionsDir -ItemType Directory -Force | Out-Null
                                        
                                        foreach ($vDiskVersion in $vDiskVersions) {
                                            $vDiskVersion | Export-Clixml -Path (Join-Path -Path $vDiskVersionsDir -ChildPath "v$($vDiskVersion.Version).xml")
                                        }
                                        Write-Log "Exported $($vDiskVersions.Count) versions for vDisk: $($DiskLocator.DiskLocatorName)" -Level SUCCESS
                                    }
                                }
                                catch {
                                    Write-Log "Warning: Failed to export vDisk information for $($DiskLocator.DiskLocatorName): $_" -Level WARNING
                                }
                            }
                            Write-Log "Exported $($DiskLocators.Count) vDisks for Store: $($Store.StoreName)" -Level SUCCESS
                        }
                    }
                    catch {
                        Write-Log "Warning: Failed to export vDisks for Store $($Store.StoreName): $_" -Level WARNING
                    }
                        Write-Log "Exported $($vDisks.Count) vDisks for Store: $($Store.StoreName)" -Level SUCCESS
                    }
                }
                Write-Log "Exported $($Stores.Count) Stores for Site: $($Site.SiteName)" -Level SUCCESS
            }
            
            # Export Servers
            Write-Log "Exporting Servers for Site: $($Site.SiteName)" -Level INFO
            $Servers = Get-PvsServer -SiteName $Site.SiteName
            if ($Servers) {
                $ServersDir = Join-Path -Path $SiteDir -ChildPath "Servers"
                New-Item -Path $ServersDir -ItemType Directory -Force | Out-Null
                
                foreach ($Server in $Servers) {
                    Write-Log "Exporting Server: $($Server.ServerName)" -Level INFO
                    $Server | Export-Clixml -Path (Join-Path -Path $ServersDir -ChildPath "$($Server.ServerName).xml")
                    
                    # Export Server Store access
                    $ServerStores = Get-PvsServerStore -ServerName $Server.ServerName -SiteName $Site.SiteName
                    if ($ServerStores) {
                        $ServerStoresDir = Join-Path -Path $ServersDir -ChildPath "$($Server.ServerName)_Stores"
                        New-Item -Path $ServerStoresDir -ItemType Directory -Force | Out-Null
                        
                        foreach ($ServerStore in $ServerStores) {
                            $ServerStore | Export-Clixml -Path (Join-Path -Path $ServerStoresDir -ChildPath "$($ServerStore.StoreName).xml")
                        }
                        Write-Log "Exported $($ServerStores.Count) store connections for Server: $($Server.ServerName)" -Level SUCCESS
                    }
                }
                Write-Log "Exported $($Servers.Count) Servers for Site: $($Site.SiteName)" -Level SUCCESS
            }
            
            # Export Site properties
            Write-Log "Exporting Site properties for Site: $($Site.SiteName)" -Level INFO
            try {
                # Export AuthGroups
                $AuthGroups = Get-PvsAuthGroup -SiteName $Site.SiteName
                if ($AuthGroups) {
                    $AuthGroupsDir = Join-Path -Path $SiteDir -ChildPath "AuthGroups"
                    New-Item -Path $AuthGroupsDir -ItemType Directory -Force | Out-Null
                    
                    foreach ($AuthGroup in $AuthGroups) {
                        $AuthGroup | Export-Clixml -Path (Join-Path -Path $AuthGroupsDir -ChildPath "$($AuthGroup.AuthGroupName).xml")
                    }
                    Write-Log "Exported $($AuthGroups.Count) authentication groups for Site: $($Site.SiteName)" -Level SUCCESS
                }
            }
            catch {
                Write-Log "Warning: Could not export AuthGroups: $_" -Level WARNING
            }
            
            Write-Log "Completed export for Site: $($Site.SiteName)" -Level SUCCESS
        }
        
        # Export summary file
        $Summary = @{
            ExportTime = $ScriptStartTime
            ExportPath = $ExportDir
            ExportedSites = $Sites | Where-Object { $SkipSites -notcontains $_.SiteName } | Select-Object -ExpandProperty SiteName
            SkippedSites = $SkipSites
            TotalSites = $Sites.Count
            ExportedSitesCount = ($Sites | Where-Object { $SkipSites -notcontains $_.SiteName }).Count
            FarmName = $Farm.FarmName
        }
        
        $Summary | Export-Clixml -Path (Join-Path -Path $ExportDir -ChildPath "ExportSummary.xml")
        
        Write-Log "PVS configuration export completed successfully." -Level SUCCESS
        Write-Log "Export location: $ExportDir" -Level INFO
        
        return $ExportDir
    }
    catch {
        Write-Log "Failed to export PVS configuration: $_" -Level ERROR
        return $null
    }
}

# Main Script Execution
Write-Log "===== PVS Configuration Export Script Started =====" -Level INFO
Write-Log "Export Path: $ExportPath" -Level INFO
if ($SkipSites.Count -gt 0) {
    Write-Log "Sites to skip: $($SkipSites -join ', ')" -Level INFO
}

# Load PVS Snapin
if (-not (Import-PVSSnapin)) {
    Write-Log "Failed to load required PVS Snapin. Script terminated." -Level ERROR
    exit 1
}

# Test PVS Connection
if (-not (Test-PVSConnection)) {
    Write-Log "Failed to connect to PVS. Ensure PVS is installed and configured. Script terminated." -Level ERROR
    exit 1
}

# Perform Export
$ExportDir = Export-PVSConfiguration
if ($ExportDir) {
    Write-Log "Export completed successfully to: $ExportDir" -Level SUCCESS
}
else {
    Write-Log "Export operation failed." -Level ERROR
    exit 1
}

$ScriptEndTime = Get-Date
$ExecutionTime = New-TimeSpan -Start $ScriptStartTime -End $ScriptEndTime
Write-Log "===== PVS Configuration Export Script Completed =====" -Level INFO
Write-Log "Total execution time: $($ExecutionTime.Hours) hours, $($ExecutionTime.Minutes) minutes, $($ExecutionTime.Seconds) seconds" -Level INFO

# Output export path for easy reference
Write-Host "`nExport successfully completed to: $ExportDir" -ForegroundColor Green
Write-Host "You can use this path as the ImportPath parameter for the Import script." -ForegroundColor Cyan
) {
                    Write-Host "Please enter Y or N" -ForegroundColor Yellow
                }
            }
            
            if ($confirm -match '^[Nn]
            
            # Export Collections
            Write-Log "Exporting Collections for Site: $($Site.SiteName)" -Level INFO
            $Collections = Get-PvsCollection -SiteName $Site.SiteName
            if ($Collections) {
                $CollectionsDir = Join-Path -Path $SiteDir -ChildPath "Collections"
                New-Item -Path $CollectionsDir -ItemType Directory -Force | Out-Null
                
                foreach ($Collection in $Collections) {
                    Write-Log "Exporting Collection: $($Collection.CollectionName)" -Level INFO
                    $Collection | Export-Clixml -Path (Join-Path -Path $CollectionsDir -ChildPath "$($Collection.CollectionName).xml")
                    
                    # Export Devices in Collection
                    $Devices = Get-PvsDevice -CollectionName $Collection.CollectionName -SiteName $Site.SiteName
                    if ($Devices) {
                        $DevicesDir = Join-Path -Path $CollectionsDir -ChildPath "$($Collection.CollectionName)_Devices"
                        New-Item -Path $DevicesDir -ItemType Directory -Force | Out-Null
                        
                        foreach ($Device in $Devices) {
                            $Device | Export-Clixml -Path (Join-Path -Path $DevicesDir -ChildPath "$($Device.DeviceName).xml")
                        }
                        Write-Log "Exported $($Devices.Count) devices for Collection: $($Collection.CollectionName)" -Level SUCCESS
                    }
                }
                Write-Log "Exported $($Collections.Count) Collections for Site: $($Site.SiteName)" -Level SUCCESS
            }
            
            # Export Stores
            Write-Log "Exporting Stores for Site: $($Site.SiteName)" -Level INFO
            $Stores = Get-PvsStore -SiteName $Site.SiteName
            if ($Stores) {
                $StoresDir = Join-Path -Path $SiteDir -ChildPath "Stores"
                New-Item -Path $StoresDir -ItemType Directory -Force | Out-Null
                
                foreach ($Store in $Stores) {
                    Write-Log "Exporting Store: $($Store.StoreName)" -Level INFO
                    $Store | Export-Clixml -Path (Join-Path -Path $StoresDir -ChildPath "$($Store.StoreName).xml")
                    
                    # Export vDisks in Store
                    try {
                        # First get disk locators, which provide the link between stores and vDisks
                        $DiskLocators = Get-PvsDiskLocator -StoreName $Store.StoreName -SiteName $Site.SiteName -ErrorAction Stop
                        if ($DiskLocators) {
                            $vDisksDir = Join-Path -Path $StoresDir -ChildPath "$($Store.StoreName)_vDisks"
                            New-Item -Path $vDisksDir -ItemType Directory -Force | Out-Null
                            
                            foreach ($DiskLocator in $DiskLocators) {
                                try {
                                    # Get full disk info for each disk locator
                                    $vDisk = Get-PvsDiskInfo -DiskLocatorName $DiskLocator.DiskLocatorName -StoreName $Store.StoreName -SiteName $Site.SiteName -ErrorAction Stop
                                    $vDisk | Export-Clixml -Path (Join-Path -Path $vDisksDir -ChildPath "$($DiskLocator.DiskLocatorName).xml")
                                    
                                    # Export vDisk Versions
                                    $vDiskVersions = Get-PvsDiskVersion -DiskLocatorName $DiskLocator.DiskLocatorName -StoreName $Store.StoreName -SiteName $Site.SiteName -ErrorAction Stop
                                    if ($vDiskVersions) {
                                        $vDiskVersionsDir = Join-Path -Path $vDisksDir -ChildPath "$($DiskLocator.DiskLocatorName)_Versions"
                                        New-Item -Path $vDiskVersionsDir -ItemType Directory -Force | Out-Null
                                        
                                        foreach ($vDiskVersion in $vDiskVersions) {
                                            $vDiskVersion | Export-Clixml -Path (Join-Path -Path $vDiskVersionsDir -ChildPath "v$($vDiskVersion.Version).xml")
                                        }
                                        Write-Log "Exported $($vDiskVersions.Count) versions for vDisk: $($DiskLocator.DiskLocatorName)" -Level SUCCESS
                                    }
                                }
                                catch {
                                    Write-Log "Warning: Failed to export vDisk information for $($DiskLocator.DiskLocatorName): $_" -Level WARNING
                                }
                            }
                            Write-Log "Exported $($DiskLocators.Count) vDisks for Store: $($Store.StoreName)" -Level SUCCESS
                        }
                    }
                    catch {
                        Write-Log "Warning: Failed to export vDisks for Store $($Store.StoreName): $_" -Level WARNING
                    }
                        Write-Log "Exported $($vDisks.Count) vDisks for Store: $($Store.StoreName)" -Level SUCCESS
                    }
                }
                Write-Log "Exported $($Stores.Count) Stores for Site: $($Site.SiteName)" -Level SUCCESS
            }
            
            # Export Servers
            Write-Log "Exporting Servers for Site: $($Site.SiteName)" -Level INFO
            $Servers = Get-PvsServer -SiteName $Site.SiteName
            if ($Servers) {
                $ServersDir = Join-Path -Path $SiteDir -ChildPath "Servers"
                New-Item -Path $ServersDir -ItemType Directory -Force | Out-Null
                
                foreach ($Server in $Servers) {
                    Write-Log "Exporting Server: $($Server.ServerName)" -Level INFO
                    $Server | Export-Clixml -Path (Join-Path -Path $ServersDir -ChildPath "$($Server.ServerName).xml")
                    
                    # Export Server Store access
                    $ServerStores = Get-PvsServerStore -ServerName $Server.ServerName -SiteName $Site.SiteName
                    if ($ServerStores) {
                        $ServerStoresDir = Join-Path -Path $ServersDir -ChildPath "$($Server.ServerName)_Stores"
                        New-Item -Path $ServerStoresDir -ItemType Directory -Force | Out-Null
                        
                        foreach ($ServerStore in $ServerStores) {
                            $ServerStore | Export-Clixml -Path (Join-Path -Path $ServerStoresDir -ChildPath "$($ServerStore.StoreName).xml")
                        }
                        Write-Log "Exported $($ServerStores.Count) store connections for Server: $($Server.ServerName)" -Level SUCCESS
                    }
                }
                Write-Log "Exported $($Servers.Count) Servers for Site: $($Site.SiteName)" -Level SUCCESS
            }
            
            # Export Site properties
            Write-Log "Exporting Site properties for Site: $($Site.SiteName)" -Level INFO
            try {
                # Export AuthGroups
                $AuthGroups = Get-PvsAuthGroup -SiteName $Site.SiteName
                if ($AuthGroups) {
                    $AuthGroupsDir = Join-Path -Path $SiteDir -ChildPath "AuthGroups"
                    New-Item -Path $AuthGroupsDir -ItemType Directory -Force | Out-Null
                    
                    foreach ($AuthGroup in $AuthGroups) {
                        $AuthGroup | Export-Clixml -Path (Join-Path -Path $AuthGroupsDir -ChildPath "$($AuthGroup.AuthGroupName).xml")
                    }
                    Write-Log "Exported $($AuthGroups.Count) authentication groups for Site: $($Site.SiteName)" -Level SUCCESS
                }
            }
            catch {
                Write-Log "Warning: Could not export AuthGroups: $_" -Level WARNING
            }
            
            Write-Log "Completed export for Site: $($Site.SiteName)" -Level SUCCESS
        }
        
        # Export summary file
        $Summary = @{
            ExportTime = $ScriptStartTime
            ExportPath = $ExportDir
            ExportedSites = $Sites | Where-Object { $SkipSites -notcontains $_.SiteName } | Select-Object -ExpandProperty SiteName
            SkippedSites = $SkipSites
            TotalSites = $Sites.Count
            ExportedSitesCount = ($Sites | Where-Object { $SkipSites -notcontains $_.SiteName }).Count
            FarmName = $Farm.FarmName
        }
        
        $Summary | Export-Clixml -Path (Join-Path -Path $ExportDir -ChildPath "ExportSummary.xml")
        
        Write-Log "PVS configuration export completed successfully." -Level SUCCESS
        Write-Log "Export location: $ExportDir" -Level INFO
        
        return $ExportDir
    }
    catch {
        Write-Log "Failed to export PVS configuration: $_" -Level ERROR
        return $null
    }
}

# Main Script Execution
Write-Log "===== PVS Configuration Export Script Started =====" -Level INFO
Write-Log "Export Path: $ExportPath" -Level INFO
if ($SkipSites.Count -gt 0) {
    Write-Log "Sites to skip: $($SkipSites -join ', ')" -Level INFO
}

# Load PVS Snapin
if (-not (Import-PVSSnapin)) {
    Write-Log "Failed to load required PVS Snapin. Script terminated." -Level ERROR
    exit 1
}

# Test PVS Connection
if (-not (Test-PVSConnection)) {
    Write-Log "Failed to connect to PVS. Ensure PVS is installed and configured. Script terminated." -Level ERROR
    exit 1
}

# Perform Export
$ExportDir = Export-PVSConfiguration
if ($ExportDir) {
    Write-Log "Export completed successfully to: $ExportDir" -Level SUCCESS
}
else {
    Write-Log "Export operation failed." -Level ERROR
    exit 1
}

$ScriptEndTime = Get-Date
$ExecutionTime = New-TimeSpan -Start $ScriptStartTime -End $ScriptEndTime
Write-Log "===== PVS Configuration Export Script Completed =====" -Level INFO
Write-Log "Total execution time: $($ExecutionTime.Hours) hours, $($ExecutionTime.Minutes) minutes, $($ExecutionTime.Seconds) seconds" -Level INFO

# Output export path for easy reference
Write-Host "`nExport successfully completed to: $ExportDir" -ForegroundColor Green
Write-Host "You can use this path as the ImportPath parameter for the Import script." -ForegroundColor Cyan
) {
                Write-Log "Export cancelled by user." -Level WARNING
                Remove-Item -Path $ExportDir -Recurse -Force
                return $null
            }
        } else {
            # Non-interactive mode: Use all sites except those in SkipSites
            $SitesToExport = $Sites | Where-Object { $SkipSites -notcontains $_.SiteName } | Select-Object -ExpandProperty SiteName
            $SitesToSkip = $SkipSites
        }
        
        foreach ($Site in $Sites) {
            if ($SitesToSkip -contains $Site.SiteName) {
                Write-Log "Skipping Site: $($Site.SiteName) as requested." -Level WARNING
                continue
            }
            
            Write-Log "Exporting configuration for Site: $($Site.SiteName)" -Level INFO
            
            # Create Site directory
            $SiteDir = Join-Path -Path $ExportDir -ChildPath $Site.SiteName
            New-Item -Path $SiteDir -ItemType Directory -Force | Out-Null
            
            # Export Site Configuration
            $Site | Export-Clixml -Path (Join-Path -Path $SiteDir -ChildPath "Site.xml")
            
            # Export Collections
            Write-Log "Exporting Collections for Site: $($Site.SiteName)" -Level INFO
            $Collections = Get-PvsCollection -SiteName $Site.SiteName
            if ($Collections) {
                $CollectionsDir = Join-Path -Path $SiteDir -ChildPath "Collections"
                New-Item -Path $CollectionsDir -ItemType Directory -Force | Out-Null
                
                foreach ($Collection in $Collections) {
                    Write-Log "Exporting Collection: $($Collection.CollectionName)" -Level INFO
                    $Collection | Export-Clixml -Path (Join-Path -Path $CollectionsDir -ChildPath "$($Collection.CollectionName).xml")
                    
                    # Export Devices in Collection
                    $Devices = Get-PvsDevice -CollectionName $Collection.CollectionName -SiteName $Site.SiteName
                    if ($Devices) {
                        $DevicesDir = Join-Path -Path $CollectionsDir -ChildPath "$($Collection.CollectionName)_Devices"
                        New-Item -Path $DevicesDir -ItemType Directory -Force | Out-Null
                        
                        foreach ($Device in $Devices) {
                            $Device | Export-Clixml -Path (Join-Path -Path $DevicesDir -ChildPath "$($Device.DeviceName).xml")
                        }
                        Write-Log "Exported $($Devices.Count) devices for Collection: $($Collection.CollectionName)" -Level SUCCESS
                    }
                }
                Write-Log "Exported $($Collections.Count) Collections for Site: $($Site.SiteName)" -Level SUCCESS
            }
            
            # Export Stores
            Write-Log "Exporting Stores for Site: $($Site.SiteName)" -Level INFO
            $Stores = Get-PvsStore -SiteName $Site.SiteName
            if ($Stores) {
                $StoresDir = Join-Path -Path $SiteDir -ChildPath "Stores"
                New-Item -Path $StoresDir -ItemType Directory -Force | Out-Null
                
                foreach ($Store in $Stores) {
                    Write-Log "Exporting Store: $($Store.StoreName)" -Level INFO
                    $Store | Export-Clixml -Path (Join-Path -Path $StoresDir -ChildPath "$($Store.StoreName).xml")
                    
                    # Export vDisks in Store
                    try {
                        # First get disk locators, which provide the link between stores and vDisks
                        $DiskLocators = Get-PvsDiskLocator -StoreName $Store.StoreName -SiteName $Site.SiteName -ErrorAction Stop
                        if ($DiskLocators) {
                            $vDisksDir = Join-Path -Path $StoresDir -ChildPath "$($Store.StoreName)_vDisks"
                            New-Item -Path $vDisksDir -ItemType Directory -Force | Out-Null
                            
                            foreach ($DiskLocator in $DiskLocators) {
                                try {
                                    # Get full disk info for each disk locator
                                    $vDisk = Get-PvsDiskInfo -DiskLocatorName $DiskLocator.DiskLocatorName -StoreName $Store.StoreName -SiteName $Site.SiteName -ErrorAction Stop
                                    $vDisk | Export-Clixml -Path (Join-Path -Path $vDisksDir -ChildPath "$($DiskLocator.DiskLocatorName).xml")
                                    
                                    # Export vDisk Versions
                                    $vDiskVersions = Get-PvsDiskVersion -DiskLocatorName $DiskLocator.DiskLocatorName -StoreName $Store.StoreName -SiteName $Site.SiteName -ErrorAction Stop
                                    if ($vDiskVersions) {
                                        $vDiskVersionsDir = Join-Path -Path $vDisksDir -ChildPath "$($DiskLocator.DiskLocatorName)_Versions"
                                        New-Item -Path $vDiskVersionsDir -ItemType Directory -Force | Out-Null
                                        
                                        foreach ($vDiskVersion in $vDiskVersions) {
                                            $vDiskVersion | Export-Clixml -Path (Join-Path -Path $vDiskVersionsDir -ChildPath "v$($vDiskVersion.Version).xml")
                                        }
                                        Write-Log "Exported $($vDiskVersions.Count) versions for vDisk: $($DiskLocator.DiskLocatorName)" -Level SUCCESS
                                    }
                                }
                                catch {
                                    Write-Log "Warning: Failed to export vDisk information for $($DiskLocator.DiskLocatorName): $_" -Level WARNING
                                }
                            }
                            Write-Log "Exported $($DiskLocators.Count) vDisks for Store: $($Store.StoreName)" -Level SUCCESS
                        }
                    }
                    catch {
                        Write-Log "Warning: Failed to export vDisks for Store $($Store.StoreName): $_" -Level WARNING
                    }
                        Write-Log "Exported $($vDisks.Count) vDisks for Store: $($Store.StoreName)" -Level SUCCESS
                    }
                }
                Write-Log "Exported $($Stores.Count) Stores for Site: $($Site.SiteName)" -Level SUCCESS
            }
            
            # Export Servers
            Write-Log "Exporting Servers for Site: $($Site.SiteName)" -Level INFO
            $Servers = Get-PvsServer -SiteName $Site.SiteName
            if ($Servers) {
                $ServersDir = Join-Path -Path $SiteDir -ChildPath "Servers"
                New-Item -Path $ServersDir -ItemType Directory -Force | Out-Null
                
                foreach ($Server in $Servers) {
                    Write-Log "Exporting Server: $($Server.ServerName)" -Level INFO
                    $Server | Export-Clixml -Path (Join-Path -Path $ServersDir -ChildPath "$($Server.ServerName).xml")
                    
                    # Export Server Store access
                    $ServerStores = Get-PvsServerStore -ServerName $Server.ServerName -SiteName $Site.SiteName
                    if ($ServerStores) {
                        $ServerStoresDir = Join-Path -Path $ServersDir -ChildPath "$($Server.ServerName)_Stores"
                        New-Item -Path $ServerStoresDir -ItemType Directory -Force | Out-Null
                        
                        foreach ($ServerStore in $ServerStores) {
                            $ServerStore | Export-Clixml -Path (Join-Path -Path $ServerStoresDir -ChildPath "$($ServerStore.StoreName).xml")
                        }
                        Write-Log "Exported $($ServerStores.Count) store connections for Server: $($Server.ServerName)" -Level SUCCESS
                    }
                }
                Write-Log "Exported $($Servers.Count) Servers for Site: $($Site.SiteName)" -Level SUCCESS
            }
            
            # Export Site properties
            Write-Log "Exporting Site properties for Site: $($Site.SiteName)" -Level INFO
            try {
                # Export AuthGroups
                $AuthGroups = Get-PvsAuthGroup -SiteName $Site.SiteName
                if ($AuthGroups) {
                    $AuthGroupsDir = Join-Path -Path $SiteDir -ChildPath "AuthGroups"
                    New-Item -Path $AuthGroupsDir -ItemType Directory -Force | Out-Null
                    
                    foreach ($AuthGroup in $AuthGroups) {
                        $AuthGroup | Export-Clixml -Path (Join-Path -Path $AuthGroupsDir -ChildPath "$($AuthGroup.AuthGroupName).xml")
                    }
                    Write-Log "Exported $($AuthGroups.Count) authentication groups for Site: $($Site.SiteName)" -Level SUCCESS
                }
            }
            catch {
                Write-Log "Warning: Could not export AuthGroups: $_" -Level WARNING
            }
            
            Write-Log "Completed export for Site: $($Site.SiteName)" -Level SUCCESS
        }
        
        # Export summary file
        $Summary = @{
            ExportTime = $ScriptStartTime
            ExportPath = $ExportDir
            ExportedSites = $Sites | Where-Object { $SkipSites -notcontains $_.SiteName } | Select-Object -ExpandProperty SiteName
            SkippedSites = $SkipSites
            TotalSites = $Sites.Count
            ExportedSitesCount = ($Sites | Where-Object { $SkipSites -notcontains $_.SiteName }).Count
            FarmName = $Farm.FarmName
        }
        
        $Summary | Export-Clixml -Path (Join-Path -Path $ExportDir -ChildPath "ExportSummary.xml")
        
        Write-Log "PVS configuration export completed successfully." -Level SUCCESS
        Write-Log "Export location: $ExportDir" -Level INFO
        
        return $ExportDir
    }
    catch {
        Write-Log "Failed to export PVS configuration: $_" -Level ERROR
        return $null
    }
}

# Main Script Execution
Write-Log "===== PVS Configuration Export Script Started =====" -Level INFO
Write-Log "Export Path: $ExportPath" -Level INFO
if ($SkipSites.Count -gt 0) {
    Write-Log "Sites to skip: $($SkipSites -join ', ')" -Level INFO
}

# Load PVS Snapin
if (-not (Import-PVSSnapin)) {
    Write-Log "Failed to load required PVS Snapin. Script terminated." -Level ERROR
    exit 1
}

# Test PVS Connection
if (-not (Test-PVSConnection)) {
    Write-Log "Failed to connect to PVS. Ensure PVS is installed and configured. Script terminated." -Level ERROR
    exit 1
}

# Perform Export
$ExportDir = Export-PVSConfiguration
if ($ExportDir) {
    Write-Log "Export completed successfully to: $ExportDir" -Level SUCCESS
}
else {
    Write-Log "Export operation failed." -Level ERROR
    exit 1
}

$ScriptEndTime = Get-Date
$ExecutionTime = New-TimeSpan -Start $ScriptStartTime -End $ScriptEndTime
Write-Log "===== PVS Configuration Export Script Completed =====" -Level INFO
Write-Log "Total execution time: $($ExecutionTime.Hours) hours, $($ExecutionTime.Minutes) minutes, $($ExecutionTime.Seconds) seconds" -Level INFO

# Output export path for easy reference
Write-Host "`nExport successfully completed to: $ExportDir" -ForegroundColor Green
Write-Host "You can use this path as the ImportPath parameter for the Import script." -ForegroundColor Cyan
