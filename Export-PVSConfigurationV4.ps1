# Citrix PVS Configuration Export Script
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
    [switch]$ExportFarms = $true,
    
    [Parameter(Mandatory=$false)]
    [switch]$ExportSites = $true,
    
    [Parameter(Mandatory=$false)]
    [switch]$ExportStores = $true,
    
    [Parameter(Mandatory=$false)]
    [switch]$ExportCollections = $true,
    
    [Parameter(Mandatory=$false)]
    [switch]$ExportDevices = $true,
    
    [Parameter(Mandatory=$false)]
    [switch]$ExportvDisks = $true,
    
    [Parameter(Mandatory=$false)]
    [switch]$ExportViews = $true
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
function Load-PVSSnapin {
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
function Create-OutputFolder {
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
            $farmFile = Join-Path -Path $OutputFolder -ChildPath "Farms.xml"
            $farms | Export-Clixml -Path $farmFile
            Write-Log "Successfully exported $($farms.Count) PVS Farms to $farmFile" "SUCCESS"
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
            $siteFile = Join-Path -Path $OutputFolder -ChildPath "Sites.xml"
            $sites | Export-Clixml -Path $siteFile
            Write-Log "Successfully exported $($sites.Count) PVS Sites to $siteFile" "SUCCESS"
            
            # Export site properties
            foreach ($site in $sites) {
                $siteName = $site.SiteName
                Write-Log "Exporting additional configuration for site: $siteName" "INFO"
                
                # Export Site servers
                try {
                    $servers = Get-PvsServer -SiteName $siteName
                    if ($servers) {
                        $serverFile = Join-Path -Path $OutputFolder -ChildPath "Servers_$($siteName).xml"
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
            $storeFile = Join-Path -Path $OutputFolder -ChildPath "Stores.xml"
            $stores | Export-Clixml -Path $storeFile
            Write-Log "Successfully exported $($stores.Count) PVS Stores to $storeFile" "SUCCESS"
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
        foreach ($site in $sites) {
            $siteName = $site.SiteName
            Write-Log "Exporting collections for site: $siteName" "INFO"
            
            $collections = Get-PvsCollection -SiteName $siteName
            if ($collections) {
                $collectionFile = Join-Path -Path $OutputFolder -ChildPath "Collections_$($siteName).xml"
                $collections | Export-Clixml -Path $collectionFile
                Write-Log "Successfully exported $($collections.Count) PVS Collections for site $siteName to $collectionFile" "SUCCESS"
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
        $vDisks = Get-PvsDiskInfo
        if ($vDisks) {
            $vDiskFile = Join-Path -Path $OutputFolder -ChildPath "vDisks.xml"
            $vDisks | Export-Clixml -Path $vDiskFile
            Write-Log "Successfully exported $($vDisks.Count) PVS vDisks to $vDiskFile" "SUCCESS"
            
            # Export vDisk versions
            Write-Log "Exporting vDisk versions" "INFO"
            $vDiskVersions = @()
            foreach ($vDisk in $vDisks) {
                $diskLocatorId = $vDisk.DiskLocatorId
                try {
                    $versions = Get-PvsDiskVersion -DiskLocatorId $diskLocatorId
                    if ($versions) {
                        $vDiskVersions += $versions
                    }
                }
                catch {
                    Write-Log "Error exporting versions for vDisk $($vDisk.Name): $_" "ERROR"
                }
            }
            
            if ($vDiskVersions.Count -gt 0) {
                $vDiskVersionFile = Join-Path -Path $OutputFolder -ChildPath "vDiskVersions.xml"
                $vDiskVersions | Export-Clixml -Path $vDiskVersionFile
                Write-Log "Successfully exported $($vDiskVersions.Count) PVS vDisk versions to $vDiskVersionFile" "SUCCESS"
            } else {
                Write-Log "No PVS vDisk versions found to export" "WARNING"
            }
        } else {
            Write-Log "No PVS vDisks found to export" "WARNING"
        }
    }
    catch {
        Write-Log "Error exporting PVS vDisks: $_" "ERROR"
    }
}

# Function to export PVS Views configuration
function Export-PVSViews {
    Write-Log "Starting export of PVS Views configuration" "INFO"
    
    try {
        $views = Get-PvsView
        if ($views) {
            $viewFile = Join-Path -Path $OutputFolder -ChildPath "Views.xml"
            $views | Export-Clixml -Path $viewFile
            Write-Log "Successfully exported $($views.Count) PVS Views to $viewFile" "SUCCESS"
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
if (!(Load-PVSSnapin)) {
    Write-Log "Failed to initialize PVS environment. Exiting script." "ERROR"
    exit 1
}

# Create output folder
if (!(Create-OutputFolder)) {
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
