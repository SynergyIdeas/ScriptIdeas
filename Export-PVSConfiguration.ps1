# Export-PVSConfiguration.ps1
# Script to export Citrix PVS configuration with detailed logging and interactive prompts
# Author: Claude
# Date: April 14, 2025

# Function to write log entries
function Write-Log {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Output to console with color based on level
    switch ($Level) {
        "INFO"    { Write-Host $logEntry -ForegroundColor Cyan }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        "ERROR"   { Write-Host $logEntry -ForegroundColor Red }
        "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
    }
    
    # Add to log file
    Add-Content -Path $script:LogFile -Value $logEntry
}

# Function to prompt user for yes/no response
function Prompt-YesNo {
    param (
        [string]$Question
    )
    
    $response = Read-Host "$Question (Y/N)"
    return $response.ToUpper() -eq "Y"
}

# Main script execution starts here
try {
    # Script variables
    $scriptStartTime = Get-Date
    $exportPath = "$env:USERPROFILE\Documents\PVSExport"
    $exportDateTime = Get-Date -Format "yyyyMMdd_HHmmss"
    $exportFolder = Join-Path $exportPath $exportDateTime
    $script:LogFile = Join-Path $exportFolder "Export_Log.txt"
    
    # Create export directory structure
    if (-not (Test-Path $exportPath)) {
        New-Item -ItemType Directory -Path $exportPath | Out-Null
    }
    
    if (-not (Test-Path $exportFolder)) {
        New-Item -ItemType Directory -Path $exportFolder | Out-Null
    }
    
    # Banner and initial information
    Write-Host "`n============================================================" -ForegroundColor Cyan
    Write-Host "             CITRIX PVS CONFIGURATION EXPORT TOOL" -ForegroundColor Cyan
    Write-Host "============================================================`n" -ForegroundColor Cyan
    
    Write-Log "Starting PVS Configuration Export" "INFO"
    Write-Log "Export folder: $exportFolder" "INFO"
    
    # Check if PVS SnapIn is available
    if (-not (Get-PSSnapin -Name Citrix.PVS.SnapIn -ErrorAction SilentlyContinue)) {
        try {
            Add-PSSnapin Citrix.PVS.SnapIn
            Write-Log "Citrix PVS SnapIn loaded successfully" "SUCCESS"
        }
        catch {
            Write-Log "Failed to load Citrix PVS SnapIn. Please ensure Citrix PVS Console is installed on this machine" "ERROR"
            Write-Log "Error: $($_.Exception.Message)" "ERROR"
            exit 1
        }
    }
    
    # Validate connection to PVS 
    try {
        $pvsFarmList = Get-PvsFarm
        if (-not $pvsFarmList) {
            Write-Log "Unable to connect to any PVS Farm. Please check your permissions and connections" "ERROR"
            exit 1
        }
        
        $farmCount = ($pvsFarmList | Measure-Object).Count
        Write-Log "Successfully connected to PVS. Found $farmCount farm(s)" "SUCCESS"
    }
    catch {
        Write-Log "Error connecting to PVS: $($_.Exception.Message)" "ERROR"
        exit 1
    }
    
    # Create metadata file with export information
    $metadataFile = Join-Path $exportFolder "ExportMetadata.xml"
    $metadata = @{
        ExportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        ExportUser = $env:USERNAME
        ExportComputer = $env:COMPUTERNAME
        PVSVersion = (Get-PvsFarm).DefaultSiteId # We'll extract version from this object later
    }
    
    $metadata | Export-Clixml -Path $metadataFile
    Write-Log "Created export metadata file" "INFO"
    
    # Export Farm configuration
    Write-Log "Exporting Farm configuration..." "INFO"
    
    foreach ($farm in $pvsFarmList) {
        $farmName = $farm.FarmName
        Write-Log "Processing Farm: $farmName" "INFO"
        
        # Export farm details
        $farmExportFile = Join-Path $exportFolder "Farm_$($farmName).xml"
        $farm | Export-Clixml -Path $farmExportFile
        Write-Log "Exported Farm configuration to $farmExportFile" "SUCCESS"
        
        # Get sites in the farm
        $pvsSites = Get-PvsSite -FarmId $farm.FarmId
        Write-Log "Found $($pvsSites.Count) site(s) in farm $farmName" "INFO"
        
        # Create a sites directory
        $sitesFolder = Join-Path $exportFolder "Sites"
        if (-not (Test-Path $sitesFolder)) {
            New-Item -ItemType Directory -Path $sitesFolder | Out-Null
        }
        
        # Process each site
        foreach ($site in $pvsSites) {
            $siteName = $site.SiteName
            Write-Log "Processing Site: $siteName" "INFO"
            
            # Ask if user wants to skip this site
            $exportSite = Prompt-YesNo "Do you want to export configuration for site '$siteName'?"
            
            if (-not $exportSite) {
                Write-Log "Skipping export of Site: $siteName (User choice)" "WARNING"
                continue
            }
            
            # Create site directory
            $siteFolder = Join-Path $sitesFolder $siteName
            if (-not (Test-Path $siteFolder)) {
                New-Item -ItemType Directory -Path $siteFolder | Out-Null
            }
            
            # Export site details
            $siteExportFile = Join-Path $siteFolder "SiteConfig.xml"
            $site | Export-Clixml -Path $siteExportFile
            Write-Log "Exported Site configuration for '$siteName'" "SUCCESS"
            
            # Export collections
            $collectionsFolder = Join-Path $siteFolder "Collections"
            if (-not (Test-Path $collectionsFolder)) {
                New-Item -ItemType Directory -Path $collectionsFolder | Out-Null
            }
            
            $collections = Get-PvsCollection -SiteId $site.SiteId
            Write-Log "Found $($collections.Count) collection(s) in site '$siteName'" "INFO"
            
            foreach ($collection in $collections) {
                $collectionName = $collection.CollectionName
                Write-Log "Exporting Collection: $collectionName" "INFO"
                
                $collectionExportFile = Join-Path $collectionsFolder "$collectionName.xml"
                $collection | Export-Clixml -Path $collectionExportFile
                
                # Export devices in the collection
                $devicesFolder = Join-Path $collectionsFolder "$collectionName-Devices"
                if (-not (Test-Path $devicesFolder)) {
                    New-Item -ItemType Directory -Path $devicesFolder | Out-Null
                }
                
                $devices = Get-PvsDevice -CollectionId $collection.CollectionId
                Write-Log "Found $($devices.Count) device(s) in collection '$collectionName'" "INFO"
                
                $devicesExportFile = Join-Path $devicesFolder "Devices.xml"
                $devices | Export-Clixml -Path $devicesExportFile
                
                Write-Log "Exported Collection '$collectionName' with $($devices.Count) devices" "SUCCESS"
            }
            
            # Export stores
            $storesFolder = Join-Path $siteFolder "Stores"
            if (-not (Test-Path $storesFolder)) {
                New-Item -ItemType Directory -Path $storesFolder | Out-Null
            }
            
            $stores = Get-PvsStore -SiteId $site.SiteId
            Write-Log "Found $($stores.Count) store(s) in site '$siteName'" "INFO"
            
            foreach ($store in $stores) {
                $storeName = $store.StoreName
                Write-Log "Exporting Store: $storeName" "INFO"
                
                $storeExportFile = Join-Path $storesFolder "$storeName.xml"
                $store | Export-Clixml -Path $storeExportFile
                
                # Export vDisks in the store
                $vDisksFolder = Join-Path $storesFolder "$storeName-vDisks"
                if (-not (Test-Path $vDisksFolder)) {
                    New-Item -ItemType Directory -Path $vDisksFolder | Out-Null
                }
                
                $vDisks = Get-PvsDiskInfo -StoreName $storeName
                if ($vDisks) {
                    Write-Log "Found $($vDisks.Count) vDisk(s) in store '$storeName'" "INFO"
                
                    $vDisksExportFile = Join-Path $vDisksFolder "vDisks.xml"
                    $vDisks | Export-Clixml -Path $vDisksExportFile
                    
                    Write-Log "Exported Store '$storeName' with $($vDisks.Count) vDisks" "SUCCESS"
                }
                else {
                    Write-Log "No vDisks found in store '$storeName'" "WARNING"
                }
            }
            
            # Export servers
            $serversFolder = Join-Path $siteFolder "Servers"
            if (-not (Test-Path $serversFolder)) {
                New-Item -ItemType Directory -Path $serversFolder | Out-Null
            }
            
            $servers = Get-PvsServer -SiteId $site.SiteId
            Write-Log "Found $($servers.Count) server(s) in site '$siteName'" "INFO"
            
            foreach ($server in $servers) {
                $serverName = $server.ServerName
                Write-Log "Exporting Server: $serverName" "INFO"
                
                $serverExportFile = Join-Path $serversFolder "$serverName.xml"
                $server | Export-Clixml -Path $serverExportFile
            }
            
            Write-Log "Completed export of Site: $siteName" "SUCCESS"
        }
        
        Write-Log "Completed export of Farm: $farmName" "SUCCESS"
    }
    
    # Create a zip archive of the export (optional)
    $zipFile = "$exportFolder.zip"
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::CreateFromDirectory($exportFolder, $zipFile)
        Write-Log "Created zip archive of the export at: $zipFile" "SUCCESS"
    }
    catch {
        Write-Log "Failed to create zip archive: $($_.Exception.Message)" "WARNING"
    }
    
    # Final summary
    $scriptEndTime = Get-Date
    $executionTime = $scriptEndTime - $scriptStartTime
    
    Write-Host "`n============================================================" -ForegroundColor Green
    Write-Host "        CITRIX PVS CONFIGURATION EXPORT COMPLETED" -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Green
    Write-Host "Export location: $exportFolder" -ForegroundColor Green
    Write-Host "Log file: $script:LogFile" -ForegroundColor Green
    Write-Host "Execution time: $($executionTime.TotalMinutes.ToString("0.00")) minutes" -ForegroundColor Green
    Write-Host "============================================================`n" -ForegroundColor Green
    
    Write-Log "PVS Configuration Export completed successfully" "SUCCESS"
    Write-Log "Execution time: $($executionTime.TotalMinutes.ToString("0.00")) minutes" "INFO"
}
catch {
    Write-Log "Critical error in export script: $($_.Exception.Message)" "ERROR"
    Write-Log "Stack trace: $($_.ScriptStackTrace)" "ERROR"
    
    Write-Host "`n============================================================" -ForegroundColor Red
    Write-Host "        CITRIX PVS CONFIGURATION EXPORT FAILED" -ForegroundColor Red
    Write-Host "============================================================" -ForegroundColor Red
    Write-Host "Please check the log file for details: $script:LogFile" -ForegroundColor Red
    Write-Host "============================================================`n" -ForegroundColor Red
    
    exit 1
}
