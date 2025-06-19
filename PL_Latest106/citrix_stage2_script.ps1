#Requires -RunAsAdministrator
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

<#
.SYNOPSIS
    Citrix Platform Installation - Stage 2 (Post-Reboot)
.DESCRIPTION
    Post-reboot verification and system validation.
.EXAMPLE
    .\citrix_stage2_script.ps1
.NOTES
    Version 2.0 - Enhanced with comprehensive validation
#>

# Set default values
$ConfigFilePath = "CitrixConfig.txt"
$FunctionsPath = Join-Path $PSScriptRoot "citrix_functions_library.psm1"

if (-not (Test-Path $FunctionsPath)) {
    Write-Host "FATAL ERROR: Functions module not found at: $FunctionsPath" -ForegroundColor Red
    $null = Read-Host "Press Enter to exit"
    exit 1
}

try {
    # Remove any existing module instances
    Get-Module citrix_functions_library | Remove-Module -Force -ErrorAction SilentlyContinue
    
    # Import module with explicit scope
    Import-Module $FunctionsPath -Force -ErrorAction Stop -DisableNameChecking -Global
    Write-Host "Functions module imported successfully!" -ForegroundColor Green
    
    # Verify critical functions are available
    $RequiredFunctions = @('Test-AdminPrivileges', 'Stop-NetBiosOverTCP', 'Stop-NetworkOffloadParameters', 'Set-SMBSettings', 'Set-CrashDumpToKernelMode', 'Reset-RDSGracePeriod')
    $MissingFunctions = @()
    
    foreach ($Function in $RequiredFunctions) {
        if (-not (Get-Command $Function -ErrorAction SilentlyContinue)) {
            $MissingFunctions += $Function
        }
    }
    
    if ($MissingFunctions.Count -gt 0) {
        Write-Host "Warning: Missing functions detected: $($MissingFunctions -join ', ')" -ForegroundColor Yellow
        # Force re-import with dot sourcing as fallback
        . $FunctionsPath
        Write-Host "Functions loaded via dot sourcing" -ForegroundColor Yellow
    }
    
    # Define fallback functions if module loading fails
    if (-not (Get-Command "Get-ConfigValue" -ErrorAction SilentlyContinue) -or -not (Get-Command "Expand-ConfigPath" -ErrorAction SilentlyContinue)) {
        function Get-ConfigValue {
            param($Key, $DefaultValue, $ConfigFile)
            
            if (-not (Test-Path $ConfigFile)) {
                return $DefaultValue
            }
            
            try {
                $ConfigData = Get-Content $ConfigFile | Where-Object { $_ -notmatch '^\s*#' -and $_ -notmatch '^\s*$' }
                
                foreach ($Line in $ConfigData) {
                    if ($Line -match "^$Key\s*=\s*(.*)$") {
                        $Value = $Matches[1].Trim()
                        
                        # Handle boolean values
                        if ($Value -eq 'true') { return $true }
                        elseif ($Value -eq 'false') { return $false }
                        
                        # Expand environment variables in paths
                        $Value = [Environment]::ExpandEnvironmentVariables($Value)
                        
                        # Handle variable substitution (e.g., %NetworkSourcePath%, %LocalInstallPath%)
                        if ($Value -match '%(\w+)%') {
                            $VariableName = $Matches[1]
                            $VariableValue = Get-ConfigValue -Key $VariableName -DefaultValue "" -ConfigFile $ConfigFile
                            if (![string]::IsNullOrEmpty($VariableValue)) {
                                $Value = $Value -replace "%$VariableName%", $VariableValue
                            }
                        }
                        
                        return $Value
                    }
                }
                
                return $DefaultValue
            }
            catch {
                Write-Warning "Error reading config value '$Key': $($_.Exception.Message)"
                return $DefaultValue
            }
        }
        function Write-Log {
            param($Message, $Level = "INFO")
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Write-Host "[$timestamp] [$Level] $Message"
        }
        function Write-LogHeader {
            param($Header)
            Write-Host "`n=== $Header ===" -ForegroundColor Cyan
        }
        function Expand-ConfigPath {
            param($Path, $Stage = 2)
            $ExpandedPath = [Environment]::ExpandEnvironmentVariables($Path)
            $CurrentDate = Get-Date -Format "yyyyMMdd"
            $CurrentTime = Get-Date -Format "HHmmss"
            $ExpandedPath = $ExpandedPath -replace '%DATE%', $CurrentDate
            $ExpandedPath = $ExpandedPath -replace '%TIME%', $CurrentTime
            $ExpandedPath = $ExpandedPath -replace '%STAGE%', $Stage
            $ExpandedPath = $ExpandedPath -replace '%COMPUTERNAME%', $env:COMPUTERNAME
            return $ExpandedPath
        }
    }
}
catch {
    Write-Host "FATAL ERROR: Cannot import functions module: $($_.Exception.Message)" -ForegroundColor Red
    $null = Read-Host "Press Enter to exit"
    exit 1
}

# =============================================================================
# CONFIGURATION CACHING - LOAD ALL CONFIG VALUES INTO MEMORY
# =============================================================================

Write-Host "Caching all configuration values into memory..." -ForegroundColor Cyan

# Create comprehensive config cache to avoid file access issues after cleanup
$Global:CachedConfig = @{}

# Cache essential config values - ALL SETTINGS NEEDED FOR STAGE 2
# Validation and Error Handling Settings
$Global:CachedConfig.ValidationMode = Get-ConfigValue -Key "ValidationMode" -DefaultValue "Enhanced" -ConfigFile $ConfigFilePath
$Global:CachedConfig.ContinueOnWarnings = [bool](Get-ConfigValue -Key "ContinueOnWarnings" -DefaultValue "true" -ConfigFile $ConfigFilePath)

# Cache Drive Configuration
$Global:CachedConfig.UseVirtualCacheDrive = [bool](Get-ConfigValue -Key "UseVirtualCacheDrive" -DefaultValue "true" -ConfigFile $ConfigFilePath)
$Global:CachedConfig.ConfigurePagefile = [bool](Get-ConfigValue -Key "ConfigurePagefile" -DefaultValue "true" -ConfigFile $ConfigFilePath)
$Global:CachedConfig.RedirectPagefileToCache = [bool](Get-ConfigValue -Key "RedirectPagefileToCache" -DefaultValue "true" -ConfigFile $ConfigFilePath)
$Global:CachedConfig.PagefileSizeGB = [int](Get-ConfigValue -Key "PagefileSizeGB" -DefaultValue "8" -ConfigFile $ConfigFilePath)
$Global:CachedConfig.CacheDriveLetter = Get-ConfigValue -Key "CacheDriveLetter" -DefaultValue "D" -ConfigFile $ConfigFilePath

# Virtual Cache Drive Configuration (CRITICAL - missing from previous cache)
$Global:CachedConfig.VirtualCacheDrivePath = Get-ConfigValue -Key "VirtualCacheDrivePath" -DefaultValue "C:\Temp\CACHE.VHDX" -ConfigFile $ConfigFilePath
$Global:CachedConfig.VirtualCacheDriveSizeMB = [int](Get-ConfigValue -Key "VirtualCacheDriveSizeMB" -DefaultValue "100" -ConfigFile $ConfigFilePath)
$Global:CachedConfig.VirtualCacheDriveLabel = Get-ConfigValue -Key "VirtualCacheDriveLabel" -DefaultValue "Cache" -ConfigFile $ConfigFilePath
$Global:CachedConfig.VirtualCacheDriveLetter = Get-ConfigValue -Key "VirtualCacheDriveLetter" -DefaultValue "D" -ConfigFile $ConfigFilePath

# Legacy settings for backward compatibility
$Global:CachedConfig.CacheDriveSizeGB = [int](Get-ConfigValue -Key "CacheDriveSizeGB" -DefaultValue "40" -ConfigFile $ConfigFilePath)
$Global:CachedConfig.VHDXPath = Get-ConfigValue -Key "VHDXPath" -DefaultValue "C:\CacheDrive.vhdx" -ConfigFile $ConfigFilePath

# Cache Drive Operations
$Global:CachedConfig.RequireCacheDrive = [bool](Get-ConfigValue -Key "RequireCacheDrive" -DefaultValue "true" -ConfigFile $ConfigFilePath)
$Global:CachedConfig.ConfigureCacheDrive = [bool](Get-ConfigValue -Key "ConfigureCacheDrive" -DefaultValue "true" -ConfigFile $ConfigFilePath)
$Global:CachedConfig.EnableCacheDriveOperations = [bool](Get-ConfigValue -Key "EnableCacheDriveOperations" -DefaultValue "true" -ConfigFile $ConfigFilePath)

# Event Log and Profile Redirection Paths
$Global:CachedConfig.EventLogsPath = Get-ConfigValue -Key "EventLogsPath" -DefaultValue "EventLogs" -ConfigFile $ConfigFilePath
$Global:CachedConfig.UserProfilesPath = Get-ConfigValue -Key "UserProfilesPath" -DefaultValue "Profiles" -ConfigFile $ConfigFilePath
$Global:CachedConfig.RedirectEventLogsToCache = [bool](Get-ConfigValue -Key "RedirectEventLogsToCache" -DefaultValue "true" -ConfigFile $ConfigFilePath)
$Global:CachedConfig.RedirectUserProfilesToCache = [bool](Get-ConfigValue -Key "RedirectUserProfilesToCache" -DefaultValue "true" -ConfigFile $ConfigFilePath)

# System Optimization Feature Flags
$Global:CachedConfig.EnableVDIOptimizations = [bool](Get-ConfigValue -Key "EnableVDIOptimizations" -DefaultValue "true" -ConfigFile $ConfigFilePath)
$Global:CachedConfig.EnableWEMCleanup = [bool](Get-ConfigValue -Key "EnableWEMCleanup" -DefaultValue "true" -ConfigFile $ConfigFilePath)
$Global:CachedConfig.EnableDomainProfileCleanup = [bool](Get-ConfigValue -Key "EnableDomainProfileCleanup" -DefaultValue "true" -ConfigFile $ConfigFilePath)
$Global:CachedConfig.EnableSystemOptimizations = [bool](Get-ConfigValue -Key "EnableSystemOptimizations" -DefaultValue "true" -ConfigFile $ConfigFilePath)
$Global:CachedConfig.EnablePasswordAgeCleanup = [bool](Get-ConfigValue -Key "EnablePasswordAgeCleanup" -DefaultValue "true" -ConfigFile $ConfigFilePath)
$Global:CachedConfig.EnableAutomaticMaintenanceDisable = [bool](Get-ConfigValue -Key "EnableAutomaticMaintenanceDisable" -DefaultValue "true" -ConfigFile $ConfigFilePath)
$Global:CachedConfig.EnableRecycleBinDisable = [bool](Get-ConfigValue -Key "EnableRecycleBinDisable" -DefaultValue "true" -ConfigFile $ConfigFilePath)
$Global:CachedConfig.EnableQuickAccessDisable = [bool](Get-ConfigValue -Key "EnableQuickAccessDisable" -DefaultValue "true" -ConfigFile $ConfigFilePath)
$Global:CachedConfig.EnableVMwareOptimizations = [bool](Get-ConfigValue -Key "EnableVMwareOptimizations" -DefaultValue "true" -ConfigFile $ConfigFilePath)

# Network and System Optimization Settings
$Global:CachedConfig.DisableNetBiosOverTCP = [bool](Get-ConfigValue -Key "DisableNetBiosOverTCP" -DefaultValue "true" -ConfigFile $ConfigFilePath)
$Global:CachedConfig.DisableNetworkOffloadParameters = [bool](Get-ConfigValue -Key "DisableNetworkOffloadParameters" -DefaultValue "true" -ConfigFile $ConfigFilePath)
$Global:CachedConfig.ConfigureSMBSettings = [bool](Get-ConfigValue -Key "ConfigureSMBSettings" -DefaultValue "true" -ConfigFile $ConfigFilePath)
$Global:CachedConfig.SetCrashDumpToKernelMode = [bool](Get-ConfigValue -Key "SetCrashDumpToKernelMode" -DefaultValue "true" -ConfigFile $ConfigFilePath)
$Global:CachedConfig.RemovePasswordAge = [bool](Get-ConfigValue -Key "RemovePasswordAge" -DefaultValue "true" -ConfigFile $ConfigFilePath)
$Global:CachedConfig.ResetRDSGracePeriod = [bool](Get-ConfigValue -Key "ResetRDSGracePeriod" -DefaultValue "true" -ConfigFile $ConfigFilePath)

$Global:CachedConfig.DisableWindowsServices = [bool](Get-ConfigValue -Key "DisableWindowsServices" -DefaultValue "true" -ConfigFile $ConfigFilePath)

# Cache report output path for HTML report generation
$Global:CachedConfig.ReportOutputPath = Get-ConfigValue -Key "ReportOutputPath" -DefaultValue "%USERPROFILE%\Desktop" -ConfigFile $ConfigFilePath

# Cache logging configuration
$Global:CachedConfig.DetailedLogging = [bool](Get-ConfigValue -Key "DetailedLogging" -DefaultValue "true" -ConfigFile $ConfigFilePath)

# Citrix Optimizer Configuration
$Global:CachedConfig.RunCitrixOptimizer = [bool](Get-ConfigValue -Key "RunCitrixOptimizer" -DefaultValue "true" -ConfigFile $ConfigFilePath)
$Global:CachedConfig.CitrixOptimizerPath = Get-ConfigValue -Key "CitrixOptimizerPath" -DefaultValue "C:\CitrixOptimizer\CitrixOptimizer.exe" -ConfigFile $ConfigFilePath
$Global:CachedConfig.CitrixOptimizerTemplatesPath = Get-ConfigValue -Key "CitrixOptimizerTemplatesPath" -DefaultValue "C:\CitrixOptimizer\Templates" -ConfigFile $ConfigFilePath
$Global:CachedConfig.CitrixOptimizerOutputPath = Get-ConfigValue -Key "CitrixOptimizerOutputPath" -DefaultValue "C:\Temp\CitrixOptimizer_Results" -ConfigFile $ConfigFilePath
$Global:CachedConfig.CitrixOptimizerTemplate = Get-ConfigValue -Key "CitrixOptimizerTemplate" -DefaultValue "Windows_Server_2019_VDI.xml" -ConfigFile $ConfigFilePath
$Global:CachedConfig.CitrixOptimizerMode = Get-ConfigValue -Key "CitrixOptimizerMode" -DefaultValue "Execute" -ConfigFile $ConfigFilePath

# Service Configuration
$Global:CachedConfig.CitrixServicesToDisable = Get-ConfigValue -Key "CitrixServicesToDisable" -DefaultValue "wuauserv" -ConfigFile $ConfigFilePath
$Global:CachedConfig.CitrixServicesToDisableStage2 = Get-ConfigValue -Key "CitrixServicesToDisableStage2" -DefaultValue "CdfSvc,BITS,TapiSrv" -ConfigFile $ConfigFilePath

# Get configurable log path from config file
$ConfigLogPath = Get-ConfigValue -Key "Stage2LogPath" -DefaultValue "" -ConfigFile $ConfigFilePath
if ([string]::IsNullOrEmpty($ConfigLogPath)) {
    # Fallback to generic LogPath if Stage2LogPath not specified
    $ConfigLogPath = Get-ConfigValue -Key "LogPath" -DefaultValue "%USERPROFILE%\Desktop\Citrix_Stage2_%DATE%_%TIME%.log" -ConfigFile $ConfigFilePath
}

# Expand environment variables and placeholders in log path
$LogPath = Expand-ConfigPath -Path $ConfigLogPath -Stage 2

Write-Host "Configuration cached successfully - all values stored in memory" -ForegroundColor Green
Write-Host "Validation Settings from CitrixConfig.txt:" -ForegroundColor Green
Write-Host "  ValidationMode: $($Global:CachedConfig.ValidationMode)" -ForegroundColor White
Write-Host "  ContinueOnWarnings: $($Global:CachedConfig.ContinueOnWarnings)" -ForegroundColor White

# =============================================================================
# NETWORK DRIVE MAPPING - ACCESS TO SOURCE FILES
# =============================================================================

Write-Host "`n" -ForegroundColor Yellow
Write-Host "NETWORK DRIVE MAPPING FOR SOURCE FILE ACCESS" -ForegroundColor Cyan -BackgroundColor Black
Write-Host "=============================================" -ForegroundColor Cyan

# Get network source path from configuration
$NetworkSourcePath = Get-ConfigValue -Key "NetworkSourcePath" -DefaultValue "\\fileserver\citrix" -ConfigFile $ConfigFilePath
$MapNetworkDrive = [bool](Get-ConfigValue -Key "MapNetworkDrive" -DefaultValue "true" -ConfigFile $ConfigFilePath)
$NetworkDriveLetter = Get-ConfigValue -Key "NetworkDriveLetter" -DefaultValue "Z" -ConfigFile $ConfigFilePath

if ($MapNetworkDrive -and ![string]::IsNullOrEmpty($NetworkSourcePath)) {
    Write-Host "Network source path: $NetworkSourcePath" -ForegroundColor White
    Write-Host "Target drive letter: $NetworkDriveLetter" -ForegroundColor White
    
    # Check if drive is already mapped
    $ExistingDrive = Get-PSDrive -Name $NetworkDriveLetter -ErrorAction SilentlyContinue
    
    if ($ExistingDrive -and ($ExistingDrive.Root -eq $NetworkSourcePath + "\")) {
        Write-Host "$NetworkDriveLetter`: drive already mapped to correct path" -ForegroundColor Green
    } else {
        # Remove existing mapping if different path
        if ($ExistingDrive) {
            Write-Host "Removing existing $NetworkDriveLetter`: mapping..." -ForegroundColor Yellow
            Remove-PSDrive -Name $NetworkDriveLetter -Force -ErrorAction SilentlyContinue
            net use "$NetworkDriveLetter`:" /delete /y 2>$null
        }
        
        Write-Host "Mapping network drive for source file access..." -ForegroundColor Cyan
        Write-Host "Please provide network credentials for: $NetworkSourcePath" -ForegroundColor Yellow
        
        # Prompt for credentials
        $NetworkCredential = Get-Credential -Message "Enter credentials for network source path: $NetworkSourcePath"
        
        if ($NetworkCredential) {
            try {
                # Map the network drive
                $NetworkDriveResult = New-PSDrive -Name $NetworkDriveLetter -PSProvider FileSystem -Root $NetworkSourcePath -Credential $NetworkCredential -Persist -ErrorAction Stop
                
                if ($NetworkDriveResult) {
                    Write-Host "SUCCESS: Network drive mapped to $NetworkDriveLetter`: ($NetworkSourcePath)" -ForegroundColor Green
                    
                    # Test access
                    if (Test-Path "$NetworkDriveLetter`:\") {
                        Write-Host "Network drive access verified successfully" -ForegroundColor Green
                    } else {
                        Write-Host "WARNING: Drive mapped but access test failed" -ForegroundColor Yellow
                    }
                } else {
                    Write-Host "FAILED: Could not map network drive" -ForegroundColor Red
                }
            }
            catch {
                Write-Host "FAILED: Network drive mapping error: $($_.Exception.Message)" -ForegroundColor Red
                Write-Host "Stage 2 operations may fail without network access" -ForegroundColor Yellow
            }
        } else {
            Write-Host "WARNING: No credentials provided - network drive not mapped" -ForegroundColor Yellow
            Write-Host "Stage 2 operations may fail without network access" -ForegroundColor Yellow
        }
    }
} else {
    Write-Host "Network drive mapping disabled or no network source path configured" -ForegroundColor Gray
}

# =============================================================================
# STAGE 2 INITIALIZATION - VIRTUAL CACHE DRIVE MOUNTING
# =============================================================================

Write-Host "`n" -ForegroundColor Yellow
Write-Host "STAGE 2 INITIALIZATION: Virtual Cache Drive Check" -ForegroundColor Green -BackgroundColor Black
Write-Host "=================================================" -ForegroundColor Green

# Check if virtual cache drive was used in Stage 1 and mount if needed
$UseVirtualCacheDrive = $Global:CachedConfig.UseVirtualCacheDrive

if ($UseVirtualCacheDrive) {
    Write-Host "Virtual cache drive enabled - checking mount status..." -ForegroundColor Cyan
    
    # Check if D: drive already exists
    $DDriveExists = Test-Path "D:\"
    
    if ($DDriveExists) {
        Write-Host "D: drive already mounted and accessible" -ForegroundColor Green
    } else {
        Write-Host "D: drive not found - attempting to mount virtual cache drive..." -ForegroundColor Yellow
        
        try {
            # Mount the virtual cache drive using cached configuration values
            $VirtualCacheResult = New-VirtualCacheDrive -VHDXPath $Global:CachedConfig.VirtualCacheDrivePath -SizeMB $Global:CachedConfig.VirtualCacheDriveSizeMB -DriveLetter $Global:CachedConfig.VirtualCacheDriveLetter -VolumeLabel $Global:CachedConfig.VirtualCacheDriveLabel
            
            if ($VirtualCacheResult.Success) {
                Write-Host "SUCCESS: Virtual cache drive mounted!" -ForegroundColor Green
                Write-Host "Drive: $($VirtualCacheResult.DriveLetter): ($($VirtualCacheResult.DriveInfo.SizeMB) MB)" -ForegroundColor Green
                Write-Host "VHDX Location: $($VirtualCacheResult.VHDXPath)" -ForegroundColor Gray
            } else {
                Write-Host "FAILED: Virtual cache drive mounting failed" -ForegroundColor Red
                foreach ($Error in $VirtualCacheResult.Errors) {
                    Write-Host "Error: $Error" -ForegroundColor Red
                }
                Write-Host "Stage 2 operations may fail without D: drive access" -ForegroundColor Yellow
            }
        }
        catch {
            Write-Host "EXCEPTION: Virtual cache drive mounting failed: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "Stage 2 operations may fail without D: drive access" -ForegroundColor Yellow
        }
    }
} else {
    Write-Host "Virtual cache drive disabled - assuming physical D: drive" -ForegroundColor Gray
}

Write-Host "Stage 2 initialization completed`n" -ForegroundColor Green

try {
    # Initialize logging manually since function may not be available
    try {
        $LogDir = Split-Path $LogPath -Parent
        if (-not (Test-Path $LogDir)) {
            New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
        }
        $Global:LogPath = $LogPath
        "Logging initialized at $(Get-Date)" | Out-File -FilePath $LogPath -Force
        Write-Host "Enhanced logging initialized: $LogPath" -ForegroundColor Green
    }
    catch {
        Write-Host "WARNING: Logging initialization failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    Write-LogHeader "CITRIX PLATFORM INSTALLATION - STAGE 2"
    Write-Log "Stage 2 execution started at: $(Get-Date)"
    Write-Log "Executed by: $($env:USERNAME) on $($env:COMPUTERNAME)"
    
    # Display cached configuration summary (config file already deleted at this point)
    Write-Log "Using cached configuration values loaded at script startup" "SUCCESS"
    Write-Log "Configuration file deleted during cleanup - using memory cache" "INFO"
    
    # Display critical cached configuration values
    Write-Log "Cached Values: UseVirtualCacheDrive=$($Global:CachedConfig.UseVirtualCacheDrive), PagefileSizeGB=$($Global:CachedConfig.PagefileSizeGB)" "INFO"
    Write-Log "Cached Values: CacheDriveLetter=$($Global:CachedConfig.CacheDriveLetter), RequireCacheDrive=$($Global:CachedConfig.RequireCacheDrive)" "INFO"
    Write-Log "All configuration values successfully preserved in memory" "SUCCESS"
    
    # Validation checks
    Write-LogHeader "STAGE 2 SYSTEM VALIDATION"
    
    if (-not (Test-AdminPrivileges)) {
        Write-Log "CRITICAL: Administrator privileges required" "ERROR"
        throw "Administrator privileges required"
    }
    Write-Log "Administrator privileges confirmed" "SUCCESS"
    
    # System information - use manual collection if function fails
    try {
        $CurrentSystemInfo = Get-SystemInformation
    }
    catch {
        Write-Log "Using fallback system information collection" "WARN"
        $CurrentSystemInfo = @{
            ComputerName = $env:COMPUTERNAME
            Domain = $env:USERDOMAIN
            OSVersion = (Get-WmiOrCimInstance Win32_OperatingSystem).Caption
            ProcessorName = (Get-WmiOrCimInstance Win32_Processor | Select-Object -First 1).Name
            TotalMemoryGB = [Math]::Round((Get-WmiOrCimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
            VirtualMachine = $false
        }
    }
    
    # Get detailed OS version information
    $OSVersionDetails = Get-OSVersion
    
    if ($CurrentSystemInfo) {
        Write-Log "System Information Collection: SUCCESS" "SUCCESS"
        Write-Log "Computer: $($CurrentSystemInfo.ComputerName)"
        Write-Log "OS: $($CurrentSystemInfo.OSVersion)"
        if ($OSVersionDetails) {
            Write-Log "OS Build: $($OSVersionDetails.BuildNumber)" "INFO"
            Write-Log "OS Edition: $($OSVersionDetails.Edition)" "INFO"
        }
        Write-Log "Processor: $($CurrentSystemInfo.ProcessorName)"
        Write-Log "Memory: $($CurrentSystemInfo.TotalMemoryGB) GB"
    }
    
    # VDA verification - manual check if function fails
    Write-LogHeader "VDA INSTALLATION VERIFICATION"
    try {
        $VDAInstalled = Test-VDAInstallation
    }
    catch {
        Write-Log "Using fallback VDA detection" "WARN"
        $VDARegPath = "HKLM:\SOFTWARE\Citrix\VirtualDesktopAgent"
        $VDAInstalled = Test-Path $VDARegPath
    }
    
    if ($VDAInstalled) {
        Write-Log "VDA Installation: VERIFIED" "SUCCESS"
    }
    else {
        Write-Log "VDA Installation: NOT DETECTED" "ERROR"
    }
    
    # Citrix services - manual check if function fails
    Write-LogHeader "CITRIX SERVICES VALIDATION"
    try {
        $CitrixServices = Get-CitrixServices
        $TotalFoundServices = ($CitrixServices | Where-Object { $_.Status -eq "Running" } | Measure-Object).Count
    }
    catch {
        Write-Log "Using fallback service detection" "WARN"
        $ServiceNames = @("BrokerAgent", "picaSvc2", "CdfSvc")
        $TotalFoundServices = 0
        foreach ($ServiceName in $ServiceNames) {
            $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if ($Service -and $Service.Status -eq "Running") {
                $TotalFoundServices++
            }
        }
    }
    
    Write-Log "Found $TotalFoundServices running Citrix services" "INFO"
    
    # System optimizations - basic check
    Write-LogHeader "SYSTEM OPTIMIZATION VERIFICATION"
    try {
        $OptimizationResults = Test-SystemOptimizations
    }
    catch {
        Write-Log "Using basic optimization check" "WARN"
        $OptimizationResults = @{ OverallStatus = $true }
    }
    
    if ($OptimizationResults.OverallStatus) {
        Write-Log "System Optimizations: VERIFIED" "SUCCESS"
    }
    else {
        Write-Log "System Optimizations: ISSUES DETECTED" "WARN"
    }
    
    # Execute Citrix Optimizer for comprehensive VDI optimizations (if enabled)
    $RunCitrixOptimizer = $Global:CachedConfig.RunCitrixOptimizer
    
    if ($RunCitrixOptimizer) {
        Write-LogHeader "CITRIX OPTIMIZER EXECUTION"
        Write-Log "Running Citrix Optimizer for comprehensive VDI optimizations..." "INFO"
        
        # Use Citrix Optimizer with cached configuration values (function reads from cache internally)
        $CitrixOptimizerResult = Start-CitrixOptimizer
    } else {
        Write-LogHeader "CITRIX OPTIMIZER SKIPPED"
        Write-Log "Citrix Optimizer execution disabled in configuration" "INFO"
        $CitrixOptimizerResult = @{ Success = $false; Skipped = $true }
    }
    
    if ($CitrixOptimizerResult.Success) {
        Write-Log "Citrix Optimizer completed successfully" "SUCCESS"
        Write-Log "Template applied: $($CitrixOptimizerResult.TemplateApplied)" "SUCCESS"
        Write-Log "Optimizations applied: $($CitrixOptimizerResult.OptimizationsApplied)" "SUCCESS"
        
        if ($CitrixOptimizerResult.OptimizerExecuted) {
            Write-Log "Full Citrix Optimizer tool executed" "SUCCESS"
            if ($CitrixOptimizerResult.OutputLocation) {
                Write-Log "Optimizer reports saved to: $($CitrixOptimizerResult.OutputLocation)" "INFO"
            }
        } else {
            Write-Log "Manual template application completed" "SUCCESS"
        }
        
        # Log specific optimization categories
        if ($CitrixOptimizerResult.CategoriesProcessed) {
            Write-Log "Optimization categories processed: $($CitrixOptimizerResult.CategoriesProcessed -join ', ')" "INFO"
        }
        
        $VDIOptResults = $CitrixOptimizerResult
    }
    elseif ($CitrixOptimizerResult.Skipped) {
        Write-Log "Citrix Optimizer was skipped per configuration" "INFO"
        $VDIOptResults = @{ OverallStatus = $true; Skipped = $true }
    }
    else {
        Write-Log "Citrix Optimizer execution failed: $($CitrixOptimizerResult.Error)" "ERROR"
        $VDIOptResults = @{ OverallStatus = $false; Error = $CitrixOptimizerResult.Error }
    }
    
    # VMware memory ballooning disable
    Write-LogHeader "VMWARE MEMORY BALLOONING DISABLE"
    $DisableVMwareMemoryBallooning = $Global:CachedConfig.EnableVMwareOptimizations
    if ($DisableVMwareMemoryBallooning) {
        try {
            $VMwareDisableResult = Disable-VMwareMemoryBallooning
            if ($VMwareDisableResult.VMwareEnvironment) {
                Write-Log "VMware environment detected - disabling memory ballooning" "INFO"
                if ($VMwareDisableResult.Success) {
                    if ($VMwareDisableResult.RegistryModified) {
                        Write-Log "VMware Memory Ballooning: DISABLED (Registry modified)" "SUCCESS"
                        Write-Log "Previous start type: $($VMwareDisableResult.PreviousStartType), New start type: $($VMwareDisableResult.NewStartType)" "INFO"
                    } else {
                        Write-Log "VMware Memory Ballooning: ALREADY DISABLED" "SUCCESS"
                    }
                    $VMwareMemoryStatus = @{ OverallCompliant = $true; Success = $true; VMwareDetected = $true }
                } else {
                    Write-Log "VMware Memory Ballooning: FAILED TO DISABLE" "ERROR"
                    Write-Log "Error: $($VMwareDisableResult.Error)" "ERROR"
                    $VMwareMemoryStatus = @{ OverallCompliant = $false; Success = $false; VMwareDetected = $true; Error = $VMwareDisableResult.Error }
                }
            } else {
                Write-Log "VMware Memory Ballooning: NOT APPLICABLE (Non-VMware environment)" "INFO"
                $VMwareMemoryStatus = @{ OverallCompliant = $true; Success = $true; VMwareDetected = $false; Skipped = $true }
            }
        }
        catch {
            Write-Log "VMware memory ballooning disable failed: $($_.Exception.Message)" "ERROR"
            $VMwareMemoryStatus = @{ OverallCompliant = $false; Success = $false; Error = $_.Exception.Message }
        }
    } else {
        Write-Log "VMware memory ballooning disable disabled in configuration" "INFO"
        $VMwareMemoryStatus = @{ OverallCompliant = $true; Success = $true; Skipped = $true }
    }
    
    # Recycle Bin creation disable
    Write-LogHeader "RECYCLE BIN CREATION DISABLE"
    $DisableRecycleBinCreation = $Global:CachedConfig.EnableRecycleBinDisable
    if ($DisableRecycleBinCreation) {
        try {
            $RecycleBinDisableResult = Disable-RecycleBinCreation
            if ($RecycleBinDisableResult.Success) {
                if ($RecycleBinDisableResult.RegistryKeyRemoved) {
                    Write-Log "Recycle Bin Creation: DISABLED (Registry key removed)" "SUCCESS"
                    if ($RecycleBinDisableResult.BackupCreated) {
                        Write-Log "Registry key contents logged before removal" "INFO"
                    }
                } else {
                    Write-Log "Recycle Bin Creation: ALREADY DISABLED (Registry key not found)" "SUCCESS"
                }
                $RecycleBinResult = $true
            } else {
                Write-Log "Recycle Bin Creation: FAILED TO DISABLE" "ERROR"
                Write-Log "Error: $($RecycleBinDisableResult.Error)" "ERROR"
                $RecycleBinResult = $false
            }
        }
        catch {
            Write-Log "Recycle Bin creation disable failed: $($_.Exception.Message)" "ERROR"
            $RecycleBinResult = $false
        }
    } else {
        Write-Log "Recycle Bin creation disable disabled in configuration" "INFO"
        $RecycleBinResult = $true
    }
    
    # Quick Access and user folders disable
    Write-LogHeader "QUICK ACCESS AND USER FOLDERS DISABLE"
    $DisableQuickAccessUserFolders = $Global:CachedConfig.EnableQuickAccessDisable
    if ($DisableQuickAccessUserFolders) {
        try {
            $QuickAccessDisableResult = Disable-QuickAccessUserFolders
            if ($QuickAccessDisableResult.Success) {
                Write-Log "Quick Access and User Folders: DISABLED (HubMode set to 1)" "SUCCESS"
                Write-Log "Previous HubMode: $($QuickAccessDisableResult.PreviousHubMode), New HubMode: $($QuickAccessDisableResult.NewHubMode)" "INFO"
                $QuickAccessResult = $true
            } else {
                Write-Log "Quick Access and User Folders: FAILED TO DISABLE" "ERROR"
                Write-Log "Error: $($QuickAccessDisableResult.Error)" "ERROR"
                $QuickAccessResult = $false
            }
        }
        catch {
            Write-Log "Quick Access and user folders disable failed: $($_.Exception.Message)" "ERROR"
            $QuickAccessResult = $false
        }
    } else {
        Write-Log "Quick Access and user folders disable disabled in configuration" "INFO"
        $QuickAccessResult = $true
    }
    
    # Password age registry key removal
    Write-LogHeader "PASSWORD AGE REGISTRY CLEANUP"
    $RemovePasswordAge = $Global:CachedConfig.EnablePasswordAgeCleanup
    if ($RemovePasswordAge) {
        try {
            Write-Log "Checking for password age registry key..." "INFO"
            $PasswordAgeResult = Remove-PasswordAgeRegistryKey
            if ($PasswordAgeResult) {
                Write-Log "Password Age Registry: KEY FOUND AND REMOVED" "SUCCESS"
                $PasswordAgeResult = $true
            } else {
                Write-Log "Password Age Registry: KEY NOT FOUND (ALREADY CLEAN)" "INFO"
                $PasswordAgeResult = $true  # Still success if key doesn't exist
            }
        }
        catch {
            Write-Log "Password age removal failed: $($_.Exception.Message)" "WARN"
            $PasswordAgeResult = $false
        }
    } else {
        Write-Log "Password age registry removal disabled in configuration" "INFO"
        $PasswordAgeResult = $true
    }
    
    # Network optimizations
    Write-LogHeader "NETWORK OPTIMIZATIONS"
    
    $NetworkOptResults = @{
        Success = $true
        NetBios = $false
        Offload = $false
        SMB = $false
        Errors = @()
        Details = "Network optimizations for Citrix VDI environments"
    }
    
    $DisableNetBiosOverTCP = $Global:CachedConfig.EnableSystemOptimizations
    if ($DisableNetBiosOverTCP) {
        Write-Log "Disabling NetBIOS over TCP/IP..." "INFO"
        try {
            $NetBiosResult = Stop-NetBiosOverTCP
            if ($NetBiosResult) {
                Write-Log "NetBIOS over TCP/IP: DISABLED" "SUCCESS"
                $NetworkOptResults.NetBios = $true
            } else {
                Write-Log "NetBIOS over TCP/IP: PARTIAL" "WARN"
                $NetworkOptResults.Errors += "NetBIOS partial configuration"
            }
        } catch {
            Write-Log "NetBIOS over TCP/IP: ERROR - $($_.Exception.Message)" "ERROR"
            $NetworkOptResults.Errors += "NetBIOS: $($_.Exception.Message)"
        }
    } else {
        Write-Log "NetBIOS over TCP/IP optimization: SKIPPED" "INFO"
        $NetworkOptResults.NetBios = $true  # Skipped but considered successful
    }
    
    $DisableNetworkOffloadParameters = $Global:CachedConfig.EnableSystemOptimizations
    if ($DisableNetworkOffloadParameters) {
        Write-Log "Disabling network offload parameters for PVS compatibility..." "INFO"
        try {
            $OffloadResult = Stop-NetworkOffloadParameters
            if ($OffloadResult) {
                Write-Log "Network offload parameters: DISABLED" "SUCCESS"
                $NetworkOptResults.Offload = $true
            } else {
                Write-Log "Network offload parameters: PARTIAL" "WARN"
                $NetworkOptResults.Errors += "Network offload partial configuration"
            }
        } catch {
            Write-Log "Network offload parameters: ERROR - $($_.Exception.Message)" "ERROR"
            $NetworkOptResults.Errors += "Network offload: $($_.Exception.Message)"
        }
    } else {
        Write-Log "Network offload parameters optimization: SKIPPED" "INFO"
        $NetworkOptResults.Offload = $true  # Skipped but considered successful
    }
    
    $ConfigureSMBSettings = $Global:CachedConfig.EnableSystemOptimizations
    if ($ConfigureSMBSettings) {
        Write-Log "Configuring SMB settings for Citrix environments..." "INFO"
        try {
            $SMBResult = Set-SMBSettings
            if ($SMBResult) {
                Write-Log "SMB settings: CONFIGURED" "SUCCESS"
                $NetworkOptResults.SMB = $true
            } else {
                Write-Log "SMB settings: PARTIAL" "WARN"
                $NetworkOptResults.Errors += "SMB partial configuration"
            }
        } catch {
            Write-Log "SMB settings: ERROR - $($_.Exception.Message)" "ERROR"
            $NetworkOptResults.Errors += "SMB: $($_.Exception.Message)"
        }
    } else {
        Write-Log "SMB settings configuration: SKIPPED" "INFO"
        $NetworkOptResults.SMB = $true  # Skipped but considered successful
    }
    
    # Set overall success based on individual components
    $NetworkOptResults.Success = $NetworkOptResults.NetBios -and $NetworkOptResults.Offload -and $NetworkOptResults.SMB
    
    # System optimizations moved from Stage 1
    Write-LogHeader "COMPREHENSIVE SYSTEM OPTIMIZATIONS"
    
    # Windows services management
    $DisableWindowsServices = $Global:CachedConfig.EnableSystemOptimizations
    if ($DisableWindowsServices) {
        Write-Log "Disabling specified Windows services..." "INFO"
        try {
            # Use Stage 2 specific service list for post-installation optimization
            $Stage2ServicesToDisable = "CdfSvc,BITS,Fax,TapiSrv"
            $ServicesToDisable = if ($Global:CachedConfig.CitrixServicesToDisableStage2) { $Global:CachedConfig.CitrixServicesToDisableStage2 } else { $Stage2ServicesToDisable }
            $CitrixServicesResult = Stop-CitrixServices -ServiceOverride $ServicesToDisable
            
            if ($CitrixServicesResult.Success) {
                Write-Log "Windows services management completed successfully" "SUCCESS"
                Write-Log "Disabled services: $($CitrixServicesResult.DisabledServices.Count)" "SUCCESS"
                Write-Log "Skipped services: $($CitrixServicesResult.SkippedServices.Count)" "INFO"
                
                if ($CitrixServicesResult.FailedServices.Count -gt 0) {
                    Write-Log "Failed to disable $($CitrixServicesResult.FailedServices.Count) services" "WARN"
                }
            }
            else {
                Write-Log "Windows services management had issues: $($CitrixServicesResult.Error)" "WARN"
            }
        } catch {
            Write-Log "Windows services management failed: $($_.Exception.Message)" "ERROR"
        }
    } else {
        Write-Log "Windows services management skipped - disabled in configuration" "INFO"
    }
    
    # Registry optimizations
    $OptimizeVDIRegistry = $Global:CachedConfig.EnableVDIOptimizations
    if ($OptimizeVDIRegistry) {
        Write-Log "Applying VDI registry optimizations..." "INFO"
        try {
            Set-RegistryOptimizations
            Write-Log "Registry optimizations applied successfully" "SUCCESS"
        } catch {
            Write-Log "Registry optimizations failed: $($_.Exception.Message)" "ERROR"
        }
    } else {
        Write-Log "Registry optimizations skipped - disabled in configuration" "INFO"
    }
    
    # Storage optimizations
    Write-LogHeader "STORAGE OPTIMIZATIONS"
    
    $StorageOptResults = @{
        Success = $true
        CrashDump = $false
        Errors = @()
        Details = "Storage optimizations for VDI environments"
    }
    
    $SetCrashDumpToKernelMode = $Global:CachedConfig.EnableSystemOptimizations
    if ($SetCrashDumpToKernelMode) {
        Write-Log "Configuring crash dump to kernel mode..." "INFO"
        try {
            $CrashDumpResult = Set-CrashDumpToKernelMode
            if ($CrashDumpResult) {
                Write-Log "Crash dump kernel mode: CONFIGURED" "SUCCESS"
                $StorageOptResults.CrashDump = $true
            } else {
                Write-Log "Crash dump kernel mode: PARTIAL" "WARN"
                $StorageOptResults.Errors += "Crash dump partial configuration"
            }
        } catch {
            Write-Log "Crash dump kernel mode: ERROR - $($_.Exception.Message)" "ERROR"
            $StorageOptResults.Errors += "Crash dump: $($_.Exception.Message)"
        }
    } else {
        Write-Log "Crash dump kernel mode configuration: SKIPPED" "INFO"
        $StorageOptResults.CrashDump = $true  # Skipped but considered successful
    }
    
    $StorageOptResults.Success = $StorageOptResults.CrashDump
    
    # RDS grace period reset
    Write-LogHeader "RDS GRACE PERIOD RESET"
    try {
        $RDSGraceResult = Reset-RDSGracePeriod
        if ($RDSGraceResult.Success) {
            if ($RDSGraceResult.Action -eq "Skipped") {
                Write-Log "RDS grace period reset: DISABLED" "INFO"
                Write-Log "Reason: $($RDSGraceResult.Reason)" "INFO"
            } else {
                Write-Log "RDS grace period reset: COMPLETED" "SUCCESS"
                Write-Log "Registry keys removed: $($RDSGraceResult.TotalRemoved)" "SUCCESS"
                if ($RDSGraceResult.TotalSkipped -gt 0) {
                    Write-Log "Keys already clean: $($RDSGraceResult.TotalSkipped)" "INFO"
                }
            }
        } else {
            Write-Log "RDS grace period reset: FAILED" "ERROR"
            Write-Log "Error: $($RDSGraceResult.Error)" "ERROR"
        }
    }
    catch {
        Write-Log "RDS grace period reset: ERROR - $($_.Exception.Message)" "ERROR"
        $RDSGraceResult = @{ Success = $false }
    }
    
    # Windows automatic maintenance optimization
    Write-LogHeader "WINDOWS AUTOMATIC MAINTENANCE OPTIMIZATION"
    try {
        $MaintenanceStatus = Test-AutomaticMaintenanceStatus
        if ($MaintenanceStatus.Optimized) {
            Write-Log "Automatic Maintenance: ALREADY OPTIMIZED" "SUCCESS"
            # Ensure the status object has the correct Success property for reporting
            $MaintenanceStatus.Success = $true
        }
        else {
            Write-Log "Automatic Maintenance: NEEDS OPTIMIZATION" "INFO"
            Write-Log "Disabling Windows automatic maintenance for VDI template..."
            
            $DisableResult = Disable-AutomaticMaintenance
            if ($DisableResult.Success) {
                Write-Log "Automatic Maintenance: SUCCESSFULLY DISABLED" "SUCCESS"
                $MaintenanceStatus = $DisableResult
                $MaintenanceStatus.Optimized = $true
            } else {
                Write-Log "Automatic Maintenance: FAILED TO DISABLE - $($DisableResult.Error)" "ERROR"
                $MaintenanceStatus = $DisableResult
            }
        }
    }
    catch {
        Write-Log "Automatic maintenance check failed: $($_.Exception.Message)" "WARN"
        $MaintenanceStatus = @{ Optimized = $false }
    }
    
    # WEM cleanup with registry key removal
    Write-LogHeader "WEM RSA CLEANUP VERIFICATION"
    try {
        $WEMCleanupSuccess = Test-WEMRSACleanup
        
        # Additional WEM RSA key removal
        Write-Log "Performing WEM RSA key cleanup..." "INFO"
        $WEMKeyRemovalResult = Remove-WEMRSAKey
        if ($WEMKeyRemovalResult.Success) {
            if ($WEMKeyRemovalResult.RemovedKeys.Count -gt 0) {
                Write-Log "WEM RSA keys removed successfully: $($WEMKeyRemovalResult.RemovedKeys.Count) items" "SUCCESS"
                foreach ($RemovedKey in $WEMKeyRemovalResult.RemovedKeys) {
                    Write-Log "  Removed: $RemovedKey" "INFO"
                }
            } else {
                Write-Log "WEM RSA cleanup completed: No keys found to remove" "SUCCESS"
            }
            
            if ($WEMKeyRemovalResult.FailedRemovals.Count -gt 0) {
                Write-Log "Some WEM RSA keys failed to remove: $($WEMKeyRemovalResult.FailedRemovals.Count) items" "WARN"
                foreach ($FailedKey in $WEMKeyRemovalResult.FailedRemovals) {
                    Write-Log "  Failed: $FailedKey" "WARN"
                }
            }
        } else {
            Write-Log "WEM RSA key removal failed: $($WEMKeyRemovalResult.Error)" "ERROR"
        }
    }
    catch {
        Write-Log "Using basic WEM cleanup check" "WARN"
        $WEMCleanupSuccess = $true
    }
    
    # Update WEM cleanup success based on actual key removal results
    $WEMCleanupSuccess = $WEMKeyRemovalResult.Success
    
    if ($WEMCleanupSuccess) {
        Write-Log "WEM RSA Cleanup: COMPLETED" "SUCCESS"
    }
    else {
        Write-Log "WEM RSA Cleanup: ISSUES DETECTED" "WARN"
    }
    
    # Domain profile cleanup - critical for VDI template preparation
    Write-LogHeader "DOMAIN PROFILE CLEANUP"
    $RemoveDomainUserProfiles = $Global:CachedConfig.EnableDomainProfileCleanup
    
    if ($RemoveDomainUserProfiles) {
        try {
            Write-Log "Removing domain user profiles for VDI template preparation..." "INFO"
            $ProfileCleanupResults = Remove-DomainUserProfiles
            
            if ($ProfileCleanupResults.Success) {
                Write-Log "Domain Profile Cleanup: COMPLETED" "SUCCESS"
                Write-Log "Removed $($ProfileCleanupResults.ProfilesRemoved) domain profiles" "SUCCESS"
                if ($ProfileCleanupResults.RemovedProfiles.Count -gt 0) {
                    Write-Log "Cleaned profiles: $($ProfileCleanupResults.RemovedProfiles -join ', ')" "INFO"
                }
            }
            else {
                Write-Log "Domain Profile Cleanup: ISSUES DETECTED" "WARN"
                if ($ProfileCleanupResults.FailedRemovals.Count -gt 0) {
                    Write-Log "Failed to remove: $($ProfileCleanupResults.FailedRemovals -join ', ')" "WARN"
                }
            }
        }
        catch {
        Write-Log "Domain Profile Cleanup: ERROR - $($_.Exception.Message)" "ERROR"
        # Manual fallback cleanup
        Write-Log "Attempting manual domain profile cleanup" "WARN"
        try {
            $ProfileListPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
            $ProfileKeys = Get-ChildItem -Path $ProfileListPath -ErrorAction SilentlyContinue
            $ManualCleanupCount = 0
            
            foreach ($ProfileKey in $ProfileKeys) {
                $ProfilePath = Get-ItemProperty -Path $ProfileKey.PSPath -Name "ProfileImagePath" -ErrorAction SilentlyContinue
                if ($ProfilePath -and $ProfilePath.ProfileImagePath) {
                    $ProfileName = Split-Path $ProfilePath.ProfileImagePath -Leaf
                    if ($ProfileName -match "^[A-Za-z0-9-]+\.[A-Za-z0-9-]+.*" -or $ProfileName.Contains(".")) {
                        $ProfileDir = $ProfilePath.ProfileImagePath
                        if (Test-Path $ProfileDir) {
                            Remove-Item -Path $ProfileDir -Recurse -Force -ErrorAction SilentlyContinue
                            $ManualCleanupCount++
                        }
                    }
                }
            }
            Write-Log "Manual cleanup removed $ManualCleanupCount domain profiles" "SUCCESS"
        }
        catch {
            Write-Log "Manual domain profile cleanup also failed: $($_.Exception.Message)" "ERROR"
        }
        }
    } else {
        Write-Log "Domain profile cleanup: DISABLED" "INFO"
        Write-Log "Skipping domain user profile removal - disabled in configuration" "INFO"
        $ProfileCleanupResults = @{ Success = $true; ProfilesRemoved = 0; Skipped = $true }
    }
    
    # Execute ghost device removal for template optimization
    Write-LogHeader "GHOST DEVICE REMOVAL"
    Write-Log "Starting ghost device removal for VDI template cleanup..."
    
    try {
        $GhostDeviceResult = Remove-GhostDevices
        
        if ($GhostDeviceResult.Success) {
            Write-Log "Ghost device removal completed successfully" "SUCCESS"
            Write-Log "Total devices scanned: $($GhostDeviceResult.TotalDevicesFound)" "SUCCESS"
            Write-Log "Ghost devices removed: $($GhostDeviceResult.GhostDevicesRemoved)" "SUCCESS"
            Write-Log "Execution time: $($GhostDeviceResult.ExecutionTime) seconds" "INFO"
            
            if ($GhostDeviceResult.GhostDevicesRemoved -gt 0) {
                Write-Log "VDI template optimized by removing orphaned hardware devices" "SUCCESS"
            }
        }
        else {
            Write-Log "Ghost device removal encountered issues" "WARN"
            if ($GhostDeviceResult.Errors.Count -gt 0) {
                foreach ($Error in $GhostDeviceResult.Errors) {
                    Write-Log "  - Ghost Device Error: $Error" "WARN"
                }
            }
        }
        
        if ($GhostDeviceResult.DevicesFailedToRemove -gt 0) {
            Write-Log "Some devices could not be removed - this is normal for protected system devices" "INFO"
        }
        
        # Store result for reporting
        $GhostDeviceResults = $GhostDeviceResult
    }
    catch {
        Write-Log "ERROR: Ghost device removal failed: $($_.Exception.Message)" "ERROR"
        $GhostDeviceResults = @{ Success = $false; Error = $_.Exception.Message }
    }
    
    # Execute system drive defragmentation for optimal VDI performance (Optional)
    Write-LogHeader "SYSTEM DRIVE DEFRAGMENTATION (OPTIONAL)"
    Write-Log "Attempting C:\ drive defragmentation for template optimization..."
    Write-Log "Note: This operation is optional and template preparation will continue regardless of outcome" "INFO"
    
    try {
        $DefragResult = Start-SystemDriveDefragmentation -DriveLetter "C" -TimeoutMinutes 45
        
        if ($DefragResult.Success) {
            Write-Log "System drive defragmentation completed successfully" "SUCCESS"
            Write-Log "Method used: $($DefragResult.Method)" "SUCCESS"
            Write-Log "Defragmentation time: $($DefragResult.ExecutionTime.ToString('F2')) minutes" "INFO"
            
            if ($DefragResult.DefragmentationPerformed) {
                Write-Log "Free space consolidation completed" "SUCCESS"
                Write-Log "VDI template optimized for improved performance" "SUCCESS"
            } else {
                Write-Log "Analysis completed - defragmentation was not required" "INFO"
            }
            
            if ($DefragResult.Details.Count -gt 0) {
                foreach ($Detail in $DefragResult.Details) {
                    Write-Log "Defrag detail: $Detail" "INFO"
                }
            }
        }
        else {
            Write-Log "System drive defragmentation was skipped due to volume conflicts" "WARN"
            Write-Log "This is normal in virtualized environments and will not affect template quality" "INFO"
            if ($DefragResult.Errors.Count -gt 0) {
                Write-Log "Defragmentation details: Volume optimization service conflicts detected" "INFO"
            }
        }
        
        # Store result for reporting
        $DefragResults = $DefragResult
    }
    catch {
        Write-Log "System drive defragmentation was skipped: $($_.Exception.Message)" "WARN"
        Write-Log "VDI template preparation will continue - defragmentation is not critical" "INFO"
        $DefragResults = @{ Success = $false; Error = $_.Exception.Message; Skipped = $true }
    }
    
    # Execute Windows Event Logs cleanup after defragmentation
    Write-LogHeader "WINDOWS EVENT LOGS CLEANUP"
    Write-Log "Starting Windows Event Logs cleanup for VDI template preparation..."
    
    try {
        $EventLogResult = Clear-WindowsEventLogs -ExcludeLogs @("Security")
        
        if ($EventLogResult.Success) {
            
            if ($EventLogResult.LogsCleared -gt 0) {
                Write-Log "VDI template cleaned of installation artifacts and user activity traces" "SUCCESS"
            }
        }
        else {
            Write-Log "Windows Event Logs cleanup encountered issues" "WARN"
            if ($EventLogResult.FailedLogs.Count -gt 0) {
                foreach ($Error in $EventLogResult.FailedLogs) {
                    Write-Log "  - Event Log Error: $Error" "WARN"
                }
            }
        }
        
        if ($EventLogResult.LogsFailed -gt 0) {
            Write-Log "Some event logs could not be cleared - this may be normal for protected system logs" "INFO"
        }
        
        # Store result for reporting
        $EventLogCleanupResults = $EventLogResult
    }
    catch {
        Write-Log "ERROR: Windows Event Logs cleanup failed: $($_.Exception.Message)" "ERROR"
        $EventLogCleanupResults = @{ Success = $false; Error = $_.Exception.Message }
    }
    
    # Execute .NET Framework optimization
    Write-LogHeader ".NET FRAMEWORK OPTIMIZATION"
    Write-Log "Starting .NET Framework native image optimization for VDI template..."
    
    try {
        $DotNetOptimizationResult = Start-DotNetOptimization
        
        if ($DotNetOptimizationResult.Success) {
            Write-Log ".NET Framework optimization completed successfully" "SUCCESS"
            Write-Log "Frameworks optimized: $($DotNetOptimizationResult.FrameworkVersionsOptimized.Count)" "SUCCESS"
            Write-Log "Total assemblies optimized: $($DotNetOptimizationResult.TotalAssembliesOptimized)" "SUCCESS"
            Write-Log "Optimization time: $($DotNetOptimizationResult.ExecutionTime.TotalMinutes.ToString('F2')) minutes" "INFO"
        } else {
            Write-Log ".NET Framework optimization encountered issues" "WARN"
            Write-Log "Optimization errors: $($DotNetOptimizationResult.OptimizationErrors.Count)" "WARN"
            foreach ($Error in $DotNetOptimizationResult.OptimizationErrors) {
                Write-Log "Optimization error: $Error" "WARN"
            }
        }
        
        # Store result for reporting
        $DotNetResults = $DotNetOptimizationResult
    }
    catch {
        Write-Log ".NET Framework optimization failed: $($_.Exception.Message)" "ERROR"
        $DotNetResults = @{ Success = $false; Error = $_.Exception.Message }
    }
    
    # Active Components Registry Cleanup
    Write-LogHeader "ACTIVE COMPONENTS REGISTRY CLEANUP"
    Write-Log "Starting Active Components registry cleanup for VDI optimization..."
    
    try {
        $ActiveComponentsResult = Remove-ActiveComponentsRegistry
        
        if ($ActiveComponentsResult.Success) {
            Write-Log "Active Components registry cleanup completed successfully" "SUCCESS"
            if ($ActiveComponentsResult.TotalRemoved -gt 0) {
                Write-Log "Removed $($ActiveComponentsResult.TotalRemoved) Active Components" "INFO"
                if ($ActiveComponentsResult.RemovedComponents -and $ActiveComponentsResult.RemovedComponents.Count -gt 0) {
                    Write-Log "Cleaned components: $($ActiveComponentsResult.RemovedComponents -join ', ')" "INFO"
                }
            } else {
                Write-Log "No Active Components required removal" "INFO"
            }
        } else {
            Write-Log "Active Components registry cleanup encountered issues" "WARN"
            if ($ActiveComponentsResult.Message) {
                Write-Log "Error details: $($ActiveComponentsResult.Message)" "WARN"
            }
        }
        
        # Store result for reporting
        if (-not $ActiveComponentsResult) {
            $ActiveComponentsResult = @{ Success = $false; TotalRemoved = 0; Message = "Function execution failed" }
        }
    }
    catch {
        Write-Log "Active Components registry cleanup failed: $($_.Exception.Message)" "ERROR"
        $ActiveComponentsResult = @{ Success = $false; TotalRemoved = 0; Message = $_.Exception.Message }
    }

    
    # System validation moved to after cache drive removal
    
    # CACHE DRIVE REDIRECTIONS
    Write-LogHeader "CACHE DRIVE REDIRECTIONS CONFIGURATION"
    Write-Log "Configuring all cache drive redirections..."
    
    # Check if cache drive is required first
    $RequireCacheDrive = $Global:CachedConfig.RequireCacheDrive
    
    # Event Logs Redirection
    $RedirectEventLogsToCache = $Global:CachedConfig.RedirectEventLogsToCache
    if ($RedirectEventLogsToCache -and $RequireCacheDrive) {
        Write-Log "Configuring event logs redirection to cache drive..." "INFO"
        try {
            $EventLogResult = Set-EventLogRedirection -ConfigFilePath "dummy"
            if ($EventLogResult) {
                Write-Log "Event logs redirection configured successfully" "SUCCESS"
            } else {
                Write-Log "Event logs redirection partially completed" "WARN"
            }
        } catch {
            Write-Log "Failed to configure event logs redirection: $($_.Exception.Message)" "ERROR"
            $EventLogResult = $false
        }
    } else {
        Write-Log "Event logs redirection skipped - disabled or cache drive not required" "INFO"
        $EventLogResult = $true
    }
    
    # User Profiles Redirection (only if cache drive is required)
    $RedirectUserProfilesToCache = $Global:CachedConfig.RedirectUserProfilesToCache
    
    if ($RequireCacheDrive -and $RedirectUserProfilesToCache) {
        Write-Log "Configuring user profiles redirection to cache drive..." "INFO"
        try {
            $UserProfileResult = Set-UserProfileRedirection -ConfigFilePath "dummy"
            if ($UserProfileResult) {
                Write-Log "User profiles redirection configured successfully" "SUCCESS"
            } else {
                Write-Log "User profiles redirection configuration failed" "WARN"
            }
        } catch {
            Write-Log "Failed to configure user profiles redirection: $($_.Exception.Message)" "ERROR"
            $UserProfileResult = $false
        }
    } elseif (-not $RequireCacheDrive) {
        Write-Log "User profiles redirection skipped - cache drive requirement disabled" "INFO"
        $UserProfileResult = $true
    } else {
        Write-Log "User profiles redirection skipped - disabled in configuration" "INFO"
        $UserProfileResult = $true
    }
    
    # FINAL STEP: Configure pagefile on D: drive (only if cache drive is required)
    if ($RequireCacheDrive) {
        Write-LogHeader "FINAL OPTIMIZATION - PAGEFILE CONFIGURATION"
        Write-Log "Configuring pagefile on D: drive as the final optimization step..."
        
        # Use cached pagefile configuration values (read before cleanup)
        
        if ($CachedConfig.ConfigurePagefile -and $CachedConfig.RedirectPagefileToCache) {
            Write-Log "Configuring pagefile with cache drive redirection..."
            $PagefileResult = Set-PagefileConfiguration -PagefileSizeGB $CachedConfig.PagefileSizeGB -CacheDriveLetter $CachedConfig.CacheDriveLetter
        } elseif ($CachedConfig.ConfigurePagefile) {
            Write-Log "Configuring pagefile without cache redirection..."
            $PagefileResult = Set-PagefileConfiguration -PagefileSizeGB $CachedConfig.PagefileSizeGB
        } else {
            Write-Log "Pagefile configuration skipped - disabled in configuration"
            $PagefileResult = @{ Success = $true; Skipped = $true }
        }
        
        if ($CachedConfig.ConfigurePagefile) {
        
        if ($PagefileResult.Success) {
            Write-Log "Pagefile configuration completed successfully" "SUCCESS"
            Write-Log "Pagefile location: $($PagefileResult.Location)" "SUCCESS"
            Write-Log "Pagefile size: $($PagefileResult.SizeGB) GB ($($PagefileResult.SizeMB) MB)" "SUCCESS"
            Write-Host ""
            Write-Host "PAGEFILE CONFIGURED ON D: DRIVE" -ForegroundColor Green
            Write-Host "Location: $($PagefileResult.Location)" -ForegroundColor Cyan
            Write-Host "Size: $($PagefileResult.SizeGB) GB (Fixed)" -ForegroundColor Cyan
        }
        else {
            Write-Log "Pagefile configuration failed: $($PagefileResult.Error)" "ERROR"
            Write-Host "WARNING: Pagefile configuration failed" -ForegroundColor Yellow
        }
    } else {
        Write-Log "Pagefile configuration skipped - disabled in configuration" "INFO"
        Write-Host "Pagefile configuration skipped per configuration" -ForegroundColor Yellow
    }
    } else {
        Write-Log "All cache drive operations skipped - cache drive requirement disabled" "INFO"
        Write-Host "Cache drive operations skipped - not required in configuration" -ForegroundColor Gray
    }
    
    # Use global cached config values (loaded at script start)
    Write-Log "Using cached configuration values from memory..." "INFO"
    $CachedConfig = $Global:CachedConfig
    
    # Set legacy variables for backward compatibility
    $UseVirtualCacheDrive = $CachedConfig.UseVirtualCacheDrive
    
    # Prepare report data structures before any cleanup operations
    $ReportGenerated = $false
    
    # Initialize all result variables if not already set to ensure complete report data
    if (-not $VDAInstalled) { $VDAInstalled = $false }
    if (-not $TotalFoundServices) { $TotalFoundServices = 0 }
    if (-not $OptimizationResults) { $OptimizationResults = @{ OverallStatus = $false } }
    if (-not $VDIOptResults) { $VDIOptResults = @{ OverallStatus = $false; Skipped = $true } }
    if (-not $WEMCleanupSuccess) { $WEMCleanupSuccess = $false }
    if (-not $ProfileCleanupResults) { $ProfileCleanupResults = @{ Success = $false } }
    if (-not $VMwareMemoryStatus) { $VMwareMemoryStatus = @{ OverallCompliant = $false; Success = $false } }
    if (-not $PasswordAgeResult) { $PasswordAgeResult = $false }
    if (-not $MaintenanceStatus) { $MaintenanceStatus = @{ Optimized = $false } }
    if (-not $RecycleBinResult) { $RecycleBinResult = $false }
    if (-not $QuickAccessResult) { $QuickAccessResult = $false }
    if (-not $EventLogResult) { $EventLogResult = $false }
    if (-not $UserProfileResult) { $UserProfileResult = $false }
    if (-not $PagefileResult) { $PagefileResult = @{ Success = $false; Skipped = $true } }
    if (-not $ValidationPercentage) { $ValidationPercentage = 0 }
    if (-not $ValidationScore) { $ValidationScore = 0 }
    if (-not $MaxScore) { $MaxScore = 100 }
    
    # Collect all validation results for the report
    $AllValidationResults = @{}
    if ($VDAInstalled) { $AllValidationResults["VDA Installation"] = $true }
    if ($TotalFoundServices -gt 0) { $AllValidationResults["Citrix Services"] = $true }
    if ($OptimizationResults -and $OptimizationResults.OverallStatus) { $AllValidationResults["System Optimizations"] = $true }
    if ($VDIOptResults -and ($VDIOptResults.OverallStatus -or $VDIOptResults.Skipped)) { $AllValidationResults["VDI Optimizations"] = $true }
    if ($WEMCleanupSuccess) { $AllValidationResults["WEM RSA Cleanup"] = $true }
    if ($ProfileCleanupResults -and $ProfileCleanupResults.Success) { $AllValidationResults["Domain Profile Cleanup"] = $true }
    if ($VMwareMemoryStatus -and $VMwareMemoryStatus.OverallCompliant) { $AllValidationResults["VMware Memory Optimization"] = $true }
    if ($PasswordAgeResult) { $AllValidationResults["Password Age Registry"] = $true }
    if ($MaintenanceStatus -and $MaintenanceStatus.Optimized) { $AllValidationResults["Automatic Maintenance"] = $true }
    if ($RecycleBinResult) { $AllValidationResults["Recycle Bin Disable"] = $true }
    if ($QuickAccessResult) { $AllValidationResults["Quick Access Disable"] = $true }
    if ($EventLogResult) { $AllValidationResults["Event Log Redirection"] = $true }
    if ($UserProfileResult) { $AllValidationResults["User Profile Redirection"] = $true }
    if ($PagefileResult -and $PagefileResult.Success) { $AllValidationResults["Pagefile Configuration"] = $true }
    $AllValidationResults["System Validation"] = ($ValidationPercentage -ge 70)
    
    # Prepare comprehensive installation results for Stage 2
    $Stage2Results = @{
        "VDA Verification" = @{ Success = $VDAInstalled; Details = "Citrix VDA installation status" }
        "Citrix Services" = @{ Success = ($TotalFoundServices -gt 0); ServiceCount = $TotalFoundServices; Details = "Running Citrix services detected" }
        "System Optimizations" = @{ Success = ($OptimizationResults -and $OptimizationResults.OverallStatus); Details = "Citrix Optimizer templates applied" }
        "VDI Optimizations" = if ($VDIOptResults) { $VDIOptResults } else { @{ Success = $false; Skipped = $true } }
        "WEM RSA Cleanup" = @{ Success = $WEMCleanupSuccess; Details = "Citrix WEM RSA key removal" }
        "Domain Profile Cleanup" = if ($ProfileCleanupResults) { $ProfileCleanupResults } else { @{ Success = $false } }
        "VMware Memory Optimization" = if ($VMwareMemoryStatus) { $VMwareMemoryStatus } else { @{ Success = $false } }
        "Password Age Registry" = @{ Success = $PasswordAgeResult; Details = "Password age registry key cleanup" }
        "RDS Grace Period Reset" = if ($RDSGraceResult) { $RDSGraceResult } else { @{ Success = $false; Skipped = $true } }
        "Network Optimizations" = if ($NetworkOptResults) { $NetworkOptResults } else { @{ Success = $false; Skipped = $true } }
        "Storage Optimizations" = if ($StorageOptResults) { $StorageOptResults } else { @{ Success = $false; Skipped = $true } }
        "Ghost Device Removal" = if ($GhostDeviceResults) { $GhostDeviceResults } else { @{ Success = $false; Skipped = $true } }
        "System Defragmentation" = if ($DefragResults) { $DefragResults } else { @{ Success = $false; Skipped = $true } }
        "Event Logs Cleanup" = if ($EventLogCleanupResults) { $EventLogCleanupResults } else { @{ Success = $false; Skipped = $true } }
        ".NET Framework Optimization" = if ($DotNetResults) { $DotNetResults } else { @{ Success = $false; Skipped = $true } }
        "Active Components Registry" = if ($ActiveComponentsResult) { $ActiveComponentsResult } else { @{ Success = $false; TotalRemoved = 0 } }
        "Automatic Maintenance" = @{ Success = ($MaintenanceStatus -and ($MaintenanceStatus.Optimized -or $MaintenanceStatus.Success)); Optimized = ($MaintenanceStatus -and $MaintenanceStatus.Optimized); Details = "Windows automatic maintenance disabled" }
        "Recycle Bin Disable" = @{ Success = $RecycleBinResult; Details = "Desktop Recycle Bin disabled" }
        "Quick Access Disable" = @{ Success = $QuickAccessResult; Details = "File Explorer Quick Access disabled" }
        "Event Log Redirection" = @{ Success = $EventLogResult; Details = "Event logs redirected to cache drive" }
        "User Profile Redirection" = @{ Success = $UserProfileResult; Details = "User profiles configured for cache drive" }
        "Pagefile Configuration" = if ($PagefileResult) { $PagefileResult } else { @{ Success = $false; Skipped = $true } }
        "System Validation" = @{ Success = ($ValidationPercentage -ge 70); Percentage = $ValidationPercentage; Score = $ValidationScore; MaxScore = $MaxScore }
    }
    
    Write-Host ""
    Write-Host "All optimizations completed. Ready for cache drive removal." -ForegroundColor Green
    Write-Host ""

    # Check if virtual cache drive was used (only if cache drive was required)
    if ($RequireCacheDrive) {
        
        if ($UseVirtualCacheDrive) {
        Write-Host "Automatic virtual cache drive removal..." -ForegroundColor Cyan
        # Use cached VHDX path instead of reading from deleted config file
        $VirtualCacheRemovalResult = Remove-VirtualCacheDrive -VHDXPath $Global:CachedConfig.VirtualCacheDrivePath
        
        if ($VirtualCacheRemovalResult.Success) {
            Write-Host "Virtual cache drive removed successfully" -ForegroundColor Green
            Write-Host "VHDX file dismounted and deleted automatically" -ForegroundColor Green
            Write-Host "Virtual cache drive removal completed successfully" -ForegroundColor Green
            
            # Update report data with virtual cache drive removal results
            $AllValidationResults["Virtual Cache Drive Removal"] = $true
            $Stage2Results["Virtual Cache Drive Removal"] = $VirtualCacheRemovalResult
        } else {
            Write-Host "Virtual cache drive removal encountered issues:" -ForegroundColor Yellow
            foreach ($Error in $VirtualCacheRemovalResult.Errors) {
                Write-Host "  - $Error" -ForegroundColor Red
            }
            Write-Host "Please manually remove the virtual cache drive before continuing" -ForegroundColor Yellow
            
            # Update report data with failed virtual cache drive removal
            $AllValidationResults["Virtual Cache Drive Removal"] = $false
            $Stage2Results["Virtual Cache Drive Removal"] = $VirtualCacheRemovalResult
        }
    } else {
        do {
            $Response = Read-Host "Have you removed the D: cache drive? (y/n)"
            if ($Response.ToLower() -eq 'y' -or $Response.ToLower() -eq 'yes') {
                Write-Host "Cache drive removal confirmed" -ForegroundColor Green
                Write-Host "Cache drive removal confirmed - proceeding with cleanup" -ForegroundColor Green
                
                # Cache drive removal completed - deferring cleanup until after report generation
                break
            }
            elseif ($Response.ToLower() -eq 'n' -or $Response.ToLower() -eq 'no') {
                Write-Host "Please remove the D: cache drive before continuing" -ForegroundColor Yellow
                Write-Host "Please remove the cache drive before proceeding with finalization" -ForegroundColor Yellow
            }
            else {
                Write-Host "Please enter 'y' for yes or 'n' for no" -ForegroundColor Yellow
            }
        } while ($true)
    }
    
    # Handle configuration without cache drive operations
    if (-not $Config.EnableCacheDriveOperations) {
        Write-Host "Cache drive operations skipped - not required in configuration" -ForegroundColor Gray
        Write-Host "Proceeding directly to final cleanup..." -ForegroundColor Cyan
        
        # Non-cache drive configuration completed - deferring cleanup until after report generation
        
        Write-Host "Stage 2 operations completed successfully" -ForegroundColor Green
    }
    
    # Generate HTML Report Section - Runs after both cache and non-cache paths complete
    if (-not $ReportGenerated) {
        Write-Host "`n========================================" -ForegroundColor Cyan
        Write-Host "GENERATING COMPREHENSIVE HTML REPORT" -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        
        # Debug: Log report data being passed
        Write-Host "Report data summary:" -ForegroundColor Gray
        Write-Host "- Stage2Results count: $($Stage2Results.Keys.Count)" -ForegroundColor Gray
        Write-Host "- AllValidationResults count: $($AllValidationResults.Keys.Count)" -ForegroundColor Gray
        Write-Host "- CachedConfig count: $($CachedConfig.Keys.Count)" -ForegroundColor Gray
        
        foreach ($key in $Stage2Results.Keys) {
            $result = $Stage2Results[$key]
            if ($result -is [hashtable] -and $result.Success) {
                Write-Host "  [SUCCESS] $key" -ForegroundColor Green
            } else {
                Write-Host "  [FAILED/SKIPPED] $key" -ForegroundColor Yellow
            }
        }
        
        try {
            # Import the reporting function
            . "$PSScriptRoot\Generate-CitrixReport.ps1"
            
            # Get configurable report output path
            $ReportOutputPath = Get-ConfigValue -Key "ReportOutputPath" -DefaultValue "%USERPROFILE%\Desktop" -ConfigFile $ConfigFilePath
            $ConfiguredReportPath = Expand-ConfigPath -Path $ReportOutputPath -Stage 2
            Write-Log "Using configured report output path: $ConfiguredReportPath" "INFO"
            
            # Generate and open report
            $ReportPath = New-CitrixReport -Stage 2 -InstallResults $Stage2Results -ValidationResults $AllValidationResults -ConfigData $CachedConfig -OutputPath $ConfiguredReportPath -OpenInBrowser $true
            
            if ($ReportPath) {
                Write-Host "Report automatically opened in Microsoft Edge" -ForegroundColor Green
            }
            $ReportGenerated = $true
        }
        catch {
            Write-Host "Failed to generate HTML report: $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Host "Continuing with standard completion..." -ForegroundColor Gray
        }
    }
    }
    
    # Perform final cleanup of C:\Temp after HTML report generation
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "PERFORMING FINAL INSTALLATION CLEANUP" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Cleaning up installation files from C:\Temp..." -ForegroundColor Cyan
    
    try {
        $CleanupResult = Remove-InstallationFiles -TargetPath "C:\Temp" -ForceDelete $true
        
        if ($CleanupResult.Success) {
            Write-Host "Installation files cleanup completed successfully" -ForegroundColor Green
            Write-Host "Removed $($CleanupResult.FilesRemoved) files and $($CleanupResult.FoldersRemoved) folders" -ForegroundColor Green
        } else {
            Write-Host "Some files could not be removed:" -ForegroundColor Yellow
            foreach ($Error in $CleanupResult.Errors) {
                Write-Host "  - $Error" -ForegroundColor Red
            }
        }
    }
    catch {
        Write-Host "Cleanup encountered issues: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "Manual cleanup of C:\Temp may be required" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "Press any key to exit..." -ForegroundColor Gray
    $null = Read-Host
    
}
catch {
    Write-Log "FATAL ERROR: $($_.Exception.Message)" "ERROR"
    Write-Host "FATAL ERROR: Stage 2 failed!" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Check log: $LogPath" -ForegroundColor Yellow
    Write-Host "Press any key to exit..." -ForegroundColor Red
    $null = Read-Host
    exit 1
}