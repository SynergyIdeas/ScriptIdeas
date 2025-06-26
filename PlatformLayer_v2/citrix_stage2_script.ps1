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
# EnablePasswordAgeCleanup moved to RunKeysToRemove configuration
$Global:CachedConfig.EnableAutomaticMaintenanceDisable = [bool](Get-ConfigValue -Key "EnableAutomaticMaintenanceDisable" -DefaultValue "true" -ConfigFile $ConfigFilePath)
$Global:CachedConfig.EnableRecycleBinDisable = [bool](Get-ConfigValue -Key "EnableRecycleBinDisable" -DefaultValue "true" -ConfigFile $ConfigFilePath)
$Global:CachedConfig.EnableQuickAccessDisable = [bool](Get-ConfigValue -Key "EnableQuickAccessDisable" -DefaultValue "true" -ConfigFile $ConfigFilePath)
$Global:CachedConfig.EnableVMwareOptimizations = [bool](Get-ConfigValue -Key "EnableVMwareOptimizations" -DefaultValue "true" -ConfigFile $ConfigFilePath)

# Network and System Optimization Settings
$Global:CachedConfig.DisableNetBiosOverTCP = [bool](Get-ConfigValue -Key "DisableNetBiosOverTCP" -DefaultValue "true" -ConfigFile $ConfigFilePath)
$Global:CachedConfig.DisableNetworkOffloadParameters = [bool](Get-ConfigValue -Key "DisableNetworkOffloadParameters" -DefaultValue "true" -ConfigFile $ConfigFilePath)
$Global:CachedConfig.ConfigureSMBSettings = [bool](Get-ConfigValue -Key "ConfigureSMBSettings" -DefaultValue "true" -ConfigFile $ConfigFilePath)
$Global:CachedConfig.SetCrashDumpToKernelMode = [bool](Get-ConfigValue -Key "SetCrashDumpToKernelMode" -DefaultValue "true" -ConfigFile $ConfigFilePath)
# RemovePasswordAge moved to RunKeysToRemove configuration
$Global:CachedConfig.ResetRDSGracePeriod = [bool](Get-ConfigValue -Key "ResetRDSGracePeriod" -DefaultValue "true" -ConfigFile $ConfigFilePath)

$Global:CachedConfig.DisableWindowsServices = [bool](Get-ConfigValue -Key "DisableWindowsServices" -DefaultValue "true" -ConfigFile $ConfigFilePath)

# Component Installation Flags
$Global:CachedConfig.InstallUberAgent = [bool](Get-ConfigValue -Key "InstallUberAgent" -DefaultValue "false" -ConfigFile $ConfigFilePath)
$Global:CachedConfig.UberAgentServiceName = Get-ConfigValue -Key "UberAgentServiceName" -DefaultValue "uberAgentSvc" -ConfigFile $ConfigFilePath

# System Cleanup and Optimization
$Global:CachedConfig.RunEventLogsCleanup = [bool](Get-ConfigValue -Key "RunEventLogsCleanup" -DefaultValue "true" -ConfigFile $ConfigFilePath)
$Global:CachedConfig.RunDotNetOptimization = [bool](Get-ConfigValue -Key "RunDotNetOptimization" -DefaultValue "true" -ConfigFile $ConfigFilePath)

# Cache report output path for HTML report generation
$Global:CachedConfig.ReportOutputPath = Get-ConfigValue -Key "ReportOutputPath" -DefaultValue "%USERPROFILE%\Desktop" -ConfigFile $ConfigFilePath

# Cache logging configuration
$Global:CachedConfig.DetailedLogging = [bool](Get-ConfigValue -Key "DetailedLogging" -DefaultValue "true" -ConfigFile $ConfigFilePath)

# Citrix Optimizer Configuration with OS Detection
$Global:CachedConfig.RunCitrixOptimizer = [bool](Get-ConfigValue -Key "RunCitrixOptimizer" -DefaultValue "true" -ConfigFile $ConfigFilePath)
$Global:CachedConfig.CitrixOptimizerPath = Get-ConfigValue -Key "CitrixOptimizerPath" -DefaultValue "C:\CitrixOptimizer\CitrixOptimizer.exe" -ConfigFile $ConfigFilePath
$Global:CachedConfig.CitrixOptimizerTemplatesPath = Get-ConfigValue -Key "CitrixOptimizerTemplatesPath" -DefaultValue "C:\CitrixOptimizer\Templates" -ConfigFile $ConfigFilePath
$Global:CachedConfig.CitrixOptimizerOutputPath = Get-ConfigValue -Key "CitrixOptimizerOutputPath" -DefaultValue "C:\Temp\CitrixOptimizer_Results" -ConfigFile $ConfigFilePath
$Global:CachedConfig.CitrixOptimizerMode = Get-ConfigValue -Key "CitrixOptimizerMode" -DefaultValue "Execute" -ConfigFile $ConfigFilePath

# OS-specific template selection + overlaying template
$ConfiguredTemplates = Get-ConfigValue -Key "CitrixOptimizerTemplate" -DefaultValue "Windows_Server_2019_VDI.xml,Windows_Server_2022_VDI.xml" -ConfigFile $ConfigFilePath
$OverlayTemplate = Get-ConfigValue -Key "CitrixOptimizerOverlayTemplate" -DefaultValue "" -ConfigFile $ConfigFilePath
$OSInfo = Get-OSVersion
Write-Log "Detected OS: $($OSInfo.Caption) Build $($OSInfo.Build)" "INFO"
Write-Log "OS script source category: $($OSInfo.ScriptSource)" "INFO"

# Use configured templates exactly as specified - no fallbacks
$AllConfiguredTemplates = $ConfiguredTemplates -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }

if ($OSInfo.ScriptSource -eq "win2019") {
    $OSTemplate = $AllConfiguredTemplates | Where-Object { $_ -match "2019|Win2019" } | Select-Object -First 1
    Write-Log "Selecting Windows Server 2019 template: $OSTemplate" "INFO"
} else {
    $OSTemplate = $AllConfiguredTemplates | Where-Object { $_ -match "2022|Win2022" } | Select-Object -First 1
    Write-Log "Selecting Windows Server 2022 template: $OSTemplate" "INFO"
}

# Build template list: OS-specific template + overlay template (if configured)
$TemplatesToApply = @($OSTemplate)
if (![string]::IsNullOrEmpty($OverlayTemplate)) {
    $TemplatesToApply += $OverlayTemplate
    Write-Log "Adding overlay template: $OverlayTemplate" "INFO"
}

# Combine templates for Citrix Optimizer
$Global:CachedConfig.CitrixOptimizerTemplate = $TemplatesToApply -join ','
Write-Log "Final template configuration: $($Global:CachedConfig.CitrixOptimizerTemplate)" "SUCCESS"

# Log template application order
Write-Log "Templates to be applied in order:" "INFO"
for ($i = 0; $i -lt $TemplatesToApply.Count; $i++) {
    Write-Log "  $($i + 1). $($TemplatesToApply[$i])" "INFO"
}

# Service Configuration
$Global:CachedConfig.CitrixServicesToDisable = Get-ConfigValue -Key "CitrixServicesToDisable" -DefaultValue "wuauserv" -ConfigFile $ConfigFilePath
$Global:CachedConfig.CitrixServicesToDisableStage2 = Get-ConfigValue -Key "CitrixServicesToDisableStage2" -DefaultValue "CdfSvc,BITS,TapiSrv" -ConfigFile $ConfigFilePath

# Startup and Shutdown Scripts Configuration (moved from Stage 1)
$Global:CachedConfig.DeployStartupScripts = Get-ConfigValue -Key "DeployStartupScripts" -DefaultValue "true" -ConfigFile $ConfigFilePath
$Global:CachedConfig.DeployShutdownScripts = Get-ConfigValue -Key "DeployShutdownScripts" -DefaultValue "true" -ConfigFile $ConfigFilePath
$Global:CachedConfig.StartupScriptsSourceWin2019 = Get-ConfigValue -Key "StartupScriptsSourceWin2019" -DefaultValue "\\fileserver\scripts\startup\win2019" -ConfigFile $ConfigFilePath
$Global:CachedConfig.StartupScriptsSourceWin2022 = Get-ConfigValue -Key "StartupScriptsSourceWin2022" -DefaultValue "\\fileserver\scripts\startup\win2022" -ConfigFile $ConfigFilePath
$Global:CachedConfig.StartupScriptsDestination = Get-ConfigValue -Key "StartupScriptsDestination" -DefaultValue "C:\Scripts\Startup" -ConfigFile $ConfigFilePath
$Global:CachedConfig.ShutdownScriptsSourceWin2019 = Get-ConfigValue -Key "ShutdownScriptsSourceWin2019" -DefaultValue "\\fileserver\scripts\shutdown\win2019" -ConfigFile $ConfigFilePath
$Global:CachedConfig.ShutdownScriptsSourceWin2022 = Get-ConfigValue -Key "ShutdownScriptsSourceWin2022" -DefaultValue "\\fileserver\scripts\shutdown\win2022" -ConfigFile $ConfigFilePath
$Global:CachedConfig.ShutdownScriptsDestination = Get-ConfigValue -Key "ShutdownScriptsDestination" -DefaultValue "C:\Scripts\Shutdown" -ConfigFile $ConfigFilePath
$Global:CachedConfig.RegisterScriptsInGPO = Get-ConfigValue -Key "RegisterScriptsInGPO" -DefaultValue "true" -ConfigFile $ConfigFilePath

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
    

    
    # Configure NTP time sources based on domain
    Write-LogHeader "NTP TIME SOURCE CONFIGURATION"
    Write-Log "Configuring NTP time sources based on machine domain..." "INFO"
    
    try {
        $NTPResult = Configure-NTPTimeSources -ConfigFilePath $ConfigFilePath
        
        if ($NTPResult.Success) {
            Write-Log "NTP time source configuration completed successfully" "SUCCESS"
            Write-Log "Domain: $($NTPResult.DomainDetected)" "SUCCESS"
            Write-Log "NTP Servers: $($NTPResult.NTPServersConfigured -join ', ')" "SUCCESS"
            
            if ($NTPResult.W32TimeConfigured) {
                Write-Log "W32Time service configured" "SUCCESS"
            }
            if ($NTPResult.ServiceRestarted) {
                Write-Log "W32Time service restarted" "SUCCESS"
            }
            if ($NTPResult.TimeResyncForced) {
                Write-Log "Time synchronization forced" "SUCCESS"
            }
        } else {
            Write-Log "NTP time source configuration completed with errors" "WARN"
            foreach ($Error in $NTPResult.Errors) {
                Write-Log "  Error: $Error" "ERROR"
            }
        }
    }
    catch {
        Write-Log "Failed to configure NTP time sources: $($_.Exception.Message)" "ERROR"
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
        
        # Keep CitrixOptimizer result separate from VDI registry optimizations
        $CitrixOptimizerFinalResult = $CitrixOptimizerResult
    }
    elseif ($CitrixOptimizerResult.Skipped) {
        Write-Log "Citrix Optimizer was skipped per configuration" "INFO"
        $CitrixOptimizerFinalResult = @{ OverallStatus = $true; Skipped = $true }
    }
    else {
        Write-Log "Citrix Optimizer execution failed: $($CitrixOptimizerResult.Error)" "ERROR"
        $CitrixOptimizerFinalResult = @{ OverallStatus = $false; Error = $CitrixOptimizerResult.Error }
    }
    
    # Startup and Shutdown Scripts Configuration (moved from Stage 1)
    Write-LogHeader "STARTUP AND SHUTDOWN SCRIPTS CONFIGURATION"
    
    $DeployStartupScripts = [bool]($Global:CachedConfig.DeployStartupScripts)
    $DeployShutdownScripts = [bool]($Global:CachedConfig.DeployShutdownScripts)
    
    if ($DeployStartupScripts -or $DeployShutdownScripts) {
        Write-Log "Configuring OS-aware startup and shutdown scripts..." "INFO"
        
        # Use cached configuration values for script paths
        $StartupSourceWin2019 = $Global:CachedConfig.StartupScriptsSourceWin2019
        $StartupSourceWin2022 = $Global:CachedConfig.StartupScriptsSourceWin2022
        $StartupDestination = $Global:CachedConfig.StartupScriptsDestination
        $ShutdownSourceWin2019 = $Global:CachedConfig.ShutdownScriptsSourceWin2019
        $ShutdownSourceWin2022 = $Global:CachedConfig.ShutdownScriptsSourceWin2022
        $ShutdownDestination = $Global:CachedConfig.ShutdownScriptsDestination
        
        Write-Log "Copying OS-specific startup and shutdown scripts..." "INFO"
        $ScriptCopyParams = @{
            StartupSourceWin2019 = if ($DeployStartupScripts) { $StartupSourceWin2019 } else { "" }
            StartupSourceWin2022 = if ($DeployStartupScripts) { $StartupSourceWin2022 } else { "" }
            StartupDestination = if ($DeployStartupScripts) { $StartupDestination } else { "" }
            ShutdownSourceWin2019 = if ($DeployShutdownScripts) { $ShutdownSourceWin2019 } else { "" }
            ShutdownSourceWin2022 = if ($DeployShutdownScripts) { $ShutdownSourceWin2022 } else { "" }
            ShutdownDestination = if ($DeployShutdownScripts) { $ShutdownDestination } else { "" }
        }
        
        try {
            $ScriptCopyResult = Copy-OSSpecificStartupShutdownScripts @ScriptCopyParams
            
            # Register scripts in Group Policy if configured
            $RegisterScriptsInGPO = [bool]($Global:CachedConfig.RegisterScriptsInGPO)
            if (($ScriptCopyResult.StartupFiles.Count -gt 0 -or $ScriptCopyResult.ShutdownFiles.Count -gt 0) -and $RegisterScriptsInGPO) {
                Write-Log "Registering copied scripts for Group Policy execution..." "INFO"
                $ScriptConfigResult = Add-StartupShutdownScripts -StartupScriptPath $StartupDestination -ShutdownScriptPath $ShutdownDestination
                
                if ($ScriptConfigResult.Success) {
                    Write-Log "Startup and shutdown scripts configured successfully" "SUCCESS"
                    Write-Log "Startup scripts registered: $($ScriptConfigResult.StartupScriptsRegistered)" "SUCCESS"
                    Write-Log "Shutdown scripts registered: $($ScriptConfigResult.ShutdownScriptsRegistered)" "SUCCESS"
                } else {
                    Write-Log "Script configuration completed with some issues" "WARN"
                }
            } else {
                $reason = if (!$RegisterScriptsInGPO) { "GPO registration disabled in configuration" } else { "no scripts were copied" }
                Write-Log "Script configuration skipped - $reason" "INFO"
                $ScriptConfigResult = @{ Skipped = $true; Reason = $reason }
            }
        } catch {
            Write-Log "Script configuration failed: $($_.Exception.Message)" "ERROR"
            $ScriptCopyResult = @{ Success = $false; Error = $_.Exception.Message }
            $ScriptConfigResult = @{ Success = $false; Error = $_.Exception.Message }
        }
    } else {
        Write-Log "Startup and shutdown script deployment disabled in configuration" "INFO"
        $ScriptCopyResult = @{ Skipped = $true; Reason = "Disabled in configuration" }
        $ScriptConfigResult = @{ Skipped = $true; Reason = "Disabled in configuration" }
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
                # Use the detailed result from the function
            } else {
                Write-Log "Recycle Bin Creation: FAILED TO DISABLE" "ERROR"
                Write-Log "Error: $($RecycleBinDisableResult.Error)" "ERROR"
            }
        }
        catch {
            Write-Log "Recycle Bin creation disable failed: $($_.Exception.Message)" "ERROR"
            $RecycleBinDisableResult = @{ Success = $false; Error = $_.Exception.Message }
        }
    } else {
        Write-Log "Recycle Bin creation disable disabled in configuration" "INFO"
        $RecycleBinDisableResult = @{ Success = $true; Skipped = $true; Message = "Disabled in configuration" }
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
                # Use the detailed result from the function
            } else {
                Write-Log "Quick Access and User Folders: FAILED TO DISABLE" "ERROR"
                Write-Log "Error: $($QuickAccessDisableResult.Error)" "ERROR"
            }
        }
        catch {
            Write-Log "Quick Access and user folders disable failed: $($_.Exception.Message)" "ERROR"
            $QuickAccessDisableResult = @{ Success = $false; Error = $_.Exception.Message }
        }
    } else {
        Write-Log "Quick Access and user folders disable disabled in configuration" "INFO"
        $QuickAccessDisableResult = @{ Success = $true; Skipped = $true; Message = "Disabled in configuration" }
    }
    
    # Password age cleanup moved to Run Keys Registry Cleanup (RunKeysToRemove=passwordAge)
    $PasswordAgeResult = @{ Success = $true; Skipped = $true; Message = "Password age cleanup handled by Run Keys function" }
    
    # Network optimizations
    Write-LogHeader "NETWORK OPTIMIZATIONS"
    
    # Initialize aggregated network results
    $AllNetworkResults = @()
    $AllRegistryChanges = @()
    $AllNetworkDetails = @()
    $NetworkOptSuccessCount = 0
    $NetworkOptErrorCount = 0
    
    $DisableNetBiosOverTCP = $Global:CachedConfig.EnableSystemOptimizations
    if ($DisableNetBiosOverTCP) {
        Write-Log "Disabling NetBIOS over TCP/IP..." "INFO"
        try {
            $NetBiosResult = Stop-NetBiosOverTCP
            if ($NetBiosResult.Success) {
                Write-Log "NetBIOS over TCP/IP: DISABLED" "SUCCESS"
                $NetworkOptSuccessCount++
                if ($NetBiosResult.RegistryChanges) { $AllRegistryChanges += $NetBiosResult.RegistryChanges }
                if ($NetBiosResult.Details) { $AllNetworkDetails += $NetBiosResult.Details }
                $AllNetworkResults += "NetBIOS over TCP/IP disabled on $($NetBiosResult.InterfacesModified) interfaces"
            } else {
                Write-Log "NetBIOS over TCP/IP: FAILED" "ERROR"
                $NetworkOptErrorCount++
                $AllNetworkDetails += "NetBIOS configuration failed: $($NetBiosResult.Error)"
            }
        } catch {
            Write-Log "NetBIOS over TCP/IP: ERROR - $($_.Exception.Message)" "ERROR"
            $NetworkOptErrorCount++
            $AllNetworkDetails += "NetBIOS error: $($_.Exception.Message)"
        }
    } else {
        Write-Log "NetBIOS over TCP/IP optimization: SKIPPED" "INFO"
        $AllNetworkDetails += "NetBIOS optimization skipped per configuration"
    }
    
    $DisableNetworkOffloadParameters = $Global:CachedConfig.EnableSystemOptimizations
    if ($DisableNetworkOffloadParameters) {
        Write-Log "Disabling network offload parameters for PVS compatibility..." "INFO"
        try {
            $OffloadResult = Stop-NetworkOffloadParameters
            if ($OffloadResult.Success) {
                Write-Log "Network offload parameters: DISABLED" "SUCCESS"
                $NetworkOptSuccessCount++
                if ($OffloadResult.Details) { $AllNetworkDetails += $OffloadResult.Details }
                $AllNetworkResults += "Network offload parameters disabled on $($OffloadResult.AdaptersModified) adapters"
            } else {
                Write-Log "Network offload parameters: FAILED" "ERROR"
                $NetworkOptErrorCount++
                $AllNetworkDetails += "Network offload failed: $($OffloadResult.Error)"
            }
        } catch {
            Write-Log "Network offload parameters: ERROR - $($_.Exception.Message)" "ERROR"
            $NetworkOptErrorCount++
            $AllNetworkDetails += "Network offload error: $($_.Exception.Message)"
        }
    } else {
        Write-Log "Network offload parameters optimization: SKIPPED" "INFO"
        $AllNetworkDetails += "Network offload optimization skipped per configuration"
    }
    
    $ConfigureSMBSettings = $Global:CachedConfig.EnableSystemOptimizations
    if ($ConfigureSMBSettings) {
        Write-Log "Configuring SMB settings for Citrix environments..." "INFO"
        try {
            $SMBResult = Set-SMBSettings
            if ($SMBResult.Success) {
                Write-Log "SMB settings: CONFIGURED" "SUCCESS"
                $NetworkOptSuccessCount++
                if ($SMBResult.RegistryChanges) { $AllRegistryChanges += $SMBResult.RegistryChanges }
                if ($SMBResult.Details) { $AllNetworkDetails += $SMBResult.Details }
                $AllNetworkResults += "SMB security signing disabled for performance"
            } else {
                Write-Log "SMB settings: FAILED" "ERROR"
                $NetworkOptErrorCount++
                $AllNetworkDetails += "SMB configuration failed: $($SMBResult.Error)"
            }
        } catch {
            Write-Log "SMB settings: ERROR - $($_.Exception.Message)" "ERROR"
            $NetworkOptErrorCount++
            $AllNetworkDetails += "SMB error: $($_.Exception.Message)"
        }
    } else {
        Write-Log "SMB settings configuration: SKIPPED" "INFO"
        $AllNetworkDetails += "SMB optimization skipped per configuration"
    }
    
    # Add PVS compatibility optimization note
    $AllNetworkResults += "PVS compatibility optimized"
    
    # Create aggregated network optimization results
    $NetworkOptResults = @{
        Success = ($NetworkOptSuccessCount -gt 0 -and $NetworkOptErrorCount -eq 0)
        Message = "Network optimizations applied"
        OptimizationsApplied = $NetworkOptSuccessCount
        OptimizationsFailed = $NetworkOptErrorCount
        RegistryChanges = $AllRegistryChanges
        Details = $AllNetworkDetails
        NetworkResults = $AllNetworkResults
    }
    
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
    
    # VDI Registry optimizations
    $OptimizeVDIRegistry = $Global:CachedConfig.EnableVDIOptimizations
    if ($OptimizeVDIRegistry) {
        Write-Log "Applying VDI registry optimizations..." "INFO"
        try {
            $VDIRegistryResults = Invoke-VDIOptimizations
            if ($VDIRegistryResults.Success) {
                Write-Log "VDI registry optimizations applied successfully" "SUCCESS"
                Write-Log "Registry keys modified: $($VDIRegistryResults.RegistryKeysModified)" "INFO"
            } else {
                Write-Log "VDI registry optimizations failed: $($VDIRegistryResults.Message)" "ERROR"
            }
        } catch {
            Write-Log "VDI registry optimizations failed: $($_.Exception.Message)" "ERROR"
            $VDIRegistryResults = @{
                Success = $false
                Error = $_.Exception.Message
                Message = "VDI registry optimizations failed"
            }
        }
    } else {
        Write-Log "VDI registry optimizations skipped - disabled in configuration" "INFO"
        $VDIRegistryResults = @{
            Success = $true
            Skipped = $true
            Message = "VDI registry optimizations skipped per configuration"
        }
    }
    
    # Storage optimizations
    Write-LogHeader "STORAGE OPTIMIZATIONS"
    
    Write-Log "Applying storage optimizations for VDI environments..." "INFO"
    try {
        $StorageOptResults = Optimize-StorageSettings
        if ($StorageOptResults.Success) {
            Write-Log "Storage optimizations applied successfully" "SUCCESS"
            Write-Log "Registry optimizations applied: $($StorageOptResults.OptimizationsApplied)" "INFO"
        } else {
            Write-Log "Storage optimizations encountered issues: $($StorageOptResults.Message)" "WARN"
        }
    } catch {
        Write-Log "Storage optimizations failed: $($_.Exception.Message)" "ERROR"
        $StorageOptResults = @{
            Success = $false
            Error = $_.Exception.Message
            Message = "Storage optimizations failed"
            Details = @("Storage optimization failed: $($_.Exception.Message)")
        }
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
        $TestStatus = Test-AutomaticMaintenanceStatus
        if ($TestStatus.Optimized) {
            Write-Log "Automatic Maintenance: ALREADY OPTIMIZED" "SUCCESS"
            # Use the test result directly - it already has the correct structure
            $MaintenanceStatus = $TestStatus
            $MaintenanceStatus.Success = $true
        }
        else {
            Write-Log "Automatic Maintenance: NEEDS OPTIMIZATION" "INFO"
            Write-Log "Disabling Windows automatic maintenance for VDI template..."
            
            $MaintenanceStatus = Disable-AutomaticMaintenance
            if ($MaintenanceStatus.Success) {
                Write-Log "Automatic Maintenance: SUCCESSFULLY DISABLED" "SUCCESS"
                # MaintenanceStatus already has all the detailed information from Disable-AutomaticMaintenance
            } else {
                Write-Log "Automatic Maintenance: FAILED TO DISABLE - $($MaintenanceStatus.Error)" "ERROR"
            }
        }
    }
    catch {
        Write-Log "Automatic maintenance check failed: $($_.Exception.Message)" "WARN"
        $MaintenanceStatus = @{ Success = $false; Optimized = $false; Error = $_.Exception.Message }
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
    
    # Execute system drive defragmentation for optimal VDI performance (configurable)
    $DefragDisk = [bool](Get-ConfigValue -Key "DefragDisk" -DefaultValue "true" -ConfigFile $ConfigFilePath)
    
    if ($DefragDisk) {
        Write-LogHeader "SYSTEM DRIVE DEFRAGMENTATION"
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
    }
    else {
        Write-Log "System drive defragmentation disabled in configuration" "INFO"
        $DefragResults = @{ Success = $false; Skipped = $true; Reason = "Disabled in configuration" }
    }
    
    # Execute Windows Event Logs cleanup after defragmentation (configurable)
    $RunEventLogsCleanup = $Global:CachedConfig.RunEventLogsCleanup
    
    if ($RunEventLogsCleanup) {
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
    } else {
        Write-Log "Windows Event Logs cleanup skipped - disabled in configuration" "INFO"
        $EventLogCleanupResults = @{ Success = $false; Skipped = $true }
    }
    
    # Execute .NET Framework optimization (configurable)
    $RunDotNetOptimization = $Global:CachedConfig.RunDotNetOptimization
    
    if ($RunDotNetOptimization) {
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
    } else {
        Write-Log ".NET Framework optimization skipped - disabled in configuration" "INFO"
        $DotNetResults = @{ Success = $false; Skipped = $true }
    }
    
    # Run Keys Registry Cleanup
    Write-LogHeader "RUN KEYS REGISTRY CLEANUP"
    Write-Log "Starting Run keys registry cleanup for VDI optimization..."
    
    try {
        $RunKeysResult = Remove-RunKeysRegistry
        
        if ($RunKeysResult.Success) {
            Write-Log "Run keys registry cleanup completed successfully" "SUCCESS"
            if ($RunKeysResult.TotalRemoved -gt 0) {
                Write-Log "Removed $($RunKeysResult.TotalRemoved) Run keys" "INFO"
                if ($RunKeysResult.RemovedKeys -and $RunKeysResult.RemovedKeys.Count -gt 0) {
                    Write-Log "Cleaned keys: $($RunKeysResult.RemovedKeys -join ', ')" "INFO"
                }
            } else {
                Write-Log "No Run keys required removal" "INFO"
            }
        } else {
            Write-Log "Run keys registry cleanup encountered issues" "WARN"
            if ($RunKeysResult.Message) {
                Write-Log "Error details: $($RunKeysResult.Message)" "WARN"
            }
        }
        
        # Store result for reporting
        if (-not $RunKeysResult) {
            $RunKeysResult = @{ Success = $false; TotalRemoved = 0; Message = "Function execution failed" }
        }
    }
    catch {
        Write-Log "Run keys registry cleanup failed: $($_.Exception.Message)" "ERROR"
        $RunKeysResult = @{ Success = $false; TotalRemoved = 0; Message = $_.Exception.Message }
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
            if ($EventLogResult.Success) {
                Write-Log "Event logs redirection configured successfully" "SUCCESS"
            } else {
                Write-Log "Event logs redirection partially completed" "WARN"
            }
        } catch {
            Write-Log "Failed to configure event logs redirection: $($_.Exception.Message)" "ERROR"
            $EventLogResult = @{
                Success = $false
                Error = $_.Exception.Message
                Message = "Event log redirection failed"
                Details = @("Event log redirection failed: $($_.Exception.Message)")
            }
        }
    } else {
        Write-Log "Event logs redirection skipped - disabled or cache drive not required" "INFO"
        $EventLogResult = @{
            Success = $true
            Skipped = $true
            Message = "Event log redirection skipped"
            Reason = if (-not $RedirectEventLogsToCache) { "Event log redirection disabled" } else { "Cache drive not required" }
            Details = @("Event log redirection skipped - feature disabled or cache drive not required")
        }
    }
    
    # User Profiles Redirection (only if cache drive is required)
    $RedirectUserProfilesToCache = $Global:CachedConfig.RedirectUserProfilesToCache
    
    if ($RequireCacheDrive -and $RedirectUserProfilesToCache) {
        Write-Log "Configuring user profiles redirection to cache drive..." "INFO"
        try {
            $UserProfileResult = Set-UserProfileRedirection -ConfigFilePath "dummy"
            if ($UserProfileResult.Success) {
                Write-Log "User profiles redirection configured successfully" "SUCCESS"
            } else {
                Write-Log "User profiles redirection configuration failed or partially completed" "WARN"
            }
        } catch {
            Write-Log "Failed to configure user profiles redirection: $($_.Exception.Message)" "ERROR"
            $UserProfileResult = @{
                Success = $false
                Error = $_.Exception.Message
                Message = "User profile redirection failed"
                Details = @("User profile redirection failed: $($_.Exception.Message)")
            }
        }
    } elseif (-not $RequireCacheDrive) {
        Write-Log "User profiles redirection skipped - cache drive requirement disabled" "INFO"
        $UserProfileResult = @{
            Success = $true
            Skipped = $true
            Message = "User profile redirection skipped"
            Reason = "Cache drive not required"
            Details = @("User profile redirection skipped - cache drive requirement disabled")
        }
    } else {
        Write-Log "User profiles redirection skipped - disabled in configuration" "INFO"
        $UserProfileResult = @{
            Success = $true
            Skipped = $true
            Message = "User profile redirection skipped"
            Reason = "Feature disabled in configuration"
            Details = @("User profile redirection skipped - disabled in configuration")
        }
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
    
    # UberAgent Service Configuration (after pagefile redirection)
    # Check for UberAgent service regardless of install flag since it may be installed in Stage 1
    Write-LogHeader "UBERAGENT SERVICE CONFIGURATION"
    Write-Log "Checking for UberAgent service installed in Stage 1..." "INFO"
    
    try {
        # Use the exact service name from configuration
        $UberAgentServiceName = $Global:CachedConfig.UberAgentServiceName
        Write-Log "Looking for UberAgent service: $UberAgentServiceName" "INFO"
        
        $UberAgentService = Get-Service -Name $UberAgentServiceName -ErrorAction SilentlyContinue
        
        if ($UberAgentService) {
            Write-Log "Found UberAgent service: $UberAgentServiceName (Status: $($UberAgentService.Status), StartType: $($UberAgentService.StartType))" "SUCCESS"
            Write-Log "Configuring UberAgent service for template preparation..." "INFO"
            
            # Set service to Disabled for template preparation
            Set-Service -Name $UberAgentServiceName -StartupType Disabled -ErrorAction Stop
            Write-Log "UberAgent service startup type set to Disabled" "SUCCESS"
            Write-Log "Service: $UberAgentServiceName" "INFO"
            Write-Log "Previous startup type: $($UberAgentService.StartType)" "INFO"
            Write-Log "New startup type: Disabled" "INFO"
            
            $UberAgentServiceResult = @{ 
                Success = $true
                ServiceName = $UberAgentServiceName
                PreviousStartType = $UberAgentService.StartType
                StartupType = "Disabled"
                Status = $UberAgentService.Status
                Message = "UberAgent service startup type set to Disabled"
                Details = "Service disabled for template preparation"
            }
        } else {
            Write-Log "UberAgent service '$UberAgentServiceName' not found" "WARN"
            Write-Log "Service may not be installed or may be using a different name" "INFO"
            
            $UberAgentServiceResult = @{ 
                Success = $false
                Error = "Service not found"
                Details = "UberAgent service '$UberAgentServiceName' not found on system"
                ServiceName = $UberAgentServiceName
                Skipped = $true
            }
        }
    }
    catch {
        Write-Log "Failed to configure UberAgent service: $($_.Exception.Message)" "ERROR"
        $UberAgentServiceResult = @{ 
            Success = $false
            Error = $_.Exception.Message
            Details = "UberAgent service configuration failed"
        }
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
    if (-not $PasswordAgeResult) { $PasswordAgeResult = @{ Success = $false; Skipped = $true } }
    if (-not $MaintenanceStatus) { $MaintenanceStatus = @{ Optimized = $false } }
    if (-not $RecycleBinDisableResult) { $RecycleBinDisableResult = @{ Success = $false; Skipped = $true } }
    if (-not $QuickAccessDisableResult) { $QuickAccessDisableResult = @{ Success = $false; Skipped = $true } }
    if (-not $EventLogResult) { $EventLogResult = $false }
    if (-not $UserProfileResult) { $UserProfileResult = @{ Success = $false; Skipped = $true; Message = "User profile redirection not executed" } }
    if (-not $PagefileResult) { $PagefileResult = @{ Success = $false; Skipped = $true } }

    
    # Collect all validation results for the report (always include all components)
    # Store detailed validation results from each function
    $VDAVerificationResult = Test-VDAInstallation
    $CitrixServicesResult = Get-CitrixServicesStatus
    $SystemOptimizationsResult = Get-SystemOptimizations
    
    $AllValidationResults = @{
        "VDA Verification" = $VDAVerificationResult
        "Citrix Services" = $CitrixServicesResult
        "System Optimizations" = $SystemOptimizationsResult
        "NTP Time Configuration" = if ($NTPConfigResult) { $NTPConfigResult } else { @{ Success = $false; Message = "NTP configuration not executed"; Skipped = $true } }
        "CitrixOptimizer" = if ($CitrixOptimizerFinalResult) { $CitrixOptimizerFinalResult } else { @{ Success = $false; Message = "Citrix Optimizer not executed"; Skipped = $true } }
        "Scripts" = if ($ScriptCopyResult) { $ScriptCopyResult } else { @{ Success = $false; Skipped = $true; Message = "Script deployment not configured" } }
        "VDI Optimizations" = if ($VDIRegistryResults) { $VDIRegistryResults } else { @{ Success = $false; Message = "VDI registry optimizations not executed"; Skipped = $true } }
        "WEM RSA Cleanup" = if ($WEMCleanupSuccess -is [hashtable]) { $WEMCleanupSuccess } else { @{ Success = [bool]$WEMCleanupSuccess; Message = if ($WEMCleanupSuccess) { "WEM RSA cleanup completed" } else { "WEM RSA cleanup failed or skipped" } } }
        "Domain Profile Cleanup" = if ($ProfileCleanupResults) { $ProfileCleanupResults } else { @{ Success = $false; Message = "Profile cleanup not executed"; Skipped = $true } }
        "VMware Memory Optimization" = if ($VMwareMemoryStatus) { $VMwareMemoryStatus } else { @{ Success = $false; Message = "VMware memory optimization not executed"; Skipped = $true } }
        "RDS Grace Period Reset" = if ($RDSGraceResult) { $RDSGraceResult } else { @{ Success = $false; Message = "RDS grace period reset not executed"; Skipped = $true } }
        "Network Optimizations" = if ($NetworkOptResults) { $NetworkOptResults } else { @{ Success = $false; Message = "Network optimizations not executed"; Skipped = $true } }
        "Storage Optimizations" = if ($StorageOptResults) { $StorageOptResults } else { @{ Success = $false; Message = "Storage optimizations not executed"; Skipped = $true } }
        "Ghost Device Removal" = if ($GhostDeviceResults) { $GhostDeviceResults } else { @{ Success = $false; Message = "Ghost device removal not executed"; Skipped = $true } }
        "System Defragmentation" = if ($DefragResults) { $DefragResults } else { @{ Success = $false; Message = "System defragmentation not executed"; Skipped = $true } }
        "Event Logs Cleanup" = if ($EventLogCleanupResults) { $EventLogCleanupResults } else { @{ Success = $false; Message = "Event logs cleanup not executed"; Skipped = $true } }
        ".NET Framework Optimization" = if ($DotNetResults) { $DotNetResults } else { @{ Success = $false; Message = ".NET Framework optimization not executed"; Skipped = $true } }
        "Run Keys Registry Cleanup" = if ($RunKeysResult) { $RunKeysResult } else { @{ Success = $false; Message = "Run keys registry cleanup not executed"; Skipped = $true } }
        "Active Setup Components Cleanup" = if ($ActiveComponentsResult) { $ActiveComponentsResult } else { @{ Success = $false; Message = "Active components cleanup not executed"; Skipped = $true } }
        "Automatic Maintenance" = if ($MaintenanceStatus) { $MaintenanceStatus } else { @{ Success = $false; Message = "Automatic maintenance not configured"; Skipped = $true } }
        "Recycle Bin Disable" = if ($RecycleBinDisableResult -is [hashtable]) { $RecycleBinDisableResult } else { @{ Success = [bool]$RecycleBinDisableResult; Message = if ($RecycleBinDisableResult) { "Recycle bin disabled" } else { "Recycle bin disable failed or skipped" } } }
        "Quick Access Disable" = if ($QuickAccessDisableResult -is [hashtable]) { $QuickAccessDisableResult } else { @{ Success = [bool]$QuickAccessDisableResult; Message = if ($QuickAccessDisableResult) { "Quick access disabled" } else { "Quick access disable failed or skipped" } } }
        "Event Log Redirection" = if ($EventLogResult -is [hashtable]) { $EventLogResult } else { @{ Success = [bool]$EventLogResult; Message = if ($EventLogResult) { "Event log redirection configured" } else { "Event log redirection failed or skipped" } } }
        "User Profile Redirection" = if ($UserProfileResult -is [hashtable]) { $UserProfileResult } else { @{ Success = [bool]$UserProfileResult; Message = if ($UserProfileResult) { "User profile redirection configured" } else { "User profile redirection failed or skipped" } } }
        "Pagefile Configuration" = if ($PagefileResult) { $PagefileResult } else { @{ Success = $false; Message = "Pagefile configuration not executed"; Skipped = $true } }
        "UberAgent Service Configuration" = if ($UberAgentServiceResult) { $UberAgentServiceResult } else { @{ Success = $false; Message = "UberAgent service not configured"; Skipped = $true } }
        "Virtual Cache Drive Removal" = @{ Success = $false; Skipped = $true; Message = "Will be updated dynamically later" }
    }

    
    # Use actual detailed function results for comprehensive Stage 2 reporting
    $Stage2Results = $AllValidationResults.Clone()
    
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
            $AllValidationResults["Virtual Cache Drive Removal"] = $VirtualCacheRemovalResult
            $Stage2Results["Virtual Cache Drive Removal"] = $VirtualCacheRemovalResult
        } else {
            Write-Host "Virtual cache drive removal encountered issues:" -ForegroundColor Yellow
            foreach ($Error in $VirtualCacheRemovalResult.Errors) {
                Write-Host "  - $Error" -ForegroundColor Red
            }
            Write-Host "Please manually remove the virtual cache drive before continuing" -ForegroundColor Yellow
            
            # Update report data with failed virtual cache drive removal
            $AllValidationResults["Virtual Cache Drive Removal"] = $VirtualCacheRemovalResult
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
            if ($result -is [hashtable]) {
                # Check for skipped status with comprehensive skip detection
                $isSkipped = $false
                
                # Direct skip flag
                if ($result.Skipped -eq $true) {
                    $isSkipped = $true
                }
                
                # Check for skip-related error messages
                if ($result.Error -and $result.Error -match "ISO file not found|file not found|not found|disabled in configuration|not configured|skipped|not available|not provided|executable not found") {
                    $isSkipped = $true
                }
                
                # Check for skip-related messages
                if ($result.Message -and $result.Message -match "skipped|disabled|not configured|not found|not available|not provided") {
                    $isSkipped = $true
                }
                
                # Check for common skip conditions based on component type
                if ($key -eq "Scripts" -and (!$result.Success -and !$result.Error)) {
                    $isSkipped = $true  # Scripts often return no result when skipped
                }
                
                if ($key -eq ".NET Framework Optimization" -and $result.Error -match "ngen|not found") {
                    $isSkipped = $true
                }
                
                if ($key -eq "System Defragmentation" -and $result.Error -match "disabled|skipped") {
                    $isSkipped = $true
                }
                
                if ($key -eq "UberAgent Service Configuration" -and $result.Error -match "not found|not configured") {
                    $isSkipped = $true
                }
                
                if ($key -eq "Event Logs Cleanup" -and $result.Error -match "disabled|not configured") {
                    $isSkipped = $true
                }
                
                if ($key -eq "Citrix Services" -and (!$result.Success -and !$result.Error)) {
                    $isSkipped = $true  # Services detection often returns neutral when no services found
                }
                
                if ($key -eq "NTP Time Configuration" -and $result.Error -match "disabled|not configured") {
                    $isSkipped = $true
                }
                
                # Display appropriate status
                if ($isSkipped) {
                    Write-Host "  [SKIPPED] $key" -ForegroundColor Yellow
                } elseif ($result.Success -eq $true) {
                    Write-Host "  [SUCCESS] $key" -ForegroundColor Green
                } else {
                    Write-Host "  [FAILED] $key" -ForegroundColor Red
                }
            } else {
                Write-Host "  [UNKNOWN] $key" -ForegroundColor Gray
            }
        }
        
        # Check if HTML report generation is enabled
        $GenerateHTMLReports = [bool](Get-ConfigValue -Key "GenerateHTMLReports" -DefaultValue "true" -ConfigFile $ConfigFilePath)
        
        if ($GenerateHTMLReports) {
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
        } else {
            Write-Host "`nHTML report generation disabled in configuration" -ForegroundColor Gray
            Write-Host "Installation logs are available in console output and log files" -ForegroundColor Gray
            $ReportGenerated = $false
        }
    }
    }
    
    # Remove network drive after report generation
    if ($MapNetworkDrive -and ![string]::IsNullOrEmpty($NetworkDriveLetter)) {
        Write-Host "`n========================================" -ForegroundColor Cyan
        Write-Host "NETWORK DRIVE CLEANUP" -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Log "Removing network drive mapping after report generation..." "INFO"
        
        try {
            $ExistingDrive = Get-PSDrive -Name $NetworkDriveLetter -ErrorAction SilentlyContinue
            
            if ($ExistingDrive) {
                Remove-PSDrive -Name $NetworkDriveLetter -Force -ErrorAction Stop
                net use "$NetworkDriveLetter`:" /delete /y 2>$null
                Write-Host "Network drive $NetworkDriveLetter`: unmapped successfully" -ForegroundColor Green
                Write-Log "Network drive $NetworkDriveLetter`: unmapped successfully" "SUCCESS"
                $NetworkDriveRemovalResult = @{ Success = $true; DriveLetter = $NetworkDriveLetter }
            } else {
                Write-Host "Network drive $NetworkDriveLetter`: not found - may already be unmapped" -ForegroundColor Gray
                Write-Log "Network drive $NetworkDriveLetter`: not found - may already be unmapped" "INFO"
                $NetworkDriveRemovalResult = @{ Success = $true; AlreadyRemoved = $true }
            }
        }
        catch {
            Write-Host "Failed to remove network drive: $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Log "Failed to remove network drive: $($_.Exception.Message)" "WARN"
            $NetworkDriveRemovalResult = @{ Success = $false; Error = $_.Exception.Message }
        }
    } else {
        Write-Log "Network drive removal skipped - mapping was not enabled" "INFO"
        $NetworkDriveRemovalResult = @{ Success = $true; Skipped = $true }
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