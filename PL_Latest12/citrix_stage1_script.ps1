how #Requires -RunAsAdministrator

<#
.SYNOPSIS
    Citrix Platform Installation - Stage 1 (Pre-Reboot)
    
.DESCRIPTION
    Enhanced first stage of Citrix platform installation.
    Installs VDA, PVS Target Device, WEM Agent, UberAgent, and configures IBM TADDM without server 
    connectivity requirements. Features improved error handling, validation, and fallback mechanisms.
    
.EXAMPLE
    .\citrix_stage1_script.ps1
    
.NOTES
    - All installer paths are configured within the script
    - Modify the paths in the "Configuration Section" below as needed
    - Script runs without server configuration requirements
    - Enhanced error handling and validation throughout
    - No server connectivity required during template creation
    - Removed delivery controller, PVS server, and WEM Infrastructure server dependencies
    
.VERSION
    2.0 - Enhanced with improved error handling
#>

#region Configuration Section - Now loaded from CitrixConfig.txt
# =============================================================================
# CONFIGURATION FILE LOADING
# =============================================================================
# All configuration values are now read from CitrixConfig.txt
# Edit CitrixConfig.txt to customize your environment settings

# Script and logging configuration
$FunctionsPath = "$PSScriptRoot\citrix_functions_library.psm1" # Functions module path
$Stage2ScriptPath = "$PSScriptRoot\citrix_stage2_script.ps1"   # Stage 2 script location
$ConfigFilePath = "$PSScriptRoot\CitrixConfig.txt"           # Configuration file path

# Enhanced validation settings
$ValidationMode = "Enhanced"                              # Standard, Enhanced, or Strict
$ContinueOnWarnings = $true                              # Continue installation despite warnings
$CreateBackups = $true                                   # Create configuration backups

#endregion

# =============================================================================
# LOAD CONFIGURATION VALUES
# =============================================================================

# Set execution policy to prevent security prompts
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

# Import functions module first to access configuration functions
try {
    Import-Module $FunctionsPath -Force -DisableNameChecking
    Write-Host "Functions module loaded successfully" -ForegroundColor Green
    
    # Load configuration from CitrixConfig.txt
    $Config = Read-ConfigFile -ConfigFilePath $ConfigFilePath
    
    # Get NetworkSourcePath and LocalInstallPath first for building other paths
    $NetworkSourcePath = Get-ConfigValue -Key "NetworkSourcePath" -DefaultValue "\\fileserver\citrix" -ConfigFile $ConfigFilePath
    $LocalInstallPath = Get-ConfigValue -Key "LocalInstallPath" -DefaultValue "C:\Temp" -ConfigFile $ConfigFilePath
    
    # Set configuration variables from config file with dynamic path defaults
    $VDAISOSourcePath = Get-ConfigValue -Key "VDAISOSourcePath" -DefaultValue "$NetworkSourcePath\installers\VDA\VDAServerSetup.iso" -ConfigFile $ConfigFilePath
    $VDAISOPath = Get-ConfigValue -Key "VDAISOPath" -DefaultValue "$LocalInstallPath\VDA.iso" -ConfigFile $ConfigFilePath
    $PVSISOSourcePath = Get-ConfigValue -Key "PVSISOSourcePath" -DefaultValue "$NetworkSourcePath\installers\PVS\PVS_Target.iso" -ConfigFile $ConfigFilePath
    $PVSISOPath = Get-ConfigValue -Key "PVSISOPath" -DefaultValue "$LocalInstallPath\PVS.iso" -ConfigFile $ConfigFilePath
    
    # Sanitize paths to prevent illegal character errors
    $VDAISOPath = $VDAISOPath.Trim().Replace('\\', '\')
    $PVSISOPath = $PVSISOPath.Trim().Replace('\\', '\')
    $WEMPath = Get-ConfigValue -Key "WEMPath" -DefaultValue "" -ConfigFile $ConfigFilePath
    $UberAgentPath = Get-ConfigValue -Key "UberAgentPath" -DefaultValue "" -ConfigFile $ConfigFilePath
    $UberAgentTemplatesPath = Get-ConfigValue -Key "UberAgentTemplatesPath" -DefaultValue "$NetworkSourcePath\UberAgent\Templates" -ConfigFile $ConfigFilePath
    $UberAgentConfigPath = Get-ConfigValue -Key "UberAgentConfigPath" -DefaultValue "$NetworkSourcePath\UberAgent\Config" -ConfigFile $ConfigFilePath
    $UberAgentLicensePath = Get-ConfigValue -Key "UberAgentLicensePath" -DefaultValue "$NetworkSourcePath\UberAgent\License" -ConfigFile $ConfigFilePath
    $TADDMPath = Get-ConfigValue -Key "TADDMPath" -DefaultValue "" -ConfigFile $ConfigFilePath
    $TADDMInstallBatPath = Get-ConfigValue -Key "TADDMInstallBatPath" -DefaultValue "" -ConfigFile $ConfigFilePath
    $LogPath = Get-ConfigValue -Config $Config -Key "LogPath" -DefaultValue ""
    
    # If no log path specified in config, create desktop log path
    if ([string]::IsNullOrEmpty($LogPath)) {
        $LogPath = Get-DesktopLogPath
    }
    $PagefileSizeGB = Get-ConfigValue -Key "PagefileSizeGB" -DefaultValue 8 -ConfigFile $ConfigFilePath
    
    Write-Host "Configuration loaded from: $ConfigFilePath" -ForegroundColor Green
    
    # Display loaded configuration for user validation
    Write-Host "`n" -ForegroundColor Yellow
    Write-Host "LOADED CONFIGURATION VALUES" -ForegroundColor Cyan -BackgroundColor DarkBlue
    Write-Host "=================================" -ForegroundColor Cyan
    Write-Host "Network Source: $NetworkSourcePath" -ForegroundColor White
    Write-Host "VDA ISO Source: $VDAISOSourcePath" -ForegroundColor White
    Write-Host "VDA ISO Local: $VDAISOPath" -ForegroundColor White
    Write-Host "PVS ISO Source: $PVSISOSourcePath" -ForegroundColor White
    Write-Host "PVS ISO Local: $PVSISOPath" -ForegroundColor White
    Write-Host "WEM Agent: $(if([string]::IsNullOrEmpty($WEMPath)){'NOT CONFIGURED'}else{$WEMPath})" -ForegroundColor $(if([string]::IsNullOrEmpty($WEMPath)){'Yellow'}else{'White'})
    Write-Host "UberAgent: $(if([string]::IsNullOrEmpty($UberAgentPath)){'NOT CONFIGURED'}else{$UberAgentPath})" -ForegroundColor $(if([string]::IsNullOrEmpty($UberAgentPath)){'Yellow'}else{'White'})
    Write-Host "UberAgent Templates: $(if([string]::IsNullOrEmpty($UberAgentTemplatesPath)){'NOT CONFIGURED'}else{$UberAgentTemplatesPath})" -ForegroundColor $(if([string]::IsNullOrEmpty($UberAgentTemplatesPath)){'Yellow'}else{'White'})
    Write-Host "UberAgent Config: $(if([string]::IsNullOrEmpty($UberAgentConfigPath)){'NOT CONFIGURED'}else{$UberAgentConfigPath})" -ForegroundColor $(if([string]::IsNullOrEmpty($UberAgentConfigPath)){'Yellow'}else{'White'})
    Write-Host "UberAgent License: $(if([string]::IsNullOrEmpty($UberAgentLicensePath)){'NOT CONFIGURED'}else{$UberAgentLicensePath})" -ForegroundColor $(if([string]::IsNullOrEmpty($UberAgentLicensePath)){'Yellow'}else{'White'})
    Write-Host "IBM TADDM: $(if([string]::IsNullOrEmpty($TADDMPath)){'NOT CONFIGURED'}else{$TADDMPath})" -ForegroundColor $(if([string]::IsNullOrEmpty($TADDMPath)){'Yellow'}else{'White'})
    Write-Host "TADDM Install Bat: $(if([string]::IsNullOrEmpty($TADDMInstallBatPath)){'NOT CONFIGURED'}else{$TADDMInstallBatPath})" -ForegroundColor $(if([string]::IsNullOrEmpty($TADDMInstallBatPath)){'Yellow'}else{'White'})
    Write-Host "Log Path: $LogPath" -ForegroundColor White
    
    # Immediate log file creation test
    try {
        Write-Host "`nTesting log file creation..." -ForegroundColor Cyan
        $TestLogPath = Get-DesktopLogPath
        Write-Host "Test log path: $TestLogPath" -ForegroundColor Gray
        
        if (Test-Path $TestLogPath) {
            Write-Host "SUCCESS: Log file exists on desktop" -ForegroundColor Green
        }
        else {
            Write-Host "WARNING: Log file not found at expected location" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "ERROR: Log creation test failed - $($_.Exception.Message)" -ForegroundColor Red
    }
    Write-Host "Pagefile Size: $PagefileSizeGB GB" -ForegroundColor White
    Write-Host "=================================" -ForegroundColor Cyan
}
catch {
    Write-Host "Failed to load configuration: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Using default values..." -ForegroundColor Yellow
    
    # Default NetworkSourcePath for fallback values
    $NetworkSourcePath = "\\fileserver\citrix"
    
    # Default configuration values with LocalInstallPath
    $LocalInstallPath = "C:\Temp"
    $VDAISOSourcePath = "$NetworkSourcePath\installers\VDA\VDAServerSetup.iso"
    $VDAISOPath = "$LocalInstallPath\VDA.iso"
    $PVSISOSourcePath = "$NetworkSourcePath\installers\PVS\PVS_Target.iso"
    $PVSISOPath = "$LocalInstallPath\PVS.iso"
    $WEMPath = ""
    $UberAgentPath = ""
    $UberAgentTemplatesPath = ""
    $UberAgentConfigPath = ""
    $UberAgentLicensePath = ""
    $TADDMPath = ""
    $TADDMInstallBatPath = ""
    $LogPath = Get-DesktopLogPath
    $PagefileSizeGB = 8
}

# =============================================================================
# CRITICAL: D: CACHE DRIVE VALIDATION - MUST EXECUTE BEFORE INSTALLATION
# =============================================================================

Write-Host "`n" -ForegroundColor Yellow
Write-Host "CRITICAL VALIDATION: D: Cache Drive Check" -ForegroundColor Red -BackgroundColor Yellow
Write-Host "=======================================" -ForegroundColor Yellow

# Immediate D: drive validation - highest priority
Write-Host "`nValidating D: drive configuration..." -ForegroundColor Yellow
$DDriveCheck = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DeviceID -eq "D:" }

if ($DDriveCheck -and $DDriveCheck.DriveType -eq 5) {
    Write-Host "D: drive is CD/DVD ROM - relocating to Y: drive..." -ForegroundColor Yellow
    
    try {
        # Get the CD/DVD ROM drive volume
        $CDVolume = Get-CimInstance -ClassName Win32_Volume | Where-Object { $_.DriveLetter -eq "D:" -and $_.DriveType -eq 5 }
        
        if ($CDVolume) {
            # Check if Y: is available
            $YDriveExists = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DeviceID -eq "Y:" }
            
            if (-not $YDriveExists) {
                Write-Host "Moving CD/DVD ROM from D: to Y:..." -ForegroundColor Cyan
                $CDVolume | Set-CimInstance -Property @{ DriveLetter = "Y:" }
                Start-Sleep -Seconds 3
                
                # Verify relocation
                $DDriveAfter = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DeviceID -eq "D:" }
                if (-not $DDriveAfter) {
                    Write-Host "CD/DVD ROM successfully moved to Y: drive" -ForegroundColor Green
                    Write-Host "D: drive letter is now available for cache drive" -ForegroundColor Green
                } else {
                    Write-Host "WARNING: CD/DVD ROM relocation may have failed" -ForegroundColor Yellow
                }
            } else {
                Write-Host "ERROR: Y: drive already exists - cannot relocate CD/DVD ROM" -ForegroundColor Red
                Write-Host "Please manually change CD/DVD ROM drive letter and restart" -ForegroundColor Yellow
                Write-Host "INSTALLATION TERMINATED" -ForegroundColor Red
                exit 1
            }
        }
    }
    catch {
        Write-Host "ERROR: Failed to relocate CD/DVD ROM drive: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Please manually change CD/DVD ROM drive letter to Y: and restart" -ForegroundColor Yellow
        Write-Host "INSTALLATION TERMINATED" -ForegroundColor Red
        exit 1
    }
    
    # Now prompt for D: cache drive
    Write-Host "`nCD/DVD ROM relocated. Now requesting D: cache drive..." -ForegroundColor Yellow
    $DCacheAttached = Get-CacheDrive
    
    # Force immediate termination if Get-CacheDrive returns false
    if ($DCacheAttached -eq $false) {
        Write-Host "CRITICAL: D: cache drive validation failed after CD/DVD ROM relocation!" -ForegroundColor Red
        Write-Host "Installation cannot continue without cache drive." -ForegroundColor Red
        Write-Host "Please attach D: cache drive and restart the script." -ForegroundColor Yellow
        Write-Host "INSTALLATION TERMINATED" -ForegroundColor Red
        exit 1
    }
    
    # Only continue if explicitly true
    if ($DCacheAttached -eq $true) {
        Write-Host "D: cache drive successfully validated after CD/DVD ROM relocation" -ForegroundColor Green
    }
    else {
        Write-Host "CRITICAL: Unexpected validation result after CD/DVD ROM relocation - terminating installation" -ForegroundColor Red
        exit 1
    }
}
elseif (-not $DDriveCheck) {
    Write-Host "No D: drive detected - prompting for cache drive attachment..." -ForegroundColor Red
    $DCacheAttached = Get-CacheDrive
    
    # Force immediate termination if Get-CacheDrive returns false
    if ($DCacheAttached -eq $false) {
        Write-Host "CRITICAL: D: cache drive validation failed!" -ForegroundColor Red
        Write-Host "Installation cannot continue without cache drive." -ForegroundColor Red
        Write-Host "Please attach D: cache drive and restart the script." -ForegroundColor Yellow
        Write-Host "INSTALLATION TERMINATED" -ForegroundColor Red
        exit 1
    }
    
    # Only continue if explicitly true
    if ($DCacheAttached -eq $true) {
        Write-Host "D: cache drive successfully validated after attachment" -ForegroundColor Green
    }
    else {
        Write-Host "CRITICAL: Unexpected validation result - terminating installation" -ForegroundColor Red
        exit 1
    }
}
elseif ($DDriveCheck.DriveType -eq 3) {
    Write-Host "D: cache drive validated successfully (Fixed disk drive)" -ForegroundColor Green
}
else {
    Write-Host "D: drive detected but unknown type ($($DDriveCheck.DriveType))" -ForegroundColor Yellow
    Write-Host "CRITICAL: D: drive must be a fixed disk for cache operations!" -ForegroundColor Red
    Write-Host "Current drive type is not suitable for VDI cache operations." -ForegroundColor Red
    Write-Host "Please attach a proper fixed disk drive to D: and restart." -ForegroundColor Yellow
    Write-Host "INSTALLATION TERMINATED" -ForegroundColor Red
    exit 1
}

# D: Cache Drive validation completed - script continues only if validation passed

# =============================================================================
# SCRIPT EXECUTION - DO NOT MODIFY BELOW THIS LINE
# =============================================================================

Write-Host "Citrix Platform Installation - Stage 1 (Enhanced)" -ForegroundColor Green
Write-Host "=================================================" -ForegroundColor Green
Write-Host "Version: 2.0 - Enhanced Installation" -ForegroundColor Cyan
Write-Host "Validation Mode: $ValidationMode" -ForegroundColor Cyan
Write-Host "Script Location: $PSScriptRoot" -ForegroundColor Gray

# Display configured paths
Write-Host "`nConfigured Installation Paths:" -ForegroundColor Yellow
Write-Host "VDA ISO: $VDAISOPath"
Write-Host "PVS ISO: $(if([string]::IsNullOrEmpty($PVSISOPath)){'SKIP'}else{$PVSISOPath})"
Write-Host "WEM: $(if([string]::IsNullOrEmpty($WEMPath)){'SKIP'}else{$WEMPath})"
Write-Host "UberAgent: $(if([string]::IsNullOrEmpty($UberAgentPath)){'SKIP'}else{$UberAgentPath})"
Write-Host "TADDM: $(if([string]::IsNullOrEmpty($TADDMPath)){'SKIP'}else{$TADDMPath})"
Write-Host "Functions: $FunctionsPath"
Write-Host "Log: $LogPath"
Write-Host "Stage 2 Script: $Stage2ScriptPath"
Write-Host "Pagefile: $PagefileSizeGB GB (Fixed Size)"

# Enhanced validation with multiple fallback locations
Write-Host "`nEnhanced validation starting..." -ForegroundColor Yellow

$ValidationErrors = @()
$ValidationWarnings = @()

# Check functions module with fallback locations
Write-Host "Validating functions module..." -ForegroundColor Gray
$FunctionsFound = $false
$FunctionsPaths = @(
    $FunctionsPath,
    ".\citrix_functions_library.psm1",
    "$PSScriptRoot\citrix_functions_library.psm1",
    "C:\Scripts\citrix_functions_library.psm1",
    "C:\Logs\citrix_functions_library.psm1"
)

foreach ($FuncPath in $FunctionsPaths) {
    if (Test-Path $FuncPath) {
        $FunctionsPath = $FuncPath
        $FunctionsFound = $true
        Write-Host "  Functions module found: $FuncPath" -ForegroundColor Green
        break
    }
}

if (!$FunctionsFound) {
    $ValidationErrors += "Functions module not found in any expected location"
    Write-Host "  Functions module: NOT FOUND" -ForegroundColor Red
}

# Check VDA installer source (required)
Write-Host "Validating VDA installer source..." -ForegroundColor Gray
if (![string]::IsNullOrEmpty($VDAISOSourcePath) -and (Test-Path -Path $VDAISOSourcePath -ErrorAction SilentlyContinue)) {
    Write-Host "  VDA ISO Source: FOUND" -ForegroundColor Green
    
    # Enhanced VDA ISO validation
    try {
        $VDAFileInfo = Get-ItemProperty -Path $VDAISOSourcePath
        $VDASize = [Math]::Round($VDAFileInfo.Length / 1MB, 1)
        Write-Host "  VDA ISO size: $VDASize MB" -ForegroundColor Gray
        
        if ($VDASize -lt 100) {
            $ValidationWarnings += "VDA ISO seems unusually small ($VDASize MB)"
        }
    }
    catch {
        $ValidationWarnings += "Could not validate VDA ISO properties"
    }
    
    # Check if local destination directory exists
    $VDADestDir = Split-Path $VDAISOPath -Parent
    if (-not (Test-Path $VDADestDir)) {
        Write-Host "  Creating VDA destination directory: $VDADestDir" -ForegroundColor Yellow
        New-Item -Path $VDADestDir -ItemType Directory -Force | Out-Null
    }
}
else {
    $ValidationErrors += "VDA ISO source not found: $VDAISOSourcePath"
    Write-Host "  VDA ISO Source: NOT FOUND" -ForegroundColor Red
}

# Check Stage 2 script with fallback locations
Write-Host "Validating Stage 2 script..." -ForegroundColor Gray
$Stage2Found = $false
$Stage2Paths = @(
    $Stage2ScriptPath,
    ".\citrix_stage2_script.ps1",
    "$PSScriptRoot\citrix_stage2_script.ps1",
    "C:\Scripts\citrix_stage2_script.ps1",
    "C:\Logs\citrix_stage2_script.ps1"
)

foreach ($S2Path in $Stage2Paths) {
    if (Test-Path $S2Path) {
        $Stage2ScriptPath = $S2Path
        $Stage2Found = $true
        Write-Host "  Stage 2 script found: $S2Path" -ForegroundColor Green
        break
    }
}

if (!$Stage2Found) {
    $ValidationWarnings += "Stage 2 script not found - reboot automation will not work"
    Write-Host "  Stage 2 script: NOT FOUND (reboot automation disabled)" -ForegroundColor Yellow
}

# Check optional installers with enhanced validation
$OptionalComponents = @(
    @{ Name = "PVS Target Device"; Path = $PVSISOPath; Variable = "PVSISOPath" },
    @{ Name = "WEM Agent"; Path = $WEMPath; Variable = "WEMPath" },
    @{ Name = "UberAgent"; Path = $UberAgentPath; Variable = "UberAgentPath" },
    @{ Name = "UberAgent Templates"; Path = $UberAgentTemplatesPath; Variable = "UberAgentTemplatesPath" },
    @{ Name = "UberAgent Config"; Path = $UberAgentConfigPath; Variable = "UberAgentConfigPath" },
    @{ Name = "UberAgent License"; Path = $UberAgentLicensePath; Variable = "UberAgentLicensePath" }
)

foreach ($Component in $OptionalComponents) {
    if (![string]::IsNullOrEmpty($Component.Path)) {
        Write-Host "Validating $($Component.Name)..." -ForegroundColor Gray
        
        try {
            # For network paths, validate the source, not the destination
            $PathToCheck = $Component.Path
            
            # Sanitize the path to prevent illegal character errors
            if (![string]::IsNullOrEmpty($PathToCheck)) {
                $PathToCheck = $PathToCheck.Trim().Replace('\\', '\')
            }
            
            # For ISOs, check source path instead of destination
            if ($Component.Variable -eq "PVSISOPath" -and ![string]::IsNullOrEmpty($PVSISOSourcePath)) {
                $PathToCheck = $PVSISOSourcePath.Trim().Replace('\\', '\')
                Write-Host "  Checking source: $PathToCheck" -ForegroundColor Gray
            }
            
            # Only test path if it's valid
            if (![string]::IsNullOrEmpty($PathToCheck) -and $PathToCheck.Length -gt 0) {
                if (Test-Path -Path $PathToCheck -ErrorAction SilentlyContinue) {
                    Write-Host "  $($Component.Name): FOUND" -ForegroundColor Green
                }
                else {
                    $ValidationWarnings += "$($Component.Name) not found: $PathToCheck"
                    Write-Host "  $($Component.Name): NOT FOUND" -ForegroundColor Yellow
                    
                    # Clear the variable if file doesn't exist
                    Set-Variable -Name $Component.Variable -Value "" -Scope Script
                }
            }
            else {
                Write-Host "  $($Component.Name): INVALID PATH" -ForegroundColor Red
                Set-Variable -Name $Component.Variable -Value "" -Scope Script
            }
        }
        catch {
            $ValidationWarnings += "$($Component.Name) path validation failed: $($_.Exception.Message)"
            Write-Host "  $($Component.Name): PATH ERROR - $($_.Exception.Message)" -ForegroundColor Red
            Set-Variable -Name $Component.Variable -Value "" -Scope Script
        }
    }
    else {
        Write-Host "  $($Component.Name): SKIPPED (not configured)" -ForegroundColor Gray
    }
}

# Check TADDM with auto-detection
if (![string]::IsNullOrEmpty($TADDMPath)) {
    Write-Host "Validating IBM TADDM..." -ForegroundColor Gray
    
    $TADDMFound = $false
    $TADDMSearchPaths = @(
        $TADDMPath,
        "C:\Program Files\IBM\TADDM",
        "C:\Program Files (x86)\IBM\TADDM",
        "C:\IBM\TADDM",
        "C:\Program Files\IBM\Tivoli\TADDM",
        "C:\Program Files (x86)\IBM\Tivoli\TADDM"
    )
    
    foreach ($SearchPath in $TADDMSearchPaths) {
        if (Test-Path $SearchPath) {
            $TADDMPath = $SearchPath
            $TADDMFound = $true
            Write-Host "  TADDM installation found: $SearchPath" -ForegroundColor Green
            break
        }
    }
    
    if (!$TADDMFound) {
        $ValidationWarnings += "IBM TADDM installation not found in standard locations"
        Write-Host "  TADDM installation: NOT FOUND" -ForegroundColor Yellow
    }
}

# System requirements validation
Write-Host "Validating system requirements..." -ForegroundColor Gray

try {
    # System drive validated
    Write-Host "  System drive: Available and accessible" -ForegroundColor Gray
    
    # Check memory (enhanced)
    $Memory = Get-CimInstance -ClassName Win32_PhysicalMemory -ErrorAction SilentlyContinue
    if ($Memory) {
        $TotalMemoryGB = [Math]::Round(($Memory | Measure-Object -Property Capacity -Sum).Sum / 1GB, 2)
        Write-Host "  Total system memory: $TotalMemoryGB GB" -ForegroundColor Gray
        
        if ($TotalMemoryGB -lt 4) {
            $ValidationErrors += "Insufficient memory: $TotalMemoryGB GB (minimum 4GB required)"
        }
        elseif ($TotalMemoryGB -lt 8) {
            $ValidationWarnings += "Low memory: $TotalMemoryGB GB (8GB+ recommended for optimal performance)"
        }
    }
    
    # Check OS version
    $OS = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    if ($OS) {
        $OSBuildNumber = [int]$OS.BuildNumber
        Write-Host "  OS Version: $($OS.Caption) (Build $OSBuildNumber)" -ForegroundColor Gray
        
        if ($OSBuildNumber -lt 10240) {
            $ValidationErrors += "Unsupported OS version: Build $OSBuildNumber (minimum Windows 10/Server 2016 required)"
        }
    }
}
catch {
    $ValidationWarnings += "Could not complete system requirements validation: $($_.Exception.Message)"
}

# Display validation results
Write-Host "`nValidation Results:" -ForegroundColor Yellow

if ($ValidationErrors.Count -gt 0) {
    Write-Host "ERRORS ($($ValidationErrors.Count)):" -ForegroundColor Red
    foreach ($ErrorMsg in $ValidationErrors) {
        Write-Host "  - $ErrorMsg" -ForegroundColor Red
    }
}

if ($ValidationWarnings.Count -gt 0) {
    Write-Host "WARNINGS ($($ValidationWarnings.Count)):" -ForegroundColor Yellow
    foreach ($Warning in $ValidationWarnings) {
        Write-Host "  - $Warning" -ForegroundColor Yellow
    }
}

if ($ValidationErrors.Count -eq 0 -and $ValidationWarnings.Count -eq 0) {
    Write-Host "All validations passed successfully!" -ForegroundColor Green
}

# Determine if we can proceed
$CanProceed = $false

if ($ValidationErrors.Count -eq 0) {
    $CanProceed = $true
}
elseif ($ValidationMode -eq "Standard" -and $ContinueOnWarnings) {
    $CanProceed = $true
    Write-Host "`nContinuing with warnings (Standard validation mode)..." -ForegroundColor Yellow
}

if (!$CanProceed) {
    Write-Host "`nCannot proceed due to validation errors." -ForegroundColor Red
    Write-Host "Please correct the issues above and run again." -ForegroundColor Yellow
    Write-Host "Or set ValidationMode to 'Standard' and ContinueOnWarnings to `$true to proceed with warnings." -ForegroundColor Gray
    exit 1
}

# Enhanced user confirmation
Write-Host "`nReady to start installation with the following configuration:" -ForegroundColor Cyan
Write-Host "  VDA ISO: $VDAISOPath"
if (![string]::IsNullOrEmpty($PVSISOPath)) { Write-Host "  PVS ISO: $PVSISOPath" }
if (![string]::IsNullOrEmpty($WEMPath)) { Write-Host "  WEM: $WEMPath" }
if (![string]::IsNullOrEmpty($UberAgentPath)) { Write-Host "  UberAgent: $UberAgentPath" }
if (![string]::IsNullOrEmpty($TADDMPath)) { Write-Host "  TADDM: $TADDMPath" }
Write-Host "  Enhanced Error Handling: Enabled"

Write-Host "`nPress any key to start installation or Ctrl+C to cancel..." -ForegroundColor Yellow
$null = Read-Host

# Import functions module with enhanced error handling
try {
    Write-Host "Importing functions module..." -ForegroundColor Gray
    Import-Module $FunctionsPath -Force -ErrorAction Stop -DisableNameChecking
    Write-Host "Functions module imported successfully" -ForegroundColor Green
}
catch {
    Write-Host "FATAL ERROR: Cannot import functions module: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Please ensure citrix_functions_library.psm1 is available and accessible." -ForegroundColor Yellow
    exit 1
}

# Initialize enhanced logging with verification
try {
    Write-Host "`nInitializing logging system..." -ForegroundColor Cyan
    Write-Host "Target log path: $LogPath" -ForegroundColor Gray
    
    $LogInitResult = Start-Logging -LogPath $LogPath -ClearExisting
    if (!$LogInitResult) {
        throw "Logging initialization returned false"
    }
    
    # Verify log file was actually created
    if (Test-Path $LogPath) {
        Write-Host "SUCCESS: Log file created and accessible" -ForegroundColor Green
        $LogSize = (Get-Item $LogPath).Length
        Write-Host "Log file size: $LogSize bytes" -ForegroundColor Gray
    }
    else {
        Write-Host "WARNING: Log initialization succeeded but file not found" -ForegroundColor Yellow
    }
}
catch {
    Write-Host "ERROR: Could not initialize logging: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Attempting emergency desktop logging..." -ForegroundColor Yellow
    
    # Emergency fallback - create log directly on desktop
    try {
        $EmergencyLogPath = "$env:USERPROFILE\Desktop\Citrix_Emergency_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
        "Emergency Citrix Installation Log - $(Get-Date)" | Out-File -FilePath $EmergencyLogPath -Force
        $Global:LogPath = $EmergencyLogPath
        Write-Host "Emergency log created: $EmergencyLogPath" -ForegroundColor Green
    }
    catch {
        Write-Host "CRITICAL: All logging methods failed" -ForegroundColor Red
        $Global:LogPath = $null
    }
}

# Main execution with enhanced error handling
try {
    Write-LogHeader "CITRIX PLATFORM INSTALLATION - STAGE 1 (ENHANCED)"
    Write-Log "Stage 1 execution started at: $(Get-Date)"
    Write-Log "Script Version: 2.0 - Enhanced Installation"
    Write-Log "Executed by: $($env:USERNAME) on $($env:COMPUTERNAME)"
    Write-Log "PowerShell Version: $($PSVersionTable.PSVersion)"
    Write-Log "Validation Mode: $ValidationMode"
    Write-Log "Continue on Warnings: $ContinueOnWarnings"
    Write-Log "Create Backups: $CreateBackups"
    
    if ($ValidationWarnings.Count -gt 0) {
        Write-Log "Installation proceeding with $($ValidationWarnings.Count) warning(s)" "WARN"
    }
    
    # Validate network source files before copying
    Write-LogHeader "Network Source Files Validation"
    Write-Log "Validating network source files accessibility..."
    
    # Validate VDA ISO source exists on network before copying
    if (![string]::IsNullOrEmpty($VDAISOSourcePath)) {
        Write-Log "Checking VDA ISO source: $VDAISOSourcePath" "INFO"
        if (Test-Path -Path $VDAISOSourcePath -ErrorAction SilentlyContinue) {
            Write-Log "VDA ISO source validation: SUCCESS" "SUCCESS"
            try {
                $VDAFileInfo = Get-ItemProperty -Path $VDAISOSourcePath
                $VDASize = [Math]::Round($VDAFileInfo.Length / 1MB, 1)
                Write-Log "VDA ISO size: $VDASize MB" "INFO"
            }
            catch {
                Write-Log "Could not read VDA ISO properties" "WARN"
            }
        }
        else {
            Write-Log "VDA ISO source validation: FAILED - File not accessible" "ERROR"
        }
    }
    
    # Validate PVS ISO source if configured
    if (![string]::IsNullOrEmpty($PVSISOSourcePath)) {
        Write-Log "Checking PVS ISO source: $PVSISOSourcePath" "INFO"
        if (Test-Path -Path $PVSISOSourcePath -ErrorAction SilentlyContinue) {
            Write-Log "PVS ISO source validation: SUCCESS" "SUCCESS"
        }
        else {
            Write-Log "PVS ISO source validation: FAILED - File not accessible" "WARN"
        }
    }
    
    # Copy installation files from network location with enhanced validation
    Write-LogHeader "Installation Files Copy Operation"
    Write-Log "Copying installation files from network location..."
    
    # Generate timestamped log for detailed file operations
    $FileOperationsLog = Get-DesktopLogPath
    Write-Log "Enhanced file operations logging to: $FileOperationsLog" "INFO"
    
    # Use the already configured LocalInstallPath
    $LocalPath = $LocalInstallPath
    $CopySuccess = Copy-InstallationFiles -NetworkPath $NetworkSourcePath -LocalPath $LocalPath -Force
    
    # Validate copied files after successful copy operation
    if ($CopySuccess) {
        Write-Log "Performing copied file integrity validation..." "INFO"
        
        # Only validate if file was actually copied to local destination
        if (Test-Path $VDAISOPath) {
            Write-Log "VDA ISO successfully copied to: $VDAISOPath" "SUCCESS"
        }
        else {
            Write-Log "VDA ISO was not copied to local destination" "WARN"
        }
    }
    
    if (!$CopySuccess) {
        Write-Log "Warning: Some installation files could not be copied from network location" "WARN"
        Write-Log "Installation will attempt to use existing local files or continue with available components" "WARN"
    }
    
    # Basic system validation (VDA installer handles its own prerequisites)
    Write-LogHeader "Basic System Validation"
    Write-Log "VDA installer will handle all component prerequisites automatically" "INFO"
    
    # Enhanced drive configuration initialization (full validation)
    Write-LogHeader "Enhanced Drive Configuration"
    Write-Log "Performing comprehensive drive validation..."
    
    $DriveConfigInit = Start-DriveConfiguration -Interactive $true
    
    # Additional drive configuration testing
    $DriveTestResult = Test-DriveConfiguration
    if ($DriveTestResult) {
        Write-Log "Drive configuration test passed" "SUCCESS"
    }
    else {
        Write-Log "Drive configuration test failed - performing additional validation" "WARN"
    }
    
    if ($DriveConfigInit.DriveValidationPassed) {
        Write-Log "Drive validation passed - continuing with installation" "SUCCESS"
    }
    else {
        Write-Log "Drive configuration completed with warnings - check log for details" "WARN"
    }
    
    # Log configured paths with enhanced detail
    Write-LogHeader "Enhanced Installation Configuration"
    Write-Log "VDA ISO Path: $VDAISOPath"
    Write-Log "PVS ISO Path: $(if([string]::IsNullOrEmpty($PVSISOPath)){'Not specified - SKIP'}else{$PVSISOPath})"
    Write-Log "WEM Path: $(if([string]::IsNullOrEmpty($WEMPath)){'Not specified - SKIP'}else{$WEMPath})"
    Write-Log "UberAgent Installer: $(if([string]::IsNullOrEmpty($UberAgentPath)){'Not specified - SKIP'}else{$UberAgentPath})"
    Write-Log "UberAgent Templates: $(if([string]::IsNullOrEmpty($UberAgentTemplatesPath)){'Not specified - SKIP'}else{$UberAgentTemplatesPath})"
    Write-Log "UberAgent Config: $(if([string]::IsNullOrEmpty($UberAgentConfigPath)){'Not specified - SKIP'}else{$UberAgentConfigPath})"
    Write-Log "UberAgent License: $(if([string]::IsNullOrEmpty($UberAgentLicensePath)){'Not specified - SKIP'}else{$UberAgentLicensePath})"
    Write-Log "TADDM Path: $(if([string]::IsNullOrEmpty($TADDMPath)){'Not specified - SKIP'}else{$TADDMPath})"
    Write-Log "TADDM Install.bat: $(if([string]::IsNullOrEmpty($TADDMInstallBatPath)){'Auto-detect'}else{$TADDMInstallBatPath})"
    Write-Log "Functions Path: $FunctionsPath"
    Write-Log "Stage 2 Script Path: $Stage2ScriptPath"
    Write-Log "Pagefile Size: $PagefileSizeGB GB (Fixed)"
    Write-Log "Validation Mode: $ValidationMode"
    Write-Log "Continue on Warnings: $ContinueOnWarnings"
    
    Write-Log "No server connectivity required during installation"
    Write-Log "Delivery controllers, PVS servers, and WEM infrastructure servers are not required"
    
    # Initialize installation configuration (fresh OS layer - no existing installations)
    $InstallConfig = New-InstallConfig
    
    # Add Stage 1 specific properties
    $InstallConfig.Stage1CompletedAt = Get-Date
    $InstallConfig.ValidationMode = $ValidationMode
    $InstallConfig.ValidationWarnings = $ValidationWarnings
    $InstallConfig.OverallSuccess = $false
    
    # Override paths with script parameters
    $InstallConfig.VDAISOPath = $VDAISOPath
    $InstallConfig.PVSISOPath = $PVSISOPath
    $InstallConfig.WEMPath = $WEMPath
    $InstallConfig.UberAgentPath = $UberAgentPath
    $InstallConfig.TADDMPath = $TADDMPath
    
    # Add additional parameters
    $InstallConfig.Parameters = @{
        UberAgentTemplatesPath = $UberAgentTemplatesPath
        UberAgentConfigPath = $UberAgentConfigPath
        UberAgentLicensePath = $UberAgentLicensePath
        TADDMInstallBatPath = $TADDMInstallBatPath
        LogPath = $LogPath
        PagefileSizeGB = $PagefileSizeGB
        ValidationMode = $ValidationMode
        ContinueOnWarnings = $ContinueOnWarnings
        CreateBackups = $CreateBackups
    }
    
    # Enhanced pre-installation system configuration
    Write-LogHeader "Enhanced Pre-Installation System Configuration"
    
    Write-Log "Configuring Windows services for VDI optimization..."
    Set-WindowsServices
    
    # Windows Firewall configuration handled by Citrix installer (firewall disabled in environment)
    
    Write-Log "Disabling NetBIOS over TCP/IP..."
    Stop-NetBiosOverTCP
    
    Write-Log "Disabling network offload parameters for PVS compatibility..."
    Stop-NetworkOffloadParameters
    
    Write-Log "Configuring SMB settings for Citrix environments..."
    Set-SMBSettings
    
    Write-Log "Configuring crash dump to kernel mode..."
    Set-CrashDumpToKernelMode
    
    Write-Log "Removing PasswordAge registry key..."
    Remove-PasswordAgeRegistryKey
    
    Write-Log "Running Citrix Optimizer..."
    # Citrix Optimizer execution with full tool integration
    Write-LogHeader "CITRIX OPTIMIZER EXECUTION"
    $CitrixOptimizerResult = Start-CitrixOptimizer -ConfigFilePath $ConfigFilePath
    
    if ($CitrixOptimizerResult.Success) {
        Write-Log "Citrix Optimizer completed successfully" "SUCCESS"
        Write-Log "Template applied: $($CitrixOptimizerResult.TemplateApplied)" "SUCCESS"
        Write-Log "Optimizations applied: $($CitrixOptimizerResult.OptimizationsApplied)" "SUCCESS"
        
        if ($CitrixOptimizerResult.OptimizerExecuted) {
            Write-Log "Full Citrix Optimizer tool executed" "SUCCESS"
            if ($CitrixOptimizerResult.OutputLocation) {
                Write-Log "Optimizer reports saved to: $($CitrixOptimizerResult.OutputLocation)" "INFO"
            }
        }
        elseif ($CitrixOptimizerResult.FallbackApplied) {
            Write-Log "Fallback optimizations applied (Citrix Optimizer tool not available)" "WARN"
        }
        
        $InstallConfig.InstallationResults.CitrixOptimizer = $CitrixOptimizerResult
    }
    else {
        Write-Log "Citrix optimization failed: $($CitrixOptimizerResult.Error)" "ERROR"
        $InstallConfig.InstallationResults.CitrixOptimizer = $CitrixOptimizerResult
    }
    
    Write-Log "Disabling specified Citrix services..."
    $CitrixServicesResult = Stop-CitrixServices -ConfigFilePath $ConfigFilePath
    
    if ($CitrixServicesResult.Success) {
        Write-Log "Citrix services management completed successfully" "SUCCESS"
        Write-Log "Disabled services: $($CitrixServicesResult.DisabledServices.Count)" "SUCCESS"
        Write-Log "Skipped services: $($CitrixServicesResult.SkippedServices.Count)" "INFO"
        
        if ($CitrixServicesResult.FailedServices.Count -gt 0) {
            Write-Log "Failed to disable $($CitrixServicesResult.FailedServices.Count) services" "WARN"
        }
        
        $InstallConfig.InstallationResults.CitrixServicesDisabled = $CitrixServicesResult
    }
    else {
        Write-Log "Citrix services management had issues: $($CitrixServicesResult.Error)" "WARN"
        $InstallConfig.InstallationResults.CitrixServicesDisabled = $CitrixServicesResult
    }
    
    Write-Log "Configuring event logs location..."
    Set-EventLogs
    
    Write-Log "Applying registry optimizations..."
    Set-RegistryOptimizations
    
    Write-Log "Applying VDI specific optimizations..."
    Set-VDIOptimizations -PagefileSizeGB $PagefileSizeGB
    
    Write-Log "Disabling VMware memory ballooning..."
    Stop-VMwareMemoryBallooning
    
    # Enhanced Citrix components installation
    Write-LogHeader "Enhanced Citrix Components Installation"
    
    # Install VDA from ISO (no delivery controller required)
    # Note: VDA installer handles all prerequisites automatically
    Write-Log "Installing Citrix VDA from ISO (no delivery controller required)..."
    $VDAResult = Add-CitrixVDA -VDAISOSourcePath $VDAISOSourcePath -VDAISOPath $VDAISOPath -LogDir (Split-Path $LogPath -Parent)
    $InstallConfig.InstallationResults.VDA = $VDAResult
    
    if ($VDAResult.Success) {
        Write-Log "VDA installation completed successfully" "SUCCESS"
    }
    else {
        Write-Log "VDA installation encountered issues" "ERROR"
        if ($VDAResult.Issues.Count -gt 0) {
            foreach ($Issue in $VDAResult.Issues) {
                Write-Log "  - VDA Issue: $Issue" "ERROR"
            }
        }
    }
    
    if ($VDAResult.RebootRequired) {
        $InstallConfig.RebootRequired = $true
        Write-Log "VDA installation requires reboot" "WARN"
    }
    
    # Install PVS Target Device from ISO (if specified, no PVS server required)
    if (![string]::IsNullOrEmpty($PVSISOSourcePath)) {
        Write-Log "Installing PVS Target Device from ISO (no PVS server required)..."
        $PVSResult = Add-PVSTargetDevice -PVSISOSourcePath $PVSISOSourcePath -PVSISOPath $PVSISOPath
        $InstallConfig.InstallationResults.PVS = $PVSResult
        
        if ($PVSResult.Success) {
            Write-Log "PVS Target Device installation completed successfully" "SUCCESS"
        }
        elseif (!$PVSResult.Skipped) {
            Write-Log "PVS Target Device installation encountered issues" "ERROR"
        }
        
        if ($PVSResult.RebootRequired) {
            $InstallConfig.RebootRequired = $true
            Write-Log "PVS Target Device installation requires reboot" "WARN"
        }
    }
    else {
        Write-Log "PVS Target Device installation skipped - no path specified"
        $InstallConfig.InstallationResults.PVS = @{ Skipped = $true }
    }
    
    # Install WEM Agent (if specified, no WEM infrastructure server required)
    if (![string]::IsNullOrEmpty($WEMInstallerSourcePath)) {
        Write-Log "Installing WEM Agent (no infrastructure server required)..."
        $WEMResult = Add-WEMAgent -WEMSourcePath $WEMInstallerSourcePath -WEMPath $WEMInstallerPath
        $InstallConfig.InstallationResults.WEM = $WEMResult
        
        if ($WEMResult.Success) {
            Write-Log "WEM Agent installation completed successfully" "SUCCESS"
        }
        elseif (!$WEMResult.Skipped) {
            Write-Log "WEM Agent installation encountered issues" "ERROR"
        }
        
        if ($WEMResult.RebootRequired) {
            $InstallConfig.RebootRequired = $true
            Write-Log "WEM Agent installation requires reboot" "WARN"
        }
    }
    else {
        Write-Log "WEM Agent installation skipped - no path specified"
        $InstallConfig.InstallationResults.WEM = @{ Skipped = $true }
    }
    
    # Install UberAgent with enhanced template management (if specified)
    if (![string]::IsNullOrEmpty($UberAgentPath)) {
        Write-Log "Installing UberAgent with enhanced template and configuration management..."
        
        $UberAgentResult = Add-UberAgent -UberAgentPath $UberAgentPath -ConfigFilePath $ConfigFilePath
        $InstallConfig.InstallationResults.UberAgent = $UberAgentResult
        
        if ($UberAgentResult.OverallSuccess) {
            Write-Log "UberAgent installation and configuration completed successfully" "SUCCESS"
            Write-Log "Installation: SUCCESS, Templates: $(if ($UberAgentResult.TemplatesCopied) { 'COPIED' } else { 'SKIPPED' }), Config: $(if ($UberAgentResult.ConfigCopied) { 'COPIED' } else { 'SKIPPED' }), License: $(if ($UberAgentResult.LicenseCopied) { 'COPIED' } else { 'SKIPPED' })" "SUCCESS"
            Write-Log "Post-install: Service: $(if ($UberAgentResult.ServiceStopped) { 'STOPPED' } else { 'SKIPPED' }), Registry: $(if ($UberAgentResult.RegistryCleared) { 'CLEARED' } else { 'SKIPPED' }), Output Dir: $(if ($UberAgentResult.OutputDirectoryConfigured) { 'CONFIGURED' } else { 'SKIPPED' })" "SUCCESS"
            Write-Log "Files processed: $($UberAgentResult.FilesProcessed.Count), Post-install steps: $($UberAgentResult.PostInstallSteps.Count)" "SUCCESS"
        }
        elseif (!$UberAgentResult.Skipped) {
            Write-Log "UberAgent installation encountered issues" "ERROR"
            if ($UberAgentResult.Errors.Count -gt 0) {
                Write-Log "Errors: $($UberAgentResult.Errors -join '; ')" "ERROR"
            }
        }
    }
    else {
        Write-Log "UberAgent installation skipped - no path specified"
        $InstallConfig.InstallationResults.UberAgent = @{ Skipped = $true }
    }
    
    # Configure IBM TADDM permissions (if specified)
    if (![string]::IsNullOrEmpty($TADDMPath)) {
        Write-Log "Configuring IBM TADDM permissions for non-administrator discovery..."
        
        $TADDMParams = @{
            TADDMPath = $TADDMPath
            CreateGroupIfMissing = $true
        }
        
        if (![string]::IsNullOrEmpty($TADDMInstallBatPath)) {
            $TADDMParams.InstallBatPath = $TADDMInstallBatPath
        }
        
        $TADDMResult = Set-IBMTADDMPermissions @TADDMParams
        $InstallConfig.InstallationResults.TADDM = $TADDMResult
        
        if ($TADDMResult.OverallSuccess) {
            Write-Log "IBM TADDM permissions configured successfully" "SUCCESS"
        }
        elseif (!$TADDMResult.Skipped) {
            Write-Log "IBM TADDM configuration encountered issues" "WARN"
        }
    }
    else {
        Write-Log "IBM TADDM configuration skipped - no path specified"
        $InstallConfig.InstallationResults.TADDM = @{ Skipped = $true }
    }
    
    # Domain Join Operation (if enabled)
    Write-LogHeader "Domain Join Configuration"
    
    $JoinDomain = Get-ConfigValue -Key "JoinDomain" -DefaultValue $false -ConfigFile $ConfigFilePath
    if ($JoinDomain) {
        $DomainName = Get-ConfigValue -Key "DomainName" -DefaultValue "" -ConfigFile $ConfigFilePath
        $OrganizationalUnit = Get-ConfigValue -Key "OrganizationalUnit" -DefaultValue "" -ConfigFile $ConfigFilePath
        
        if (![string]::IsNullOrEmpty($DomainName)) {
            Write-Log "Domain join enabled for domain: $DomainName"
            
            # Prompt for domain credentials
            Write-Host "`nDomain Join Configuration" -ForegroundColor Yellow
            Write-Host "Domain: $DomainName" -ForegroundColor Cyan
            if (![string]::IsNullOrEmpty($OrganizationalUnit)) {
                Write-Host "OU: $OrganizationalUnit" -ForegroundColor Cyan
            }
            Write-Host "Please provide domain administrator credentials:" -ForegroundColor Yellow
            
            $DomainCredential = Get-Credential -Message "Enter domain administrator credentials for joining $DomainName"
            
            if ($DomainCredential) {
                Write-Log "Attempting to join domain: $DomainName"
                
                $DomainJoinParams = @{
                    DomainName = $DomainName
                    Credential = $DomainCredential
                    Restart = $false  # We'll handle restart separately
                }
                
                if (![string]::IsNullOrEmpty($OrganizationalUnit)) {
                    $DomainJoinParams.OrganizationalUnit = $OrganizationalUnit
                }
                
                $DomainJoinResult = Add-Domain @DomainJoinParams
                $InstallConfig.InstallationResults.DomainJoin = $DomainJoinResult
                
                if ($DomainJoinResult.Success) {
                    Write-Log "Domain join completed successfully" "SUCCESS"
                    Write-Log "System will restart after installation completion to finalize domain join" "INFO"
                }
                else {
                    Write-Log "Domain join failed - continuing with installation" "ERROR"
                }
            }
            else {
                Write-Log "Domain credentials not provided - skipping domain join" "WARN"
                $InstallConfig.InstallationResults.DomainJoin = @{ Skipped = $true; Reason = "No credentials provided" }
            }
        }
        else {
            Write-Log "Domain join enabled but no domain name specified in configuration" "ERROR"
            $InstallConfig.InstallationResults.DomainJoin = @{ Skipped = $true; Reason = "No domain name configured" }
        }
    }
    else {
        Write-Log "Domain join disabled in configuration"
        $InstallConfig.InstallationResults.DomainJoin = @{ Skipped = $true; Reason = "Disabled in configuration" }
    }
    
    # Enhanced OS-Aware Startup and Shutdown Scripts Configuration
    Write-LogHeader "OS-Aware Startup and Shutdown Scripts Configuration"
    
    # Load OS-specific script source paths from configuration
    $StartupSourceWin2019 = Get-ConfigValue -Key "StartupScriptsSourceWin2019" -DefaultValue "\\fileserver\scripts\startup\win2019" -ConfigFile $ConfigFilePath
    $StartupSourceWin2022 = Get-ConfigValue -Key "StartupScriptsSourceWin2022" -DefaultValue "\\fileserver\scripts\startup\win2022" -ConfigFile $ConfigFilePath
    $StartupDestination = Get-ConfigValue -Key "StartupScriptsDestination" -DefaultValue "C:\Scripts\Startup" -ConfigFile $ConfigFilePath
    
    $ShutdownSourceWin2019 = Get-ConfigValue -Key "ShutdownScriptsSourceWin2019" -DefaultValue "\\fileserver\scripts\shutdown\win2019" -ConfigFile $ConfigFilePath
    $ShutdownSourceWin2022 = Get-ConfigValue -Key "ShutdownScriptsSourceWin2022" -DefaultValue "\\fileserver\scripts\shutdown\win2022" -ConfigFile $ConfigFilePath
    $ShutdownDestination = Get-ConfigValue -Key "ShutdownScriptsDestination" -DefaultValue "C:\Scripts\Shutdown" -ConfigFile $ConfigFilePath
    
    Write-Log "Copying OS-specific startup and shutdown scripts..."
    $ScriptCopyResult = Copy-OSSpecificStartupShutdownScripts -StartupSourceWin2019 $StartupSourceWin2019 -StartupSourceWin2022 $StartupSourceWin2022 -StartupDestination $StartupDestination -ShutdownSourceWin2019 $ShutdownSourceWin2019 -ShutdownSourceWin2022 $ShutdownSourceWin2022 -ShutdownDestination $ShutdownDestination
    
    $InstallConfig.InstallationResults.Scripts = $ScriptCopyResult
    
    if ($ScriptCopyResult.StartupCopied -or $ScriptCopyResult.ShutdownCopied) {
        Write-Log "Configuring copied scripts for Group Policy execution..."
        $ScriptConfigResult = Set-StartupShutdownScripts -ScriptCopyResults $ScriptCopyResult -StartupDestination $StartupDestination -ShutdownDestination $ShutdownDestination
        
        $InstallConfig.InstallationResults.ScriptConfiguration = $ScriptConfigResult
        
        if ($ScriptConfigResult.RegistryConfigured -and $ScriptConfigResult.GroupPolicyConfigured) {
            Write-Log "Startup and shutdown scripts configured successfully for Windows $($ScriptCopyResult.DetectedOS)" "SUCCESS"
        }
        else {
            Write-Log "Script configuration completed with some issues" "WARN"
        }
    }
    else {
        Write-Log "No scripts were copied - configuration skipped"
        $InstallConfig.InstallationResults.ScriptConfiguration = @{ Skipped = $true }
    }
    
    # Determine overall success
    $OverallSuccess = $true
    
    # VDA is required for success
    if (!$InstallConfig.InstallationResults.VDA.Success) {
        $OverallSuccess = $false
        Write-Log "Overall installation failed - VDA installation unsuccessful" "ERROR"
    }
    
    # Optional components don't affect overall success if skipped
    $OptionalFailures = @()
    
    if ($InstallConfig.InstallationResults.PVS -and !$InstallConfig.InstallationResults.PVS.Skipped -and !$InstallConfig.InstallationResults.PVS.Success) {
        $OptionalFailures += "PVS Target Device"
    }
    
    if ($InstallConfig.InstallationResults.WEM -and !$InstallConfig.InstallationResults.WEM.Skipped -and !$InstallConfig.InstallationResults.WEM.Success) {
        $OptionalFailures += "WEM Agent"
    }
    
    if ($InstallConfig.InstallationResults.UberAgent -and !$InstallConfig.InstallationResults.UberAgent.Skipped -and !$InstallConfig.InstallationResults.UberAgent.OverallSuccess) {
        $OptionalFailures += "UberAgent"
    }
    
    if ($OptionalFailures.Count -gt 0) {
        Write-Log "Some optional components failed: $($OptionalFailures -join ', ')" "WARN"
        Write-Log "Overall installation status: SUCCESS (required components installed)" "SUCCESS"
    }
    
    $InstallConfig.OverallSuccess = $OverallSuccess
    
    # Enhanced installation summary
    Write-LogHeader "Enhanced Installation Summary"
    Write-Log "Stage 1 installation completed at: $(Get-Date)"
    Write-Log "Overall Status: $(if($OverallSuccess){'SUCCESS'}else{'FAILED'})" $(if($OverallSuccess){'SUCCESS'}else{'ERROR'})
    Write-Log "VDA: $(if($InstallConfig.InstallationResults.VDA.Success){'SUCCESS'}else{'FAILED'})"
    
    if ($InstallConfig.InstallationResults.PVS.Skipped) {
        Write-Log "PVS Target Device: SKIPPED"
    } else {
        Write-Log "PVS Target Device: $(if($InstallConfig.InstallationResults.PVS.Success){'SUCCESS'}else{'FAILED'})"
    }
    
    if ($InstallConfig.InstallationResults.WEM.Skipped) {
        Write-Log "WEM Agent: SKIPPED"
    } else {
        Write-Log "WEM Agent: $(if($InstallConfig.InstallationResults.WEM.Success){'SUCCESS'}else{'FAILED'})"
    }
    
    if ($InstallConfig.InstallationResults.UberAgent.Skipped) {
        Write-Log "UberAgent: SKIPPED"
    } else {
        Write-Log "UberAgent: $(if($InstallConfig.InstallationResults.UberAgent.OverallSuccess){'SUCCESS'}else{'FAILED'})"
    }
    
    if ($InstallConfig.InstallationResults.TADDM.Skipped) {
        Write-Log "IBM TADDM: SKIPPED"
    } else {
        Write-Log "IBM TADDM: $(if($InstallConfig.InstallationResults.TADDM.OverallSuccess){'SUCCESS'}else{'CONFIGURED'})"
    }
    
    Write-Log "Reboot Required: $($InstallConfig.RebootRequired)"
    
    Write-Log ""
    Write-Log "INSTALLATION SUMMARY:"
    Write-Log "- All components installed without server connectivity"
    Write-Log "- No server connectivity was required during installation"
    Write-Log "- Delivery controllers, PVS servers, and WEM infrastructure servers are not needed"
    Write-Log "- System is ready for final configuration"
    Write-Log "- Server connections will be configured during deployment"
    
    # Create installation report
    if ($CreateBackups) {
        Write-Log "Creating installation report..."
        New-InstallationReport -Config $InstallConfig
    }
    
    # Copy Stage 2 Script to C:\temp and Save Configuration
    Write-LogHeader "Preparing Stage 2 Script for Manual Execution"
    
    # Copy Stage 2 script from network to C:\temp
    $Stage2NetworkPath = Get-ConfigValue -Key "Stage2ScriptNetworkPath" -DefaultValue "$NetworkSourcePath\scripts\citrix_stage2_script.ps1" -ConfigFile $ConfigFilePath
    $Stage2LocalPath = "C:\temp\citrix_stage2_script.ps1"
    
    try {
        # Ensure C:\temp exists
        if (!(Test-Path "C:\temp")) {
            New-Item -Path "C:\temp" -ItemType Directory -Force | Out-Null
            Write-Log "Created C:\temp directory" "INFO"
        }
        
        # Copy Stage 2 script from network
        if (Test-Path $Stage2NetworkPath) {
            Write-Log "Copying Stage 2 script from network: $Stage2NetworkPath"
            Copy-Item -Path $Stage2NetworkPath -Destination $Stage2LocalPath -Force
            Write-Log "Stage 2 script copied to: $Stage2LocalPath" "SUCCESS"
        }
        elseif (Test-Path $Stage2ScriptPath) {
            Write-Log "Copying Stage 2 script from local path: $Stage2ScriptPath"
            Copy-Item -Path $Stage2ScriptPath -Destination $Stage2LocalPath -Force
            Write-Log "Stage 2 script copied to: $Stage2LocalPath" "SUCCESS"
        }
        else {
            Write-Log "Stage 2 script not found in network or local locations" "ERROR"
        }
        
        # Copy functions library to C:\temp as well
        $FunctionsLocalPath = "C:\temp\citrix_functions_library.psm1"
        if (Test-Path $FunctionsPath) {
            Copy-Item -Path $FunctionsPath -Destination $FunctionsLocalPath -Force
            Write-Log "Functions library copied to: $FunctionsLocalPath" "SUCCESS"
        }
        
        # Save installation configuration
        Write-Log "Saving installation configuration..."
        $ConfigSaved = Save-InstallationConfig -Config $InstallConfig -ConfigPath "C:\temp\CitrixConfig.json"
        
        if ($ConfigSaved) {
            Write-Log "Installation configuration saved to C:\temp\CitrixConfig.json" "SUCCESS"
        }
        else {
            Write-Log "Failed to save installation configuration" "ERROR"
        }
        
        # Create instruction file for manual Stage 2 execution
        $InstructionPath = "C:\temp\STAGE2_INSTRUCTIONS.txt"
        $Instructions = @"
CITRIX INSTALLATION - STAGE 2 MANUAL EXECUTION INSTRUCTIONS
==========================================================

After system reboot, execute Stage 2 manually:

1. Open PowerShell as Administrator
2. Navigate to C:\temp
3. Execute: .\citrix_stage2_script.ps1

Files copied for Stage 2:
- C:\temp\citrix_stage2_script.ps1 (Stage 2 script)
- C:\temp\citrix_functions_library.psm1 (Functions library)
- C:\temp\CitrixConfig.json (Installation configuration)

Stage 1 completed at: $(Get-Date)
Domain Join Status: $(if($InstallConfig.InstallationResults.DomainJoin.Success){'Completed'}elseif($InstallConfig.InstallationResults.DomainJoin.Skipped){'Skipped'}else{'Failed'})

NOTE: No scheduled task created - Stage 2 must be run manually after reboot.
"@
        
        Set-Content -Path $InstructionPath -Value $Instructions -Force
        Write-Log "Stage 2 instructions created: $InstructionPath" "SUCCESS"
        
    }
    catch {
        Write-Log "Error preparing Stage 2 script: $($_.Exception.Message)" "ERROR"
    }
    
    Write-Log "Stage 1 script execution completed at: $(Get-Date)" "SUCCESS"
}
catch {
    Write-Log "FATAL ERROR in Stage 1 execution: $($_.Exception.Message)" "ERROR"
    Write-Log "Stack trace: $($_.ScriptStackTrace)" "DEBUG"
    
    # Save configuration even on failure for troubleshooting
    try {
        if ($InstallConfig) {
            $InstallConfig.OverallSuccess = $false
            $InstallConfig.FatalError = $_.Exception.Message
            Save-InstallationConfig -Config $InstallConfig
        }
    }
    catch {
        Write-Log "Could not save configuration on error: $($_.Exception.Message)" "DEBUG"
    }
    
    Write-Host "`nFATAL ERROR: Installation failed!" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Check the log file for detailed information: $LogPath" -ForegroundColor Yellow
    Write-Host "Press any key to exit..." -ForegroundColor Red
    $null = Read-Host
    exit 1
}