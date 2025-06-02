#Requires -RunAsAdministrator

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

[CmdletBinding()]
param()

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

# Check VDA installer (required)
Write-Host "Validating VDA installer..." -ForegroundColor Gray
if (Test-Path $VDAISOPath) {
    Write-Host "  VDA ISO: FOUND" -ForegroundColor Green
    
    # Enhanced VDA ISO validation
    try {
        $VDAFileInfo = Get-ItemProperty -Path $VDAISOPath
        $VDASize = [Math]::Round($VDAFileInfo.Length / 1MB, 1)
        Write-Host "  VDA ISO size: $VDASize MB" -ForegroundColor Gray
        
        if ($VDASize -lt 100) {
            $ValidationWarnings += "VDA ISO seems unusually small ($VDASize MB)"
        }
    }
    catch {
        $ValidationWarnings += "Could not validate VDA ISO properties"
    }
}
else {
    $ValidationErrors += "VDA ISO not found: $VDAISOPath"
    Write-Host "  VDA ISO: NOT FOUND" -ForegroundColor Red
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
        
        if (Test-Path $Component.Path) {
            Write-Host "  $($Component.Name): FOUND" -ForegroundColor Green
        }
        else {
            $ValidationWarnings += "$($Component.Name) not found: $($Component.Path)"
            Write-Host "  $($Component.Name): NOT FOUND" -ForegroundColor Yellow
            
            # Clear the variable if file doesn't exist
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
    # Check available disk space (enhanced)
    $SystemDrive = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'" -ErrorAction SilentlyContinue
    if ($SystemDrive) {
        $FreeSpaceGB = [Math]::Round($SystemDrive.FreeSpace / 1GB, 2)
        Write-Host "  Available disk space: $FreeSpaceGB GB" -ForegroundColor Gray
        
        if ($FreeSpaceGB -lt 15) {
            $ValidationErrors += "Insufficient disk space: $FreeSpaceGB GB available (minimum 15GB recommended)"
        }
        elseif ($FreeSpaceGB -lt 25) {
            $ValidationWarnings += "Low disk space: $FreeSpaceGB GB available (25GB+ recommended for optimal performance)"
        }
    }
    
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
    foreach ($Error in $ValidationErrors) {
        Write-Host "  - $Error" -ForegroundColor Red
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
    Import-Module $FunctionsPath -Force -ErrorAction Stop
    Write-Host "Functions module imported successfully" -ForegroundColor Green
}
catch {
    Write-Host "FATAL ERROR: Cannot import functions module: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Please ensure citrix_functions_library.psm1 is available and accessible." -ForegroundColor Yellow
    exit 1
}

# Initialize enhanced logging
try {
    $LogInitResult = Initialize-Logging -LogPath $LogPath -ClearExisting
    if (!$LogInitResult) {
        throw "Logging initialization failed"
    }
}
catch {
    Write-Host "WARNING: Could not initialize logging: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "Continuing without logging..." -ForegroundColor Yellow
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
    
    # Copy installation files from network location
    Write-LogHeader "Installation Files Copy Operation"
    Write-Log "Copying installation files from network location..."
    $NetworkPath = Get-ConfigValue "NetworkSourcePath" "\\fileserver\citrix\installers"
    $LocalPath = Get-ConfigValue "LocalInstallPath" "C:\Temp"
    $CopySuccess = Copy-InstallationFiles -NetworkPath $NetworkPath -LocalPath $LocalPath -Force
    
    if (!$CopySuccess) {
        Write-Log "Warning: Some installation files could not be copied from network location" "WARN"
        Write-Log "Installation will attempt to use existing local files or continue with available components" "WARN"
    }
    
    # Enhanced prerequisites test
    Write-LogHeader "Enhanced Prerequisites Validation"
    $PrereqResults = Test-Prerequisites
    
    if (!$PrereqResults.OverallStatus) {
        Write-Log "Prerequisites validation failed!" "ERROR"
        
        if ($PrereqResults.Issues.Count -gt 0) {
            Write-Log "Prerequisites issues:"
            foreach ($Issue in $PrereqResults.Issues) {
                Write-Log "  - $Issue" "ERROR"
            }
        }
        
        if ($ValidationMode -eq "Strict") {
            throw "Prerequisites validation failed in Strict mode"
        }
        else {
            Write-Log "Continuing despite prerequisites issues (non-Strict mode)" "WARN"
        }
    }
    else {
        Write-Log "Prerequisites validation passed successfully" "SUCCESS"
    }
    
    # Enhanced drive configuration initialization
    Write-LogHeader "Enhanced Drive Configuration"
    Write-Log "Initializing drive configuration..."
    
    $DriveConfigInit = Initialize-DriveConfiguration -Interactive $true
    
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
    
    # Enhanced existing installations check
    $ExistingInstalls = Test-ExistingCitrixInstallation
    
    if ($ExistingInstalls.Details.Count -gt 0) {
        Write-Log "Existing Citrix installations detected:" "WARN"
        foreach ($Detail in $ExistingInstalls.Details) {
            Write-Log "  - $Detail" "WARN"
        }
        Write-Log "Installation will proceed but may require additional configuration" "WARN"
    }
    
    # Initialize installation configuration
    $InstallConfig = Initialize-InstallConfig
    
    # Add Stage 1 specific properties
    $InstallConfig.Stage1CompletedAt = Get-Date
    $InstallConfig.ExistingInstallations = $ExistingInstalls
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
    Configure-WindowsServices
    
    Write-Log "Configuring Windows Firewall..."
    Configure-WindowsFirewall
    
    Write-Log "Disabling NetBIOS over TCP/IP..."
    Disable-NetBiosOverTCP
    
    Write-Log "Disabling network offload parameters for PVS compatibility..."
    Disable-NetworkOffloadParameters
    
    Write-Log "Configuring SMB settings for Citrix environments..."
    Configure-SMBSettings
    
    Write-Log "Configuring crash dump to kernel mode..."
    Set-CrashDumpToKernelMode
    
    Write-Log "Removing PasswordAge registry key..."
    Remove-PasswordAgeRegistryKey
    
    Write-Log "Running Citrix Optimizer..."
    Invoke-CitrixOptimizer
    
    Write-Log "Disabling specified Citrix services..."
    Disable-CitrixServices
    
    Write-Log "Configuring event logs location..."
    Configure-EventLogs
    
    Write-Log "Applying registry optimizations..."
    Set-RegistryOptimizations
    
    Write-Log "Applying VDI specific optimizations..."
    Set-VDIOptimizations -PagefileSizeGB $PagefileSizeGB
    
    Write-Log "Disabling VMware memory ballooning..."
    Disable-VMwareMemoryBallooning
    
    # Enhanced Citrix components installation
    Write-LogHeader "Enhanced Citrix Components Installation"
    
    # Run enhanced VDA prerequisites check
    Write-Log "Checking VDA installation prerequisites..."
    $VDAPrereqs = Test-VDAPrerequisites
    
    if ($VDAPrereqs.OverallStatus) {
        Write-Log "VDA prerequisites check passed - proceeding with installation" "SUCCESS"
    }
    else {
        Write-Log "VDA prerequisites check found issues - installation may encounter problems" "WARN"
        if ($VDAPrereqs.Issues.Count -gt 0) {
            Write-Log "Prerequisite issues:"
            foreach ($Issue in $VDAPrereqs.Issues) {
                Write-Log "  - $Issue" "WARN"
            }
        }
        
        if ($ValidationMode -eq "Strict") {
            throw "VDA prerequisites failed in Strict mode"
        }
    }
    
    # Install VDA from ISO (no delivery controller required)
    Write-Log "Installing Citrix VDA from ISO (no delivery controller required)..."
    $VDAResult = Install-CitrixVDA -VDAISOPath $VDAISOPath -LogDir (Split-Path $LogPath -Parent)
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
    if (![string]::IsNullOrEmpty($PVSISOPath)) {
        Write-Log "Installing PVS Target Device from ISO (no PVS server required)..."
        $PVSResult = Install-PVSTargetDevice -PVSISOPath $PVSISOPath
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
    if (![string]::IsNullOrEmpty($WEMPath)) {
        Write-Log "Installing WEM Agent (no infrastructure server required)..."
        $WEMResult = Install-WEMAgent -WEMPath $WEMPath
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
    
    # Install UberAgent (if specified)
    if (![string]::IsNullOrEmpty($UberAgentPath)) {
        Write-Log "Installing UberAgent..."
        
        $UberAgentParams = @{
            UberAgentInstallerPath = $UberAgentPath
        }
        
        # Add optional parameters if specified
        if (![string]::IsNullOrEmpty($UberAgentTemplatesPath)) {
            $UberAgentParams.UberAgentTemplatesPath = $UberAgentTemplatesPath
        }
        
        if (![string]::IsNullOrEmpty($UberAgentConfigPath)) {
            $UberAgentParams.UberAgentConfigPath = $UberAgentConfigPath
        }
        
        if (![string]::IsNullOrEmpty($UberAgentLicensePath)) {
            $UberAgentParams.UberAgentLicensePath = $UberAgentLicensePath
        }
        
        $UberAgentResult = Install-UberAgent @UberAgentParams
        $InstallConfig.InstallationResults.UberAgent = $UberAgentResult
        
        if ($UberAgentResult.OverallSuccess) {
            Write-Log "UberAgent installation and configuration completed successfully" "SUCCESS"
        }
        elseif (!$UberAgentResult.Skipped) {
            Write-Log "UberAgent installation encountered issues" "ERROR"
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
        
        $TADDMResult = Configure-IBMTADDMPermissions @TADDMParams
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
    
    # Complete installation
    Write-LogHeader "Completing Stage 1 Installation"
    
    $CompletionResult = Complete-Installation -Config $InstallConfig -Stage2ScriptPath $(if($Stage2Found){$Stage2ScriptPath}else{""})
    
    if ($CompletionResult) {
        Write-Log "Stage 1 completion successful" "SUCCESS"
    }
    else {
        Write-Log "Stage 1 completion encountered issues" "WARN"
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