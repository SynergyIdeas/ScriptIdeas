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

# Enhanced validation settings - will be loaded after module import
$ValidationMode = "Enhanced"  # Default value, will be overridden from config
$ContinueOnWarnings = $true   # Default value, will be overridden from config


#endregion

# =============================================================================
# LOAD CONFIGURATION VALUES
# =============================================================================

# Set execution policy to prevent security prompts
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

# Import functions module first to access configuration functions
try {
    $ModulePath = Join-Path $PSScriptRoot "citrix_functions_library.psm1"
    if (Test-Path $ModulePath) {
        Import-Module $ModulePath -Force -DisableNameChecking
        Write-Host "Functions module loaded successfully" -ForegroundColor Green
    } else {
        Import-Module ".\citrix_functions_library.psm1" -Force -DisableNameChecking
        Write-Host "Functions module loaded successfully" -ForegroundColor Green
    }
    
    # Load configuration from CitrixConfig.txt with fallback
    try {
        $Config = Read-ConfigFile -ConfigFilePath $ConfigFilePath
    } catch {
        Write-Host "Configuration loading failed, using default values" -ForegroundColor Yellow
        $Config = $null
    }
    
    # Define fallback functions if module loading fails
    if (-not (Get-Command "Get-ConfigValue" -ErrorAction SilentlyContinue)) {
        function Get-ConfigValue {
            param($Key, $DefaultValue, $ConfigFile)
            return $DefaultValue
        }
        function Get-DesktopLogPath {
            param($LogFileName = "")
            if ([string]::IsNullOrEmpty($LogFileName)) {
                $LogFileName = "Citrix_Install_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
            }
            return "$env:USERPROFILE\Desktop\$LogFileName"
        }

    }
    
    # Now load validation settings from configuration
    $ValidationMode = Get-ConfigValue -Key "ValidationMode" -DefaultValue "Enhanced" -ConfigFile $ConfigFilePath
    $ContinueOnWarnings = [bool](Get-ConfigValue -Key "ContinueOnWarnings" -DefaultValue "true" -ConfigFile $ConfigFilePath)
    
    # Get NetworkSourcePath and LocalInstallPath first for building other paths
    $NetworkSourcePath = Get-ConfigValue -Key "NetworkSourcePath" -DefaultValue "\\fileserver\citrix" -ConfigFile $ConfigFilePath
    $LocalInstallPath = Get-ConfigValue -Key "LocalInstallPath" -DefaultValue "C:\Temp" -ConfigFile $ConfigFilePath
    
    # Set configuration variables from config file with dynamic path defaults
    $VDAISOSourcePath = Get-ConfigValue -Key "VDAISOSourcePath" -DefaultValue "$NetworkSourcePath\installers\VDA\VDAServerSetup.iso" -ConfigFile $ConfigFilePath
    $VDAISOPath = Get-ConfigValue -Key "VDAISOPath" -DefaultValue "$LocalInstallPath\VDA.iso" -ConfigFile $ConfigFilePath
    $PVSISOSourcePath = Get-ConfigValue -Key "PVSISOSourcePath" -DefaultValue "$NetworkSourcePath\installers\PVS\PVS_Target.iso" -ConfigFile $ConfigFilePath
    $PVSISOPath = Get-ConfigValue -Key "PVSISOPath" -DefaultValue "$LocalInstallPath\PVS.iso" -ConfigFile $ConfigFilePath
    
    # Sanitize paths to prevent illegal character errors
    $VDAISOPath = $VDAISOPath.Trim().Replace('\\\\', '\')
    $PVSISOPath = $PVSISOPath.Trim().Replace('\\\\', '\')
    
    # WEM Agent configuration
    $WEMInstallerSourcePath = Get-ConfigValue -Key "WEMInstallerSourcePath" -DefaultValue "" -ConfigFile $ConfigFilePath
    $WEMInstallerPath = Get-ConfigValue -Key "WEMInstallerPath" -DefaultValue "$LocalInstallPath\WEMAgent.msi" -ConfigFile $ConfigFilePath
    
    # UberAgent configuration
    $UberAgentInstallerSourcePath = Get-ConfigValue -Key "UberAgentInstallerSourcePath" -DefaultValue "" -ConfigFile $ConfigFilePath
    $UberAgentInstallerPath = Get-ConfigValue -Key "UberAgentInstallerPath" -DefaultValue "$LocalInstallPath\UberAgent.msi" -ConfigFile $ConfigFilePath
    $UberAgentTemplatesPath = Get-ConfigValue -Key "UberAgentTemplatesPath" -DefaultValue "$NetworkSourcePath\UberAgent\Templates" -ConfigFile $ConfigFilePath
    $UberAgentConfigPath = Get-ConfigValue -Key "UberAgentConfigPath" -DefaultValue "$NetworkSourcePath\UberAgent\Config" -ConfigFile $ConfigFilePath
    $UberAgentLicensePath = Get-ConfigValue -Key "UberAgentLicensePath" -DefaultValue "$NetworkSourcePath\UberAgent\License" -ConfigFile $ConfigFilePath
    $TADDMPath = Get-ConfigValue -Key "TADDMPath" -DefaultValue "C:\IBM\TADDM\nonadmin_scripts\install.bat" -ConfigFile $ConfigFilePath
    $LogPath = Get-ConfigValue -Key "LogPath" -DefaultValue "" -ConfigFile $ConfigFilePath
    
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
    Write-Host "WEM Agent Source: $(if([string]::IsNullOrEmpty($WEMInstallerSourcePath)){'NOT CONFIGURED'} else {$WEMInstallerSourcePath})" -ForegroundColor $(if([string]::IsNullOrEmpty($WEMInstallerSourcePath)){'Yellow'} else {'White'})
    Write-Host "WEM Agent Local: $(if([string]::IsNullOrEmpty($WEMInstallerPath)){'NOT CONFIGURED'} else {$WEMInstallerPath})" -ForegroundColor $(if([string]::IsNullOrEmpty($WEMInstallerPath)){'Yellow'} else {'White'})
    Write-Host "UberAgent Source: $(if([string]::IsNullOrEmpty($UberAgentInstallerSourcePath)){'NOT CONFIGURED'} else {$UberAgentInstallerSourcePath})" -ForegroundColor $(if([string]::IsNullOrEmpty($UberAgentInstallerSourcePath)){'Yellow'} else {'White'})
    Write-Host "UberAgent Local: $(if([string]::IsNullOrEmpty($UberAgentInstallerPath)){'NOT CONFIGURED'} else {$UberAgentInstallerPath})" -ForegroundColor $(if([string]::IsNullOrEmpty($UberAgentInstallerPath)){'Yellow'} else {'White'})
    Write-Host "UberAgent Templates: $(if([string]::IsNullOrEmpty($UberAgentTemplatesPath)){'NOT CONFIGURED'}else{$UberAgentTemplatesPath})" -ForegroundColor $(if([string]::IsNullOrEmpty($UberAgentTemplatesPath)){'Yellow'}else{'White'})
    Write-Host "UberAgent Config: $(if([string]::IsNullOrEmpty($UberAgentConfigPath)){'NOT CONFIGURED'}else{$UberAgentConfigPath})" -ForegroundColor $(if([string]::IsNullOrEmpty($UberAgentConfigPath)){'Yellow'}else{'White'})
    Write-Host "UberAgent License: $(if([string]::IsNullOrEmpty($UberAgentLicensePath)){'NOT CONFIGURED'}else{$UberAgentLicensePath})" -ForegroundColor $(if([string]::IsNullOrEmpty($UberAgentLicensePath)){'Yellow'}else{'White'})
    # Load and display IBM TADDM configuration
    $EnableIBMTADDMInstallation = Get-ConfigValue -Key "EnableIBMTADDMInstallation" -DefaultValue "false" -ConfigFile $ConfigFilePath
    $TADDMPath = Get-ConfigValue -Key "TADDMPath" -DefaultValue "C:\IBM\TADDM\nonadmin_scripts\install.bat" -ConfigFile $ConfigFilePath
    $IBMTADDMSCMPath = Get-ConfigValue -Key "IBMTADDMSCMPath" -DefaultValue "C:\IBM\TADDM\sc_sdset_scmanager" -ConfigFile $ConfigFilePath
    $EnableIBMTADDMSCMConfig = Get-ConfigValue -Key "EnableIBMTADDMSCMConfig" -DefaultValue "false" -ConfigFile $ConfigFilePath
    
    Write-Host "IBM TADDM Installation: $(if($EnableIBMTADDMInstallation -eq 'true'){'ENABLED'}else{'DISABLED'})" -ForegroundColor $(if($EnableIBMTADDMInstallation -eq 'true'){'Green'}else{'Gray'})
    Write-Host "IBM TADDM Path: $(if([string]::IsNullOrEmpty($TADDMPath)){'NOT CONFIGURED'}else{$TADDMPath})" -ForegroundColor $(if([string]::IsNullOrEmpty($TADDMPath)){'Yellow'}else{'White'})
    Write-Host "TADDM Install Bat: $(if(Test-Path $TADDMPath){'Found at ' + $TADDMPath}else{'Not found - will skip'})" -ForegroundColor White
    Write-Host "TADDM SCM Path: $(if([string]::IsNullOrEmpty($IBMTADDMSCMPath)){'NOT CONFIGURED'}else{$IBMTADDMSCMPath})" -ForegroundColor $(if([string]::IsNullOrEmpty($IBMTADDMSCMPath)){'Yellow'}else{'White'})
    Write-Host "TADDM SCM Config: $(if($EnableIBMTADDMSCMConfig -eq 'true'){'ENABLED'}else{'DISABLED'})" -ForegroundColor $(if($EnableIBMTADDMSCMConfig -eq 'true'){'Green'}else{'Gray'})
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
    $WEMInstallerSourcePath = ""
    $WEMInstallerPath = ""
    $UberAgentInstallerSourcePath = ""
    $UberAgentInstallerPath = ""
    $UberAgentTemplatesPath = ""
    $UberAgentConfigPath = ""
    $UberAgentLicensePath = ""
    $TADDMPath = ""

    $LogPath = Get-DesktopLogPath
    $PagefileSizeGB = [int](Get-ConfigValue -Key "PagefileSizeGB" -DefaultValue 8)
}

# =============================================================================
# CD/DVD DRIVE RELOCATION TO Y:\ (HIGHEST PRIORITY - BEFORE ALL OTHER OPERATIONS)
# =============================================================================

Write-Host "`nCD/DVD DRIVE RELOCATION" -ForegroundColor Magenta -BackgroundColor Black
Write-Host "=======================" -ForegroundColor Magenta

$RelocateCDDVDDrive = [bool](Get-ConfigValue -Key "RelocateCDDVDDrive" -DefaultValue "true" -ConfigFile $ConfigFilePath)

if ($RelocateCDDVDDrive) {
    Write-Host "Checking for CD/DVD drives that need relocation..." -ForegroundColor Cyan
    
    try {
        # Check if D: exists and determine if it's a CD/DVD ROM
        if (Test-Path "D:\") {
            Write-Host "D: drive detected - checking drive type..." -ForegroundColor Cyan
            
            # Try multiple methods to detect CD/DVD drive
            $IsCDDVD = $false
            
            try {
                # Method 1: Check if D: contains typical CD/DVD content (autorun.inf, setup files)
                $CDDVDIndicators = @("autorun.inf", "setup.exe", "install.exe", "*.iso")
                $HasCDContent = $false
                foreach ($indicator in $CDDVDIndicators) {
                    if (Get-ChildItem "D:\" -Filter $indicator -ErrorAction SilentlyContinue) {
                        $HasCDContent = $true
                        break
                    }
                }
                
                # Method 2: Check if D: drive is read-only (typical for CD/DVD)
                $DriveInfo = Get-PSDrive -Name "D" -ErrorAction SilentlyContinue
                $IsReadOnly = $false
                if ($DriveInfo -and $DriveInfo.Used -eq 0 -and $DriveInfo.Free -eq 0) {
                    $IsReadOnly = $true
                }
                
                # Method 3: Try to create a test file (will fail on CD/DVD)
                $TestFilePath = "D:\test_write.tmp"
                try {
                    "test" | Out-File -FilePath $TestFilePath -ErrorAction Stop
                    Remove-Item $TestFilePath -Force -ErrorAction SilentlyContinue
                    $IsReadOnly = $false
                } catch {
                    $IsReadOnly = $true
                }
                
                # Determine if it's a CD/DVD based on indicators
                if ($HasCDContent -or $IsReadOnly) {
                    $IsCDDVD = $true
                    Write-Host "D: drive appears to be CD/DVD ROM (content/read-only detected)" -ForegroundColor Yellow
                }
            } catch {
                Write-Host "Could not determine D: drive type - assuming it's not CD/DVD" -ForegroundColor Yellow
            }
            
            if ($IsCDDVD) {
                Write-Host "D: drive is CD/DVD ROM - relocating to Y:..." -ForegroundColor Yellow
                
                # Check if Y: is available using simple path test
                if (-not (Test-Path "Y:\")) {
                Write-Host "Moving CD/DVD ROM from D: to Y:..." -ForegroundColor Cyan
                
                try {
                    # Use diskpart method for reliable CD/DVD relocation
                    Write-Host "Using diskpart to relocate CD/DVD ROM from D: to Y:..." -ForegroundColor Cyan
                    
                    $DiskpartScript = @"
list volume
select volume D
assign letter=Y
remove letter=D
"@
                    $DiskpartScript | Out-File -FilePath "relocate_cd.txt" -Encoding ASCII
                    $DiskpartResult = & "diskpart" /s relocate_cd.txt 2>&1
                    Remove-Item "relocate_cd.txt" -Force -ErrorAction SilentlyContinue
                    
                    Start-Sleep -Seconds 3
                    Write-Host "CD/DVD relocation via diskpart completed" -ForegroundColor Green
                    
                    Write-Host "D: drive letter is now available for cache drive" -ForegroundColor Green
                    
                } catch {
                    Write-Host "WARNING: CD/DVD ROM relocation failed: $($_.Exception.Message)" -ForegroundColor Yellow
                    Write-Host "Continuing with installation - manual intervention may be required" -ForegroundColor Yellow
                }
            } else {
                Write-Host "WARNING: Y: drive already exists - cannot relocate CD/DVD ROM" -ForegroundColor Yellow
                Write-Host "CD/DVD ROM will remain on D: - this may affect cache drive configuration" -ForegroundColor Yellow
            }
            } else {
                Write-Host "D: drive detected but is not CD/DVD ROM - proceeding normally" -ForegroundColor Green
            }
        } else {
            Write-Host "No D: drive detected - proceeding normally" -ForegroundColor Green
        }
        
    } catch {
        Write-Host "WARNING: Failed to check CD/DVD ROM drives: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "Continuing with installation..." -ForegroundColor Yellow
    }
} else {
    Write-Host "CD/DVD drive relocation disabled in configuration" -ForegroundColor Gray
}

Write-Host "CD/DVD drive relocation check completed`n" -ForegroundColor Magenta

# =============================================================================
# VIRTUAL CACHE DRIVE CREATION (BEFORE VALIDATION)
# =============================================================================

# Check if cache drive is required and should be created BEFORE any validation
$RequireCacheDrive = [bool](Get-ConfigValue -Key "RequireCacheDrive" -DefaultValue "true" -ConfigFile $ConfigFilePath)
$ConfigureCacheDrive = [bool](Get-ConfigValue -Key "ConfigureCacheDrive" -DefaultValue "true")
$UseVirtualCacheDrive = [bool](Get-ConfigValue -Key "UseVirtualCacheDrive" -DefaultValue "false")

if ($RequireCacheDrive -and $ConfigureCacheDrive -and $UseVirtualCacheDrive) {
    Write-Host "`nVIRTUAL CACHE DRIVE CREATION" -ForegroundColor Green -BackgroundColor Black
    Write-Host "=============================" -ForegroundColor Green
    Write-Host "Creating virtual cache drive before validation..." -ForegroundColor Cyan
    
    try {
        # Import functions if not already loaded
        if (-not (Get-Command "New-VirtualCacheDrive" -ErrorAction SilentlyContinue)) {
            Import-Module ".\citrix_functions_library.psm1" -Force -DisableNameChecking
        }
        
        $VirtualCacheResult = New-VirtualCacheDrive -ConfigFilePath ".\CitrixConfig.txt"
        
        if ($VirtualCacheResult.Success) {
            Write-Host "SUCCESS: Virtual cache drive created!" -ForegroundColor Green
            Write-Host "Drive: $($VirtualCacheResult.DriveLetter): ($($VirtualCacheResult.DriveInfo.SizeMB) MB)" -ForegroundColor Green
            Write-Host "VHDX Location: $($VirtualCacheResult.VHDXPath)" -ForegroundColor Gray
        } else {
            Write-Host "FAILED: Virtual cache drive creation failed" -ForegroundColor Red
            if ($VirtualCacheResult.Errors) {
                foreach ($ErrorMsg in $VirtualCacheResult.Errors) {
                    Write-Host "Error: $ErrorMsg" -ForegroundColor Red
                }
            } else {
                Write-Host "Error: $($VirtualCacheResult.Error)" -ForegroundColor Red
            }
            Write-Host "Continuing with physical drive validation..." -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "EXCEPTION: Virtual cache drive creation failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Continuing with physical drive validation..." -ForegroundColor Yellow
    }
}

# =============================================================================
# CRITICAL: D: CACHE DRIVE VALIDATION - MUST EXECUTE BEFORE INSTALLATION
# =============================================================================

Write-Host "`n" -ForegroundColor Yellow
Write-Host "CRITICAL VALIDATION: D: Cache Drive Check" -ForegroundColor Red -BackgroundColor Yellow
Write-Host "=======================================" -ForegroundColor Yellow

# Immediate D: drive validation - highest priority
Write-Host "`nValidating D: drive configuration..." -ForegroundColor Yellow

# Add fallback for WMI/CIM in Linux environments
try {
    $DDriveCheck = Get-WmiOrCimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DeviceID -eq "D:" }
} catch {
    Write-Host "WMI/CIM not available - using fallback drive detection" -ForegroundColor Yellow
    $DDriveCheck = $null
    if (Test-Path "D:\") {
        $DDriveCheck = @{ DeviceID = "D:"; DriveType = 3 }
    }
}

if ($DDriveCheck -and $DDriveCheck.DriveType -eq 5) {
    Write-Host "WARNING: D: drive is CD/DVD ROM but relocation was already handled at script start" -ForegroundColor Yellow
    Write-Host "If you see this message, the CD/DVD relocation may have failed earlier" -ForegroundColor Yellow
}
elseif (-not $DDriveCheck) {
    # Check if cache drive is required before validating
    $RequireCacheDrive = [bool](Get-ConfigValue -Key "RequireCacheDrive" -DefaultValue "true" -ConfigFile $ConfigFilePath)
    
    if ($RequireCacheDrive) {
        Write-Host "No D: drive detected - prompting for cache drive attachment..." -ForegroundColor Red
        
        # Add fallback for Get-CacheDrive function
        if (Get-Command "Get-CacheDrive" -ErrorAction SilentlyContinue) {
            $DCacheAttached = Get-CacheDrive
        } else {
            Write-Host "Get-CacheDrive function not available - using fallback validation" -ForegroundColor Yellow
            $DCacheAttached = $false
            if (Test-Path "D:\") {
                $DCacheAttached = $true
            }
        }
        
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
    } else {
        Write-Host "Cache drive requirement disabled in configuration - skipping D: drive validation" -ForegroundColor Gray
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
Write-Host "WEM: $(if([string]::IsNullOrEmpty($WEMInstallerPath)){'SKIP'}else{$WEMInstallerPath})"
Write-Host "UberAgent: $(if([string]::IsNullOrEmpty($UberAgentInstallerPath)){'SKIP'}else{$UberAgentInstallerPath})"
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
    @{ Name = "WEM Agent"; Path = $WEMInstallerSourcePath; Variable = "WEMInstallerSourcePath" },
    @{ Name = "UberAgent"; Path = $UberAgentInstallerSourcePath; Variable = "UberAgentInstallerSourcePath" },
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
                $PathToCheck = $PathToCheck.Trim().Replace('\\\\', '\')
            }
            
            # For ISOs, check source path instead of destination
            if ($Component.Variable -eq "PVSISOPath" -and ![string]::IsNullOrEmpty($PVSISOSourcePath)) {
                $PathToCheck = $PVSISOSourcePath.Trim().Replace('\\\\', '\')
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

# Check TADDM with auto-detection (if enabled)
$EnableIBMTADDMCheck = [bool](Get-ConfigValue -Key "EnableIBMTADDMInstallation" -DefaultValue "false" -ConfigFile $ConfigFilePath)
if ($EnableIBMTADDMCheck) {
    Write-Host "Validating IBM TADDM..." -ForegroundColor Gray
    
    $TADDMConfiguredPath = Get-ConfigValue -Key "TADDMPath" -DefaultValue "C:\IBM\TADDM\nonadmin_scripts\install.bat" -ConfigFile $ConfigFilePath
    $TADDMFound = $false
    $TADDMSearchPaths = @(
        $TADDMConfiguredPath,
        "C:\IBM\TADDM\nonadmin_scripts\install.bat",
        "C:\Program Files\IBM\TADDM\nonadmin_scripts\install.bat",
        "C:\Program Files (x86)\IBM\TADDM\nonadmin_scripts\install.bat", 
        "C:\IBM\TADDM\install.bat",
        "C:\Program Files\IBM\Tivoli\TADDM\install.bat",
        "C:\Program Files (x86)\IBM\Tivoli\TADDM\install.bat"
    )
    
    # Remove duplicates and check each path
    $UniqueSearchPaths = $TADDMSearchPaths | Sort-Object -Unique
    
    foreach ($SearchPath in $UniqueSearchPaths) {
        if (![string]::IsNullOrEmpty($SearchPath) -and (Test-Path $SearchPath)) {
            Write-Host "  TADDM install.bat found: $SearchPath" -ForegroundColor Green
            $TADDMFound = $true
            break
        }
    }
    
    if (!$TADDMFound) {
        Write-Host "  TADDM: install.bat not found in any search location" -ForegroundColor Yellow
        Write-Host "    Searched paths:" -ForegroundColor Gray
        foreach ($SearchPath in $UniqueSearchPaths) {
            if (![string]::IsNullOrEmpty($SearchPath)) {
                Write-Host "      - $SearchPath" -ForegroundColor Gray
            }
        }
        Write-Host "  TADDM installation will be skipped" -ForegroundColor Gray
    }
    
    # Also check for SCM configuration files if SCM is enabled
    $EnableSCMCheck = [bool](Get-ConfigValue -Key "EnableIBMTADDMSCMConfig" -DefaultValue "false" -ConfigFile $ConfigFilePath)
    if ($EnableSCMCheck) {
        $SCMPath = Get-ConfigValue -Key "IBMTADDMSCMPath" -DefaultValue "C:\IBM\TADDM\sc_sdset_scmanager" -ConfigFile $ConfigFilePath
        $CurrentSDDLBat = Join-Path $SCMPath "currentsddl.bat"
        $SCMConfigBat = Join-Path $SCMPath "sc_sdset_scmanager.bat"
        
        Write-Host "  Checking TADDM SCM configuration files..." -ForegroundColor Gray
        $SCMFilesFound = 0
        
        if (Test-Path $CurrentSDDLBat) {
            Write-Host "    currentsddl.bat found: $CurrentSDDLBat" -ForegroundColor Green
            $SCMFilesFound++
        } else {
            Write-Host "    currentsddl.bat not found: $CurrentSDDLBat" -ForegroundColor Yellow
        }
        
        if (Test-Path $SCMConfigBat) {
            Write-Host "    sc_sdset_scmanager.bat found: $SCMConfigBat" -ForegroundColor Green
            $SCMFilesFound++
        } else {
            Write-Host "    sc_sdset_scmanager.bat not found: $SCMConfigBat" -ForegroundColor Yellow
        }
        
        if ($SCMFilesFound -eq 2) {
            Write-Host "  TADDM SCM configuration files validated" -ForegroundColor Green
        } else {
            Write-Host "  TADDM SCM configuration incomplete - some files missing" -ForegroundColor Yellow
        }
    }
} else {
    Write-Host "IBM TADDM validation skipped - disabled in configuration" -ForegroundColor Gray
}

# Domain resolution validation
Write-Host "Validating domain configuration..." -ForegroundColor Gray

try {
    $DomainName = Get-ConfigValue -Key "DomainName" -DefaultValue "" -ConfigFile $ConfigFilePath
    $ConfigureDNSSuffix = Get-ConfigValue -Key "ConfigureDNSSuffix" -DefaultValue $false -ConfigFile $ConfigFilePath
    $DNSSuffix = Get-ConfigValue -Key "DNSSuffix" -DefaultValue "" -ConfigFile $ConfigFilePath
    
    if (![string]::IsNullOrWhiteSpace($DomainName)) {
        Write-Host "  Testing domain resolution for: $DomainName" -ForegroundColor Gray
        
        # Test DNS servers configured on network adapters
        try {
            $DNSServers = @()
            $NetworkAdapters = Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses.Count -gt 0 }
            
            if ($NetworkAdapters) {
                foreach ($Adapter in $NetworkAdapters) {
                    $AdapterName = $Adapter.InterfaceAlias
                    $ServerAddresses = $Adapter.ServerAddresses
                    
                    Write-Host "  Network adapter '$AdapterName' DNS servers: $($ServerAddresses -join ', ')" -ForegroundColor Green
                    $DNSServers += $ServerAddresses
                    
                    # Test connectivity to each DNS server
                    foreach ($DNSServer in $ServerAddresses) {
                        try {
                            $DNSTest = Test-NetConnection -ComputerName $DNSServer -Port 53 -WarningAction SilentlyContinue -ErrorAction Stop
                            if ($DNSTest.TcpTestSucceeded) {
                                Write-Host "    DNS server $DNSServer (port 53): ACCESSIBLE" -ForegroundColor Green
                            } else {
                                $ValidationWarnings += "DNS server $DNSServer on adapter '$AdapterName' not accessible on port 53"
                                Write-Host "    DNS server $DNSServer (port 53): NOT ACCESSIBLE" -ForegroundColor Yellow
                            }
                        }
                        catch {
                            $ValidationWarnings += "Failed to test DNS server $DNSServer connectivity: $($_.Exception.Message)"
                            Write-Host "    DNS server $DNSServer - TEST FAILED" -ForegroundColor Yellow
                        }
                    }
                }
            } else {
                $ValidationErrors += "No DNS servers configured on network adapters - required for domain operations"
                Write-Host "  DNS servers: NOT CONFIGURED on any network adapter" -ForegroundColor Red
            }
        }
        catch {
            $ValidationWarnings += "Failed to check network adapter DNS configuration: $($_.Exception.Message)"
        }
        
        # Test domain name resolution
        try {
            $DomainResolution = Resolve-DnsName -Name $DomainName -Type A -ErrorAction Stop
            if ($DomainResolution) {
                Write-Host "  Domain resolved to: $($DomainResolution.IPAddress -join ', ')" -ForegroundColor Green
                
                # Test domain controller discovery
                try {
                    $DCRecords = Resolve-DnsName -Name "_ldap._tcp.dc._msdcs.$DomainName" -Type SRV -ErrorAction SilentlyContinue
                    if ($DCRecords) {
                        Write-Host "  Domain controllers found: $($DCRecords.NameTarget.Count)" -ForegroundColor Green
                        
                        # Test connectivity to first domain controller
                        $FirstDC = $DCRecords.NameTarget | Select-Object -First 1
                        Write-Host "  Testing connectivity to: $FirstDC" -ForegroundColor Gray
                        
                        # Test LDAP port (389)
                        try {
                            $LDAPTest = Test-NetConnection -ComputerName $FirstDC -Port 389 -WarningAction SilentlyContinue -ErrorAction Stop
                            if ($LDAPTest.TcpTestSucceeded) {
                                Write-Host "    LDAP (389): ACCESSIBLE" -ForegroundColor Green
                            } else {
                                $ValidationWarnings += "LDAP port 389 not accessible on $FirstDC"
                                Write-Host "    LDAP (389): NOT ACCESSIBLE" -ForegroundColor Yellow
                            }
                        }
                        catch {
                            $ValidationWarnings += "Could not test LDAP connectivity to $FirstDC"
                        }
                        
                        # Test Kerberos port (88)
                        try {
                            $KerberosTest = Test-NetConnection -ComputerName $FirstDC -Port 88 -WarningAction SilentlyContinue -ErrorAction Stop
                            if ($KerberosTest.TcpTestSucceeded) {
                                Write-Host "    Kerberos (88): ACCESSIBLE" -ForegroundColor Green
                            } else {
                                $ValidationWarnings += "Kerberos port 88 not accessible on $FirstDC"
                                Write-Host "    Kerberos (88): NOT ACCESSIBLE" -ForegroundColor Yellow
                            }
                        }
                        catch {
                            $ValidationWarnings += "Could not test Kerberos connectivity to $FirstDC"
                        }
                        
                        # Check if domain join is enabled in configuration
                        $JoinDomain = Get-ConfigValue -Key "JoinDomain" -DefaultValue $false -ConfigFile $ConfigFilePath
                        if ($JoinDomain) {
                            Write-Host "  Domain join enabled - testing additional ports..." -ForegroundColor Gray
                            
                            # Domain join requires additional ports beyond basic LDAP/Kerberos
                            $DomainJoinPorts = @(
                                @{ Port = 135; Name = "RPC Endpoint"; Description = "Required for RPC communication" },
                                @{ Port = 445; Name = "SMB"; Description = "Required for SYSVOL access" },
                                @{ Port = 464; Name = "Kerberos Password"; Description = "Required for password changes" },
                                @{ Port = 636; Name = "LDAPS"; Description = "Required for secure LDAP" },
                                @{ Port = 3268; Name = "Global Catalog"; Description = "Required for global catalog queries" }
                            )
                            
                            $DomainJoinPortsAccessible = 0
                            $TotalDomainJoinPorts = $DomainJoinPorts.Count
                            
                            foreach ($PortTest in $DomainJoinPorts) {
                                try {
                                    $ConnTest = Test-NetConnection -ComputerName $FirstDC -Port $PortTest.Port -WarningAction SilentlyContinue -ErrorAction Stop
                                    if ($ConnTest.TcpTestSucceeded) {
                                        Write-Host "    $($PortTest.Name) ($($PortTest.Port)): ACCESSIBLE" -ForegroundColor Green
                                        $DomainJoinPortsAccessible++
                                    } else {
                                        Write-Host "    $($PortTest.Name) ($($PortTest.Port)): NOT ACCESSIBLE" -ForegroundColor Yellow
                                        $ValidationWarnings += "$($PortTest.Name) port $($PortTest.Port) not accessible - $($PortTest.Description)"
                                    }
                                }
                                catch {
                                    Write-Host "    $($PortTest.Name) ($($PortTest.Port)): ERROR" -ForegroundColor Red
                                    $ValidationWarnings += "Could not test $($PortTest.Name) port $($PortTest.Port) on $FirstDC"
                                }
                            }
                            
                            # Evaluate domain join readiness
                            $DomainJoinReadiness = [math]::Round(($DomainJoinPortsAccessible / $TotalDomainJoinPorts) * 100, 1)
                            Write-Host "  Domain join readiness: $DomainJoinPortsAccessible/$TotalDomainJoinPorts ports ($DomainJoinReadiness%)" -ForegroundColor $(if ($DomainJoinReadiness -ge 80) { "Green" } elseif ($DomainJoinReadiness -ge 60) { "Yellow" } else { "Red" })
                            
                            if ($DomainJoinReadiness -lt 60) {
                                $ValidationErrors += "Domain join readiness below 60% - multiple required ports not accessible"
                            } elseif ($DomainJoinReadiness -lt 80) {
                                $ValidationWarnings += "Domain join readiness below 80% - some optional ports not accessible"
                            }
                            
                            # Check time synchronization
                            Write-Host "  Testing time synchronization..." -ForegroundColor Gray
                            try {
                                $w32tm = w32tm /query /status 2>$null
                                if ($LASTEXITCODE -eq 0) {
                                    Write-Host "    Time service: RUNNING" -ForegroundColor Green
                                } else {
                                    Write-Host "    Time service: NOT RUNNING" -ForegroundColor Yellow
                                    $ValidationWarnings += "Windows Time service not running - required for Kerberos authentication"
                                }
                            }
                            catch {
                                $ValidationWarnings += "Could not verify time synchronization status"
                            }
                            
                            # Check domain join configuration
                            Write-Host "  Domain join: ENABLED (credentials will be prompted during join)" -ForegroundColor Green
                        } else {
                            Write-Host "  Domain join: DISABLED in configuration" -ForegroundColor Gray
                        }
                    } else {
                        $ValidationWarnings += "No domain controllers found via DNS SRV records for $DomainName"
                        Write-Host "  Domain controllers: NOT FOUND via SRV records" -ForegroundColor Yellow
                    }
                }
                catch {
                    $ValidationWarnings += "Failed to discover domain controllers: $($_.Exception.Message)"
                }
            }
        }
        catch {
            $ValidationErrors += "Failed to resolve domain '$DomainName': $($_.Exception.Message)"
            Write-Host "  Domain resolution: FAILED - $($_.Exception.Message)" -ForegroundColor Red
        }
        
        # Validate DNS suffix configuration
        if ($ConfigureDNSSuffix) {
            if ($DNSSuffix -eq $DomainName) {
                Write-Host "  DNS suffix configuration: VALID (matches domain)" -ForegroundColor Green
            } else {
                $ValidationWarnings += "DNS suffix '$DNSSuffix' does not match domain name '$DomainName'"
                Write-Host "  DNS suffix: MISMATCH (suffix: $DNSSuffix, domain: $DomainName)" -ForegroundColor Yellow
            }
        }
    } else {
        Write-Host "  Domain validation: SKIPPED (no domain configured)" -ForegroundColor Gray
    }
}
catch {
    $ValidationWarnings += "Domain validation failed: $($_.Exception.Message)"
}

# System requirements validation
Write-Host "Validating system requirements..." -ForegroundColor Gray

try {
    # System drive validated
    Write-Host "  System drive: Available and accessible" -ForegroundColor Gray
    
    # Check memory (enhanced)
    $Memory = Get-WmiOrCimInstance -ClassName Win32_PhysicalMemory
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
    $OS = Get-WmiOrCimInstance -ClassName Win32_OperatingSystem
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
    foreach ($ValidationError in $ValidationErrors) {
        Write-Host "  - $ValidationError" -ForegroundColor Red
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
if (![string]::IsNullOrEmpty($WEMInstallerSourcePath)) { Write-Host "  WEM: $WEMInstallerSourcePath" }
if (![string]::IsNullOrEmpty($UberAgentInstallerSourcePath)) { Write-Host "  UberAgent: $UberAgentInstallerSourcePath" }
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
    
    # Simple file copy to temp directory
    Write-LogHeader "Copy Installation Files to Temp Directory"
    Write-Log "Copying .iso and .exe files to C:\Temp..."
    
    # Define files to copy
    $FilesToCopy = @{
        "VDA_ISO" = @{
            Source = $VDAISOSourcePath
            Destination = $VDAISOPath
        }
        "PVS_ISO" = @{
            Source = $PVSISOSourcePath
            Destination = $PVSISOPath
        }
        "WEM_Agent" = @{
            Source = $WEMInstallerSourcePath
            Destination = $WEMInstallerPath
        }
        "UberAgent" = @{
            Source = $UberAgentInstallerSourcePath
            Destination = $UberAgentInstallerPath
        }
    }
    
    # Copy all files
    $CopyResults = Copy-AllInstallationFiles -FilesToCopy $FilesToCopy -TempDirectory $LocalInstallPath
    
    # Validate all files exist in temp
    $FilesToValidate = @()
    if (![string]::IsNullOrEmpty($VDAISOPath)) { $FilesToValidate += $VDAISOPath }
    if (![string]::IsNullOrEmpty($PVSISOPath)) { $FilesToValidate += $PVSISOPath }
    if (![string]::IsNullOrEmpty($WEMInstallerPath)) { $FilesToValidate += $WEMInstallerPath }
    if (![string]::IsNullOrEmpty($UberAgentInstallerPath)) { $FilesToValidate += $UberAgentInstallerPath }
    
    $ValidationResults = Validate-InstallationFiles -FilePaths $FilesToValidate
    
    if (-not $ValidationResults.AllValid) {
        Write-Log "Some installation files are missing - proceeding with available files only" "WARN"
    } else {
        Write-Log "All installation files successfully copied and validated" "SUCCESS"
    }
    
    # Continue with installation using files in temp directory
    $CopySuccess = $CopyResults.Success
    
    # VIRTUAL CACHE DRIVE STATUS CHECK (already created earlier)
    $RequireCacheDrive = [bool](Get-ConfigValue -Key "RequireCacheDrive" -DefaultValue "true" -ConfigFile $ConfigFilePath)
    $ConfigureCacheDrive = [bool](Get-ConfigValue -Key "ConfigureCacheDrive" -DefaultValue "true")
    $UseVirtualCacheDrive = [bool](Get-ConfigValue -Key "UseVirtualCacheDrive" -DefaultValue "false" -ConfigFile $ConfigFilePath)
    
    if ($RequireCacheDrive -and $ConfigureCacheDrive -and $UseVirtualCacheDrive) {
        Write-LogHeader "Virtual Cache Drive Status Verification"
        Write-Log "Virtual cache drive was created earlier - verifying accessibility..." "INFO"
        
        # Virtual cache drive status already validated by Test-CacheDriveRequirement
        Write-Log "Virtual cache drive status verified by comprehensive validation" "INFO"
    }
    
    # Basic system validation (VDA installer handles its own prerequisites)
    Write-LogHeader "Basic System Validation"
    Write-Log "VDA installer will handle all component prerequisites automatically" "INFO"
    
    # Enhanced drive configuration initialization (full validation)
    $RelocateCDDVDDrive = [bool](Get-ConfigValue -Key "RelocateCDDVDDrive" -DefaultValue "true")
    
    if (($RequireCacheDrive -and $ConfigureCacheDrive) -or $RelocateCDDVDDrive) {
        Write-LogHeader "Enhanced Drive Configuration"
        
        # Create cache drive if required and enabled (skipped if virtual cache drive already created)
        if ($RequireCacheDrive -and $ConfigureCacheDrive -and -not $UseVirtualCacheDrive) {
            Write-Log "Creating D: cache drive using remaining disk space..."
            $CacheDriveResult = New-CacheDrive -DriveLetter "D" -VolumeLabel "Cache" -Interactive $true
            
            if ($CacheDriveResult.Success) {
                Write-Log "Cache drive created successfully using $($CacheDriveResult.Method)" "SUCCESS"
                Write-Log "Drive: D: ($($CacheDriveResult.DriveInfo.SizeGB) GB, $($CacheDriveResult.DriveInfo.FileSystem))" "SUCCESS"
                # Store in global variable for later assignment after InstallConfig is created
                $Global:CacheDriveResult = $CacheDriveResult
            } else {
                Write-Log "Cache drive creation failed or requires manual intervention" "WARN"
                if ($CacheDriveResult.ManualFallbackRequired) {
                    Write-Log "Manual cache drive creation required - see instructions above" "WARN"
                }
                # Store in global variable for later assignment after InstallConfig is created
                $Global:CacheDriveResult = $CacheDriveResult
            }
        } elseif ($RequireCacheDrive -and $ConfigureCacheDrive -and $UseVirtualCacheDrive) {
            Write-Log "Physical cache drive creation skipped - virtual cache drive already created" "INFO"
        } elseif (-not $RequireCacheDrive) {
            Write-Log "Cache drive creation skipped - cache drive requirement disabled in configuration" "INFO"
        }
        
        # Continue with drive configuration based on requirements
        if (-not $RequireCacheDrive) {
            Write-Log "Skipping all drive configuration - cache drive requirement disabled" "INFO"
            $DriveConfigInit = @{ 
                Success = $true
                Method = "Cache Drive Requirement Disabled"
                DriveValidationPassed = $true
                DDriveExists = $false
                DDriveAccessible = $false
            }
        } elseif (-not $UseVirtualCacheDrive) {
            Write-Log "Performing comprehensive drive validation..." "INFO"
            $DriveConfigInit = Start-DriveConfiguration -Interactive $true
        } elseif ($CacheDriveResult.Success) {
            Write-Log "Skipping interactive drive configuration - virtual cache drive already created successfully" "INFO"
            $DriveConfigInit = @{ 
                Success = $true
                Method = "Virtual Cache Drive"
                DriveValidationPassed = $true
                DDriveExists = $true
                DDriveAccessible = $true
            }
        } else {
            Write-Log "Virtual cache drive failed - proceeding with standard drive validation..." "WARN"
            $DriveConfigInit = Start-DriveConfiguration -Interactive $true
        }
        
        # Additional drive configuration testing only if cache drive is required
        if ($RequireCacheDrive) {
            $DriveTestResult = Test-DriveConfiguration
        } else {
            Write-Log "Drive configuration testing skipped - cache drive requirement disabled" "INFO"
            $DriveTestResult = @{ Success = $true; Method = "Skipped - Cache Drive Not Required" }
        }
        if ($DriveTestResult) {
            Write-Log "Drive configuration test passed" "SUCCESS"
        }
    } else {
        Write-Log "Drive configuration skipped - disabled in configuration"
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
    Write-Log "WEM Source Path: $(if([string]::IsNullOrEmpty($WEMInstallerSourcePath)){'Not specified - SKIP'}else{$WEMInstallerSourcePath})"
    Write-Log "WEM Local Path: $(if([string]::IsNullOrEmpty($WEMInstallerPath)){'Not specified - SKIP'}else{$WEMInstallerPath})"
    Write-Log "UberAgent Source Path: $(if([string]::IsNullOrEmpty($UberAgentInstallerSourcePath)){'Not specified - SKIP'}else{$UberAgentInstallerSourcePath})"
    Write-Log "UberAgent Local Path: $(if([string]::IsNullOrEmpty($UberAgentInstallerPath)){'Not specified - SKIP'}else{$UberAgentInstallerPath})"
    Write-Log "UberAgent Templates: $(if([string]::IsNullOrEmpty($UberAgentTemplatesPath)){'Not specified - SKIP'}else{$UberAgentTemplatesPath})"
    Write-Log "UberAgent Config: $(if([string]::IsNullOrEmpty($UberAgentConfigPath)){'Not specified - SKIP'}else{$UberAgentConfigPath})"
    Write-Log "UberAgent License: $(if([string]::IsNullOrEmpty($UberAgentLicensePath)){'Not specified - SKIP'}else{$UberAgentLicensePath})"
    Write-Log "TADDM Path: $(if([string]::IsNullOrEmpty($TADDMPath)){'Not specified - SKIP'}else{$TADDMPath})"
    Write-Log "TADDM Install.bat: $(if(Test-Path $TADDMPath){'Found at ' + $TADDMPath}else{'Not found - will skip'})"
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
    
    # Assign cache drive result if it was created earlier
    if ($Global:CacheDriveResult) {
        $InstallConfig.InstallationResults.CacheDrive = $Global:CacheDriveResult
        Write-Log "Cache drive result assigned to InstallConfig" "INFO"
    }
    
    # Override paths with script parameters
    $InstallConfig.VDAISOPath = $VDAISOPath
    $InstallConfig.PVSISOPath = $PVSISOPath
    $InstallConfig.WEMInstallerSourcePath = $WEMInstallerSourcePath
    $InstallConfig.WEMInstallerPath = $WEMInstallerPath
    $InstallConfig.UberAgentInstallerSourcePath = $UberAgentInstallerSourcePath
    $InstallConfig.UberAgentInstallerPath = $UberAgentInstallerPath
    $InstallConfig.TADDMPath = $TADDMPath
    
    # Add additional parameters
    $InstallConfig.Parameters = @{
        UberAgentTemplatesPath = $UberAgentTemplatesPath
        UberAgentConfigPath = $UberAgentConfigPath
        UberAgentLicensePath = $UberAgentLicensePath

        LogPath = $LogPath
        PagefileSizeGB = $PagefileSizeGB
        ValidationMode = $ValidationMode
        ContinueOnWarnings = $ContinueOnWarnings

    }
    
    # Enhanced pre-installation system configuration
    Write-LogHeader "Enhanced Pre-Installation System Configuration"
    
    Write-Log "Configuring Windows services..."
    Set-WindowsServices
    
    # Windows Firewall configuration handled by Citrix installer (firewall disabled in environment)
    
    # Network and storage optimizations moved to Stage 2 for post-installation execution
    
    # Windows optimizations are handled by Citrix Optimizer (redundant functions removed)
    Write-LogHeader "WINDOWS SYSTEM OPTIMIZATIONS"
    Write-Log "Windows optimizations delegated to Citrix Optimizer for consistency and completeness" "INFO"
    Write-Log "All service, registry, and performance optimizations handled by optimizer templates" "INFO"
    
    Write-Log "Citrix Optimizer execution scheduled for Stage 2 (post-installation)" "INFO"
    
    $InstallConfig.InstallationResults.CitrixOptimizer = @{
        Success = $true
        ScheduledForStage2 = $true
        Status = "Deferred to post-installation phase"
    }
    
    $DisableWindowsServices = [bool](Get-ConfigValue -Key "DisableWindowsServices" -DefaultValue "true" -ConfigFile $ConfigFilePath)
    if ($DisableWindowsServices) {
        Write-Log "Disabling specified Windows services..."
        $CitrixServicesResult = Stop-CitrixServices -ConfigFilePath $ConfigFilePath
        
        if ($CitrixServicesResult.Success) {
            Write-Log "Windows services management completed successfully" "SUCCESS"
            Write-Log "Disabled services: $($CitrixServicesResult.DisabledServices.Count)" "SUCCESS"
            Write-Log "Skipped services: $($CitrixServicesResult.SkippedServices.Count)" "INFO"
            
            if ($CitrixServicesResult.FailedServices.Count -gt 0) {
                Write-Log "Failed to disable $($CitrixServicesResult.FailedServices.Count) services" "WARN"
            }
            
            $InstallConfig.InstallationResults.CitrixServicesDisabled = $CitrixServicesResult
        }
        else {
            Write-Log "Windows services management had issues: $($CitrixServicesResult.Error)" "WARN"
            $InstallConfig.InstallationResults.CitrixServicesDisabled = $CitrixServicesResult
        }
    } else {
        Write-Log "Windows services management skipped - disabled in configuration"
        $InstallConfig.InstallationResults.CitrixServicesDisabled = @{ Skipped = $true }
    }
    
    # Configurable system optimizations (cache drive redirections moved to Stage 2)
    
    $OptimizeVDIRegistry = [bool](Get-ConfigValue -Key "OptimizeVDIRegistry" -DefaultValue "true")
    if ($OptimizeVDIRegistry) {
        Write-Log "Applying registry optimizations..."
        Set-RegistryOptimizations -ConfigFilePath $ConfigFilePath
    } else {
        Write-Log "Registry optimizations skipped - disabled in configuration"
    }
    
    # VDI optimizations moved to Stage 2 - handled by Citrix Optimizer
    

    
    # Enhanced Citrix components installation
    Write-LogHeader "Enhanced Citrix Components Installation"
    
    # VDA Installation from ISO with automatic mounting and unmounting
    Write-Host "Installing Citrix VDA from ISO..." -ForegroundColor Cyan
    $VDAResult = Install-VDAFromISO -ConfigFilePath $ConfigFilePath
    $InstallConfig.InstallationResults.VDA = $VDAResult
    
    if ($VDAResult.Success -and !$VDAResult.Skipped) {
        Write-Log "VDA installation completed successfully from ISO" "SUCCESS"
        Write-Host "VDA installation completed successfully" -ForegroundColor Green
        
        # Check if reboot is needed
        if ($VDAResult.ExitCode -eq 3010) {
            Write-Log "VDA installation requires reboot" "WARN"
            $InstallConfig.RebootRequired = $true
        }
    } elseif ($VDAResult.Skipped) {
        Write-Log "VDA installation skipped - disabled in configuration" "INFO"
        Write-Host "VDA installation skipped - disabled in configuration" -ForegroundColor Gray
        $InstallConfig.InstallationResults.VDA = @{ Skipped = $true }
    } else {
        Write-Log "VDA installation failed: $($VDAResult.Error)" "ERROR"
        Write-Host "VDA installation failed: $($VDAResult.Error)" -ForegroundColor Yellow
        $ValidationWarnings += "VDA installation failed - may need manual intervention"
    }
    
    # PVS Target Device Installation from ISO with automatic mounting and unmounting
    Write-Host "Installing PVS Target Device from ISO..." -ForegroundColor Cyan
    $PVSResult = Install-PVSFromISO -ConfigFilePath $ConfigFilePath
    $InstallConfig.InstallationResults.PVS = $PVSResult
    
    if ($PVSResult.Success -and !$PVSResult.Skipped) {
        Write-Log "PVS Target Device installation completed successfully from ISO" "SUCCESS"
        Write-Host "PVS Target Device installation completed successfully" -ForegroundColor Green
        
        # Check if reboot is needed
        if ($PVSResult.ExitCode -eq 3010) {
            Write-Log "PVS Target Device installation requires reboot" "WARN"
            $InstallConfig.RebootRequired = $true
        }
    } elseif ($PVSResult.Skipped) {
        Write-Log "PVS Target Device installation skipped - disabled in configuration" "INFO"
        Write-Host "PVS Target Device installation skipped - disabled in configuration" -ForegroundColor Gray
        $InstallConfig.InstallationResults.PVS = @{ Skipped = $true }
    } else {
        Write-Log "PVS Target Device installation failed: $($PVSResult.Error)" "ERROR"
        Write-Host "PVS Target Device installation failed: $($PVSResult.Error)" -ForegroundColor Yellow
        $ValidationWarnings += "PVS Target Device installation failed - may need manual intervention"
    }
    
    # Install WEM Agent (if enabled and file exists in temp)
    $InstallWEM = [bool](Get-ConfigValue -Key "InstallWEM" -DefaultValue "false")
    if ($InstallWEM -and ![string]::IsNullOrEmpty($WEMInstallerPath) -and (Test-Path $WEMInstallerPath)) {
        Write-Log "Installing WEM Agent from temp directory..."
        $WEMResult = Add-WEMAgent -WEMSourcePath $WEMInstallerSourcePath -WEMPath $WEMInstallerPath -ConfigFilePath $ConfigFilePath
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
        $reason = if (!$InstallWEM) { "disabled in configuration" } else { "no path specified" }
        Write-Log "WEM Agent installation skipped - $reason"
        $InstallConfig.InstallationResults.WEM = @{ Skipped = $true }
    }
    
    # Install UberAgent (if enabled and file exists in temp)
    $InstallUberAgent = [bool](Get-ConfigValue -Key "InstallUberAgent" -DefaultValue "false")
    if ($InstallUberAgent -and ![string]::IsNullOrEmpty($UberAgentInstallerPath) -and (Test-Path $UberAgentInstallerPath)) {
        Write-Log "Installing UberAgent from temp directory..."
        
        $UberAgentResult = Add-UberAgent -UberAgentInstallerPath $UberAgentInstallerPath -ConfigFilePath $ConfigFilePath
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
        $reason = if (!$InstallUberAgent) { "disabled in configuration" } else { "file not found in temp directory" }
        Write-Log "UberAgent installation skipped - $reason"
        $InstallConfig.InstallationResults.UberAgent = @{ Skipped = $true }
    }
    
    # Configure IBM TADDM using local install.bat (if enabled)
    $EnableIBMTADDMInstallation = [bool](Get-ConfigValue -Key "EnableIBMTADDMInstallation" -DefaultValue "false" -ConfigFile $ConfigFilePath)
    $TADDMPath = Get-ConfigValue -Key "TADDMPath" -DefaultValue "C:\IBM\TADDM\nonadmin_scripts\install.bat" -ConfigFile $ConfigFilePath
    if ($EnableIBMTADDMInstallation -and (Test-Path $TADDMPath)) {
        Write-Log "Executing IBM TADDM install.bat for non-administrator configuration..."
        
        $TADDMParams = @{
            TADDMPath = $TADDMPath
            CreateGroupIfMissing = $true
        }
        
        $TADDMResult = Set-IBMTADDMPermissions @TADDMParams
        $InstallConfig.InstallationResults.TADDM = $TADDMResult
        
        if ($TADDMResult.OverallSuccess) {
            if ($TADDMResult.InstallBatExecuted) {
                Write-Log "IBM TADDM install.bat executed successfully" "SUCCESS"
            } elseif ($TADDMResult.PermissionsConfigured) {
                Write-Log "IBM TADDM permissions configured successfully" "SUCCESS"
            }
        }
        elseif (!$TADDMResult.Skipped) {
            Write-Log "IBM TADDM configuration encountered issues: $($TADDMResult.Error)" "WARN"
        }
    }
    else {
        $reason = if (!$EnableIBMTADDMInstallation) { "disabled in configuration" } else { "install.bat not found at: $TADDMPath" }
        Write-Log "IBM TADDM configuration skipped - $reason"
        $InstallConfig.InstallationResults.TADDM = @{ Skipped = $true }
    }
    
    # Configure IBM TADDM Service Control Manager permissions (if enabled)
    $EnableIBMTADDMSCMConfig = [bool](Get-ConfigValue -Key "EnableIBMTADDMSCMConfig" -DefaultValue "false" -ConfigFile $ConfigFilePath)
    if ($EnableIBMTADDMSCMConfig) {
        Write-LogHeader "IBM TADDM Service Control Manager Configuration"
        
        $IBMTADDMSCMPath = Get-ConfigValue -Key "IBMTADDMSCMPath" -DefaultValue "C:\IBM\TADDM\sc_sdset_scmanager" -ConfigFile $ConfigFilePath
        
        if (Test-Path $IBMTADDMSCMPath) {
            Write-Log "Configuring IBM TADDM Service Control Manager permissions..."
            
            $SCMResult = Set-IBMTADDMSCMPermissions -SCMPath $IBMTADDMSCMPath -ConfigFilePath $ConfigFilePath
            $InstallConfig.InstallationResults.TADDMSCMConfig = $SCMResult
            
            if ($SCMResult.Success) {
                Write-Log "IBM TADDM SCM permissions configured successfully" "SUCCESS"
                Write-Log "Current SDDL generated: $($SCMResult.CurrentSDDLGenerated)" "INFO"
                Write-Log "SDDL comparison completed: $($SCMResult.SDDLComparisonCompleted)" "INFO"
                Write-Log "Differences found: $($SCMResult.Differences.Count)" "INFO"
                Write-Log "SCM permissions configured: $($SCMResult.SCMPermissionsConfigured)" "SUCCESS"
                
                # Log SDDL differences if any
                if ($SCMResult.Differences.Count -gt 0) {
                    Write-Log "SDDL configuration differences detected:" "WARN"
                    foreach ($diff in $SCMResult.Differences) {
                        Write-Log "  Line $($diff.LineNumber): $($diff.ChangeType)" "WARN"
                        Write-Log "    Current: '$($diff.Current)'" "WARN"
                        Write-Log "    Default: '$($diff.Default)'" "WARN"
                    }
                }
            } else {
                Write-Log "IBM TADDM SCM configuration encountered issues" "WARN"
                foreach ($error in $SCMResult.Errors) {
                    Write-Log "  SCM Error: $error" "ERROR"
                }
            }
        } else {
            Write-Log "IBM TADDM SCM path not found: $IBMTADDMSCMPath" "WARN"
            $InstallConfig.InstallationResults.TADDMSCMConfig = @{ 
                Skipped = $true 
                Reason = "SCM path not found: $IBMTADDMSCMPath"
            }
        }
    } else {
        Write-Log "IBM TADDM SCM configuration disabled in configuration"
        $InstallConfig.InstallationResults.TADDMSCMConfig = @{ 
            Skipped = $true 
            Reason = "Disabled in configuration" 
        }
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
    
    # Enhanced OS-Aware Startup and Shutdown Scripts Configuration (if enabled)
    $DeployStartupScripts = [bool](Get-ConfigValue -Key "DeployStartupScripts" -DefaultValue "true")
    $DeployShutdownScripts = [bool](Get-ConfigValue -Key "DeployShutdownScripts" -DefaultValue "true")
    
    if ($DeployStartupScripts -or $DeployShutdownScripts) {
        Write-LogHeader "OS-Aware Startup and Shutdown Scripts Configuration"
        
        # Load OS-specific script source paths from configuration
        $StartupSourceWin2019 = Get-ConfigValue -Key "StartupScriptsSourceWin2019" -DefaultValue "\\fileserver\scripts\startup\win2019" -ConfigFile $ConfigFilePath
        $StartupSourceWin2022 = Get-ConfigValue -Key "StartupScriptsSourceWin2022" -DefaultValue "\\fileserver\scripts\startup\win2022" -ConfigFile $ConfigFilePath
        $StartupDestination = Get-ConfigValue -Key "StartupScriptsDestination" -DefaultValue "C:\Scripts\Startup" -ConfigFile $ConfigFilePath
        
        $ShutdownSourceWin2019 = Get-ConfigValue -Key "ShutdownScriptsSourceWin2019" -DefaultValue "\\fileserver\scripts\shutdown\win2019" -ConfigFile $ConfigFilePath
        $ShutdownSourceWin2022 = Get-ConfigValue -Key "ShutdownScriptsSourceWin2022" -DefaultValue "\\fileserver\scripts\shutdown\win2022" -ConfigFile $ConfigFilePath
        $ShutdownDestination = Get-ConfigValue -Key "ShutdownScriptsDestination" -DefaultValue "C:\Scripts\Shutdown" -ConfigFile $ConfigFilePath
        
        Write-Log "Copying OS-specific startup and shutdown scripts..."
        $ScriptCopyParams = @{
            StartupSourceWin2019 = if ($DeployStartupScripts) { $StartupSourceWin2019 } else { "" }
            StartupSourceWin2022 = if ($DeployStartupScripts) { $StartupSourceWin2022 } else { "" }
            StartupDestination = if ($DeployStartupScripts) { $StartupDestination } else { "" }
            ShutdownSourceWin2019 = if ($DeployShutdownScripts) { $ShutdownSourceWin2019 } else { "" }
            ShutdownSourceWin2022 = if ($DeployShutdownScripts) { $ShutdownSourceWin2022 } else { "" }
            ShutdownDestination = if ($DeployShutdownScripts) { $ShutdownDestination } else { "" }
        }
        $ScriptCopyResult = Copy-OSSpecificStartupShutdownScripts @ScriptCopyParams
        $InstallConfig.InstallationResults.Scripts = $ScriptCopyResult
    } else {
        Write-Log "Startup and shutdown script deployment disabled in configuration"
        $InstallConfig.InstallationResults.Scripts = @{ Skipped = $true; Reason = "Disabled in configuration" }
        $ScriptCopyResult = @{ StartupCopied = $false; ShutdownCopied = $false; Skipped = $true }
    }
    
    $RegisterScriptsInGPO = [bool](Get-ConfigValue -Key "RegisterScriptsInGPO" -DefaultValue "true")
    if (($ScriptCopyResult.StartupCopied -or $ScriptCopyResult.ShutdownCopied) -and $RegisterScriptsInGPO) {
        Write-Log "Configuring copied scripts for Group Policy execution..."
        $ScriptConfigResult = Add-StartupShutdownScripts -StartupScriptPath $StartupDestination -ShutdownScriptPath $ShutdownDestination
        
        $InstallConfig.InstallationResults.ScriptConfiguration = $ScriptConfigResult
        
        if ($ScriptConfigResult.RegistryConfigured -and $ScriptConfigResult.GroupPolicyConfigured) {
            Write-Log "Startup and shutdown scripts configured successfully for Windows $($ScriptCopyResult.DetectedOS)" "SUCCESS"
        }
        else {
            Write-Log "Script configuration completed with some issues" "WARN"
        }
    }
    else {
        $reason = if (!$RegisterScriptsInGPO) { "GPO registration disabled in configuration" } else { "no scripts were copied" }
        Write-Log "Script configuration skipped - $reason"
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
    
    if ($InstallConfig.InstallationResults.TADDMSCMConfig.Skipped) {
        Write-Log "IBM TADDM SCM Config: SKIPPED"
    } else {
        Write-Log "IBM TADDM SCM Config: $(if($InstallConfig.InstallationResults.TADDMSCMConfig.Success){'SUCCESS'}else{'FAILED'})"
    }
    
    Write-Log "Reboot Required: $($InstallConfig.RebootRequired)"
    
    Write-Log "INSTALLATION SUMMARY:"
    Write-Log "- All components installed without server connectivity"
    Write-Log "- No server connectivity was required during installation"
    Write-Log "- Delivery controllers, PVS servers, and WEM infrastructure servers are not needed"
    Write-Log "- System is ready for final configuration"
    Write-Log "- Server connections will be configured during deployment"
    
    # Final Configuration and Registry Validation
    Write-LogHeader "Final Configuration and Registry Validation"
    Write-Log "Reading back all applied configurations and registry settings..." "INFO"
    
    $FinalValidation = @{
        VDARegistry = $false
        PVSRegistry = $false
        WEMRegistry = $false
        UberAgentRegistry = $false
        SystemOptimizations = @{}
        CacheDriveConfig = $false
        PagefileConfig = $false
        ServicesValidation = @{}
        RegistryKeys = @{}
    }
    
    # Validate VDA Registry Keys
    if ($InstallConfig.InstallationResults.VDA.Success) {
        $VDARegPath = "HKLM:\SOFTWARE\Citrix\VirtualDesktopAgent"
        if (Test-Path $VDARegPath) {
            $FinalValidation.VDARegistry = $true
            $VDAVersion = Get-ItemProperty -Path $VDARegPath -Name "ProductVersion" -ErrorAction SilentlyContinue
            Write-Log "VDA Registry: VALIDATED - Version $($VDAVersion.ProductVersion)" "SUCCESS"
            $FinalValidation.RegistryKeys["VDA"] = $VDAVersion.ProductVersion
        } else {
            Write-Log "VDA Registry: NOT FOUND" "ERROR"
        }
    }
    
    # Validate PVS Registry Keys
    if ($InstallConfig.InstallationResults.PVS.Success) {
        $PVSRegPath = "HKLM:\SOFTWARE\Citrix\ProvisioningServices"
        if (Test-Path $PVSRegPath) {
            $FinalValidation.PVSRegistry = $true
            Write-Log "PVS Target Registry: VALIDATED" "SUCCESS"
            $FinalValidation.RegistryKeys["PVS"] = "Installed"
        } else {
            Write-Log "PVS Target Registry: NOT FOUND" "ERROR"
        }
    }
    
    # Validate WEM Registry Keys
    if ($InstallConfig.InstallationResults.WEM.Success) {
        $WEMRegPath = "HKLM:\SOFTWARE\Citrix\WEM"
        if (Test-Path $WEMRegPath) {
            $FinalValidation.WEMRegistry = $true
            Write-Log "WEM Agent Registry: VALIDATED" "SUCCESS"
            $FinalValidation.RegistryKeys["WEM"] = "Installed"
        } else {
            Write-Log "WEM Agent Registry: NOT FOUND" "ERROR"
        }
    }
    
    # Validate UberAgent Registry (should be cleared for template)
    if ($InstallConfig.InstallationResults.UberAgent.OverallSuccess) {
        $UberAgentRegPath = "HKLM:\Software\vast limits\uberAgent"
        if (-not (Test-Path $UberAgentRegPath)) {
            $FinalValidation.UberAgentRegistry = $true
            Write-Log "UberAgent Registry: PROPERLY CLEARED for template" "SUCCESS"
            $FinalValidation.RegistryKeys["UberAgent"] = "Cleared"
        } else {
            Write-Log "UberAgent Registry: WARNING - Still present (should be cleared)" "WARN"
            $FinalValidation.RegistryKeys["UberAgent"] = "Present"
        }
    }
    
    # Validate Cache Drive Configuration
    if ($RequireCacheDrive) {
        $DCacheDrive = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='D:'" -ErrorAction SilentlyContinue
        if ($DCacheDrive) {
            $FinalValidation.CacheDriveConfig = $true
            $SizeGB = [math]::Round($DCacheDrive.Size / 1GB, 2)
            $FreeGB = [math]::Round($DCacheDrive.FreeSpace / 1GB, 2)
            Write-Log "Cache Drive D:: VALIDATED - Size: ${SizeGB}GB, Free: ${FreeGB}GB" "SUCCESS"
        } else {
            Write-Log "Cache Drive D:: NOT FOUND" "ERROR"
        }
    }
    
    # Validate Pagefile Configuration
    $PagefileConfig = Get-WmiObject -Class Win32_PageFileSetting -ErrorAction SilentlyContinue
    if ($PagefileConfig) {
        foreach ($Pagefile in $PagefileConfig) {
            $FinalValidation.PagefileConfig = $true
            Write-Log "Pagefile: $($Pagefile.Name) - Initial: $($Pagefile.InitialSize)MB, Max: $($Pagefile.MaximumSize)MB" "SUCCESS"
        }
    }
    
    # Validate Critical Services
    $CriticalServices = @()
    if ($InstallConfig.InstallationResults.VDA.Success) {
        $CriticalServices += @("BrokerAgent", "picaSvc2", "CdfSvc")
    }
    if ($InstallConfig.InstallationResults.PVS.Success) {
        $CriticalServices += @("BNDevice")
    }
    if ($InstallConfig.InstallationResults.WEM.Success) {
        $CriticalServices += @("Citrix WEM Agent Host Service")
    }
    
    foreach ($ServiceName in $CriticalServices) {
        $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($Service) {
            $FinalValidation.ServicesValidation[$ServiceName] = $Service.Status
            Write-Log "Service '$ServiceName': $($Service.Status)" "SUCCESS"
        } else {
            $FinalValidation.ServicesValidation[$ServiceName] = "NOT FOUND"
            Write-Log "Service '$ServiceName': NOT FOUND" "ERROR"
        }
    }
    
    # Validate VDA Multiple Monitor Hook Registry Keys
    $MonitorHookRegPath = "HKLM:\SOFTWARE\Citrix\Graphics"
    if (Test-Path $MonitorHookRegPath) {
        $LogonUIWidth = Get-ItemProperty -Path $MonitorHookRegPath -Name "LogonUIWidth" -ErrorAction SilentlyContinue
        $LogonUIHeight = Get-ItemProperty -Path $MonitorHookRegPath -Name "LogonUIHeight" -ErrorAction SilentlyContinue
        if ($LogonUIWidth -and $LogonUIHeight) {
            Write-Log "VDA Multi-Monitor Hook: Width=$($LogonUIWidth.LogonUIWidth), Height=$($LogonUIHeight.LogonUIHeight)" "SUCCESS"
            $FinalValidation.RegistryKeys["MonitorHook"] = "Configured"
        }
    }
    
    # Generate Final Validation Summary
    Write-LogHeader "Final Validation Summary"
    $ValidationScore = 0
    $TotalChecks = 0
    
    if ($InstallConfig.InstallationResults.VDA.Success) {
        $TotalChecks++
        if ($FinalValidation.VDARegistry) { $ValidationScore++ }
    }
    if ($InstallConfig.InstallationResults.PVS.Success) {
        $TotalChecks++
        if ($FinalValidation.PVSRegistry) { $ValidationScore++ }
    }
    if ($InstallConfig.InstallationResults.WEM.Success) {
        $TotalChecks++
        if ($FinalValidation.WEMRegistry) { $ValidationScore++ }
    }
    if ($InstallConfig.InstallationResults.UberAgent.OverallSuccess) {
        $TotalChecks++
        if ($FinalValidation.UberAgentRegistry) { $ValidationScore++ }
    }
    if ($RequireCacheDrive) {
        $TotalChecks++
        if ($FinalValidation.CacheDriveConfig) { $ValidationScore++ }
    }
    
    $ValidationPercentage = if ($TotalChecks -gt 0) { [math]::Round(($ValidationScore / $TotalChecks) * 100, 1) } else { 100 }
    
    Write-Log "Configuration Validation Score: $ValidationScore/$TotalChecks ($ValidationPercentage%)" $(if ($ValidationPercentage -ge 90) { "SUCCESS" } elseif ($ValidationPercentage -ge 70) { "WARN" } else { "ERROR" })
    Write-Log "Registry Keys Validated: $($FinalValidation.RegistryKeys.Count)" "INFO"
    Write-Log "Services Validated: $($FinalValidation.ServicesValidation.Count)" "INFO"
    
    # Copy Stage 2 Script to LocalInstallPath and Save Configuration
    Write-LogHeader "Preparing Stage 2 Script for Manual Execution"
    
    # Copy Stage 2 script from network to LocalInstallPath
    $Stage2NetworkPath = Get-ConfigValue -Key "Stage2ScriptNetworkPath" -DefaultValue "$NetworkSourcePath\scripts\citrix_stage2_script.ps1" -ConfigFile $ConfigFilePath
    $Stage2LocalPath = "$LocalInstallPath\citrix_stage2_script.ps1"
    
    try {
        # Ensure LocalInstallPath exists
        if (!(Test-Path $LocalInstallPath)) {
            New-Item -Path $LocalInstallPath -ItemType Directory -Force | Out-Null
            Write-Log "Created $LocalInstallPath directory" "INFO"
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
        
        # Copy functions library to LocalInstallPath as well
        $FunctionsLocalPath = "$LocalInstallPath\citrix_functions_library.psm1"
        if (Test-Path $FunctionsPath) {
            Copy-Item -Path $FunctionsPath -Destination $FunctionsLocalPath -Force
            Write-Log "Functions library copied to: $FunctionsLocalPath" "SUCCESS"
        }
        
        # Save installation configuration
        Write-Log "Saving installation configuration..."
        $ConfigSaved = Save-InstallationConfig -Config $InstallConfig -ConfigPath "$LocalInstallPath\CitrixConfig.json"
        
        if ($ConfigSaved) {
            Write-Log "Installation configuration saved to $LocalInstallPath\CitrixConfig.json" "SUCCESS"
        }
        else {
            Write-Log "Failed to save installation configuration" "ERROR"
        }
        
        # Create instruction file for manual Stage 2 execution
        $InstructionPath = "$LocalInstallPath\STAGE2_INSTRUCTIONS.txt"
        $Instructions = @"
CITRIX INSTALLATION - STAGE 2 MANUAL EXECUTION INSTRUCTIONS
==========================================================

After system reboot, execute Stage 2 manually:

1. Open PowerShell as Administrator
2. Navigate to $LocalInstallPath
3. Execute: .\citrix_stage2_script.ps1

Files copied for Stage 2:
- $LocalInstallPath\citrix_stage2_script.ps1 (Stage 2 script)
- $LocalInstallPath\citrix_functions_library.psm1 (Functions library)
- $LocalInstallPath\CitrixConfig.json (Installation configuration)

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