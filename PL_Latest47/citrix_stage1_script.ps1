# =============================================================================
# CITRIX AUTOMATION TOOLKIT - STAGE 1: VDA INSTALLATION SCRIPT
# =============================================================================

param(
    [switch]$ValidationMode
)

Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host "CITRIX AUTOMATION TOOLKIT - STAGE 1" -ForegroundColor White
Write-Host "VDA Installation and Configuration" -ForegroundColor White
Write-Host "=====================================================" -ForegroundColor Cyan

# Initialize configuration file path first
$ConfigFilePath = Join-Path $PSScriptRoot "CitrixConfig.txt"

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
    
    # Ensure all function calls use absolute config path
    $Global:DefaultConfigPath = $ConfigFilePath
    
    # Load configuration from CitrixConfig.txt with fallback
    try {
        if (Test-Path $ConfigFilePath) {
            $Config = Read-ConfigFile -ConfigFilePath $ConfigFilePath
        } else {
            Write-Host "Configuration file not found at: $ConfigFilePath" -ForegroundColor Yellow
            Write-Host "Using default configuration values" -ForegroundColor Yellow
            $Config = $null
        }
    } catch {
        Write-Host "Configuration loading failed: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "Using default values" -ForegroundColor Yellow
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
            return "C:\Users\Public\Desktop\CitrixInstall.log"
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
    $VDAISOPath = $VDAISOPath.Trim().Replace('\\\\', '\\')
    $PVSISOPath = $PVSISOPath.Trim().Replace('\\\\', '\\')
    
    # WEM Agent configuration
    $WEMInstallerSourcePath = Get-ConfigValue -Key "WEMInstallerSourcePath" -DefaultValue "" -ConfigFile $ConfigFilePath
    $WEMInstallerPath = Get-ConfigValue -Key "WEMInstallerPath" -DefaultValue "$LocalInstallPath\WEMAgent.msi" -ConfigFile $ConfigFilePath
    
    # UberAgent configuration
    $UberAgentInstallerSourcePath = Get-ConfigValue -Key "UberAgentInstallerSourcePath" -DefaultValue "" -ConfigFile $ConfigFilePath
    $UberAgentInstallerPath = Get-ConfigValue -Key "UberAgentInstallerPath" -DefaultValue "$LocalInstallPath\UberAgent.msi" -ConfigFile $ConfigFilePath
    $UberAgentTemplatesPath = Get-ConfigValue -Key "UberAgentTemplatesPath" -DefaultValue "$NetworkSourcePath\UberAgent\Templates" -ConfigFile $ConfigFilePath
    $UberAgentConfigPath = Get-ConfigValue -Key "UberAgentConfigPath" -DefaultValue "$NetworkSourcePath\UberAgent\Config" -ConfigFile $ConfigFilePath
    $UberAgentLicensePath = Get-ConfigValue -Key "UberAgentLicensePath" -DefaultValue "$NetworkSourcePath\UberAgent\License" -ConfigFile $ConfigFilePath
    $TADDMPath = Get-ConfigValue -Key "TADDMPath" -DefaultValue "$NetworkSourcePath\TADDM" -ConfigFile $ConfigFilePath
    $PagefileSizeGB = [int](Get-ConfigValue -Key "PagefileSizeGB" -DefaultValue 8 -ConfigFile $ConfigFilePath)
    
    # Test log file creation
    try {
        $LogPath = Get-DesktopLogPath
        $TestMessage = "Configuration loaded successfully at $(Get-Date)"
        $TestMessage | Out-File -FilePath $LogPath -Append -ErrorAction Stop
        Write-Host "Log file test successful: $LogPath" -ForegroundColor Green
    } catch {
        Write-Host "ERROR: Log creation test failed - $($_.Exception.Message)" -ForegroundColor Red
    }
    Write-Host "Pagefile Size: $PagefileSizeGB GB" -ForegroundColor White
    Write-Host "=================================" -ForegroundColor Cyan
    
} catch {
    Write-Host "Failed to load configuration: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Using default values..." -ForegroundColor Yellow
    
    # Default NetworkSourcePath for fallback values
    $NetworkSourcePath = "\\fileserver\citrix"
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

Write-Host ""
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host "CD/DVD DRIVE RELOCATION CHECK" -ForegroundColor White
Write-Host "=====================================================" -ForegroundColor Cyan

# Get configuration settings for CD/DVD relocation
$RelocateCDDVDDrive = [bool](Get-ConfigValue -Key "RelocateCDDVDDrive" -DefaultValue "true" -ConfigFile $ConfigFilePath)
$CDDVMTargetDrive = Get-ConfigValue -Key "CDDVMTargetDrive" -DefaultValue "Y" -ConfigFile $ConfigFilePath

if ($RelocateCDDVDDrive) {
    Write-Host "CD/DVD drive relocation enabled - target drive: ${CDDVMTargetDrive}:" -ForegroundColor White
    Write-Host "Checking if D: drive is a CD/DVD ROM..." -ForegroundColor White
    
    # Initialize CD/DVD detection flag
    $IsCDDVD = $false
    
    # Method 1: Check drive type using WMI
    try {
        $DDrive = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='D:'" -ErrorAction SilentlyContinue
        if ($DDrive -and $DDrive.DriveType -eq 5) {
            $IsCDDVD = $true
            Write-Host "D: drive detected as CD/DVD ROM via WMI" -ForegroundColor Green
        }
    } catch {
        Write-Host "WMI CD/DVD check failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    # Method 2: Check MediaType using Get-Volume (Windows 8+)
    if (-not $IsCDDVD) {
        try {
            $DVolumeInfo = Get-Volume -DriveLetter D -ErrorAction SilentlyContinue
            if ($DVolumeInfo -and $DVolumeInfo.DriveType -eq "CD-ROM") {
                $IsCDDVD = $true
                Write-Host "D: drive detected as CD/DVD ROM via Get-Volume" -ForegroundColor Green
            }
        } catch {
            Write-Host "Get-Volume CD/DVD check failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    
    # Method 3: Check filesystem type
    if (-not $IsCDDVD -and (Test-Path "D:\")) {
        try {
            $VolumeInfo = Get-WmiObject -Class Win32_Volume -Filter "DriveLetter='D:'" -ErrorAction SilentlyContinue
            if ($VolumeInfo -and ($VolumeInfo.FileSystem -eq "CDFS" -or $VolumeInfo.FileSystem -eq "UDF")) {
                $IsCDDVD = $true
                Write-Host "D: drive detected as CD/DVD ROM via filesystem ($($VolumeInfo.FileSystem))" -ForegroundColor Green
            } else {
                Write-Host "D: drive filesystem: $($VolumeInfo.FileSystem)" -ForegroundColor White
            }
        } catch {
            Write-Host "Volume filesystem check failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
    # Method 4: Read-only test (if D: exists)
    if (-not $IsCDDVD -and (Test-Path "D:\")) {
        try {
            $TestFile = "D:\write_test_$((Get-Date).Ticks).tmp"
            "test" | Out-File -FilePath $TestFile -ErrorAction Stop
            Remove-Item $TestFile -Force -ErrorAction SilentlyContinue
            Write-Host "D: drive is writable - not CD/DVD" -ForegroundColor White
        } catch {
            $IsCDDVD = $true
            Write-Host "D: drive is read-only - detected as CD/DVD" -ForegroundColor Green
        }
    }
    
    # Method 5: Registry-based detection
    if (-not $IsCDDVD) {
        try {
            $CDROMKeys = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\cdrom\Enum" -ErrorAction SilentlyContinue
            if ($CDROMKeys) {
                foreach ($Key in $CDROMKeys) {
                    $DeviceDesc = Get-ItemProperty -Path $Key.PSPath -Name "DeviceDesc" -ErrorAction SilentlyContinue
                    if ($DeviceDesc -and $DeviceDesc.DeviceDesc -match "CD|DVD") {
                        $IsCDDVD = $true
                        Write-Host "Assuming D: is CD/DVD based on registry detection" -ForegroundColor Green
                    }
                }
            }
        } catch {
            Write-Host "Registry CD/DVD detection failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    # All CD/DVD detection methods completed

    # Now proceed with CD/DVD relocation if detected
    if ($IsCDDVD) {
        Write-Host "D: drive is CD/DVD ROM - relocating to ${CDDVMTargetDrive}:..." -ForegroundColor Yellow
        
        # Check if target drive is available
        if (-not (Test-Path "${CDDVMTargetDrive}:\")) {
            try {
                # Use diskpart to change CD/DVD drive letter
                $DiskpartScript = @"
list volume
select volume=D:
assign letter=$CDDVMTargetDrive
exit
"@
                try {
                    $DiskpartResult = $DiskpartScript | diskpart 2>&1
                    if ($LASTEXITCODE -eq 0) {
                        Write-Host "CD/DVD drive relocated from D: to ${CDDVMTargetDrive}:" -ForegroundColor Green
                    } else {
                        Write-Host "Diskpart failed with exit code: $LASTEXITCODE" -ForegroundColor Red
                        Write-Host "Diskpart output: $DiskpartResult" -ForegroundColor Red
                    }
                } catch {
                    Write-Host "Failed to execute diskpart: $($_.Exception.Message)" -ForegroundColor Red
                }
                
                # Verify the relocation worked
                Start-Sleep -Seconds 2
                if (Test-Path "${CDDVMTargetDrive}:\") {
                    Write-Host "CD/DVD drive relocation verified successfully" -ForegroundColor Green
                } else {
                    Write-Host "CD/DVD drive relocation verification failed" -ForegroundColor Red
                }
            } catch {
                Write-Host "Failed to relocate CD/DVD drive: $($_.Exception.Message)" -ForegroundColor Red
            }
        } else {
            Write-Host "Target drive ${CDDVMTargetDrive}: already exists - cannot relocate CD/DVD" -ForegroundColor Red
        }
    } else {
        Write-Host "D: drive is not a CD/DVD ROM - no relocation needed" -ForegroundColor Green
    }
} else {
    Write-Host "CD/DVD drive relocation disabled in configuration" -ForegroundColor Yellow
}

# Continue with rest of script...
Write-Host ""
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host "PRINT SPOOLER CONFIGURATION" -ForegroundColor White
Write-Host "=====================================================" -ForegroundColor Cyan

# Configure Print Spooler service (critical before VDA installation)
try {
    $PrintSpoolerConfig = [bool](Get-ConfigValue -Key "ConfigurePrintSpooler" -DefaultValue "true" -ConfigFile $ConfigFilePath)
    
    if ($PrintSpoolerConfig) {
        Write-Host "Configuring Print Spooler service..." -ForegroundColor White
        
        # Stop Print Spooler service
        $SpoolerService = Get-Service -Name "Spooler" -ErrorAction SilentlyContinue
        if ($SpoolerService -and $SpoolerService.Status -eq "Running") {
            Stop-Service -Name "Spooler" -Force
            Write-Host "Print Spooler service stopped" -ForegroundColor Green
        }
        
        # Set Print Spooler to Manual start
        Set-Service -Name "Spooler" -StartupType Manual
        Write-Host "Print Spooler startup type set to Manual" -ForegroundColor Green
        
        # Start Print Spooler service
        Start-Service -Name "Spooler"
        Write-Host "Print Spooler service started" -ForegroundColor Green
        
    } else {
        Write-Host "Print Spooler configuration skipped - disabled in config" -ForegroundColor Yellow
    }
} catch {
    Write-Host "Print Spooler configuration failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host "CITRIX VDA INSTALLATION" -ForegroundColor White
Write-Host "=====================================================" -ForegroundColor Cyan

# Install Citrix VDA using auto-detection
try {
    $InstallVDA = [bool](Get-ConfigValue -Key "InstallVDA" -DefaultValue "true" -ConfigFile $ConfigFilePath)
    
    if ($InstallVDA) {
        Write-Host "Starting Citrix VDA installation..." -ForegroundColor White
        
        # Check if VDA ISO source path is provided
        if (-not [string]::IsNullOrEmpty($VDAISOSourcePath) -and (Test-Path $VDAISOSourcePath)) {
            Write-Host "Copying VDA ISO from network: $VDAISOSourcePath" -ForegroundColor White
            Copy-Item -Path $VDAISOSourcePath -Destination $VDAISOPath -Force
            Write-Host "VDA ISO copied to: $VDAISOPath" -ForegroundColor Green
        }
        
        if (Test-Path $VDAISOPath) {
            # Check if the required function exists
            if (Get-Command "Install-VDAFromISOWithDetection" -ErrorAction SilentlyContinue) {
                # Install VDA using auto-detection function
                $VDAInstallResult = Install-VDAFromISOWithDetection -ISOPath $VDAISOPath -ConfigFilePath $ConfigFilePath
            
                if ($VDAInstallResult.Success) {
                    Write-Host "Citrix VDA installation completed successfully" -ForegroundColor Green
                    Write-Host "Installer used: $($VDAInstallResult.InstallerUsed)" -ForegroundColor White
                    
                    if ($VDAInstallResult.ExitCode -eq 3010) {
                        Write-Host "System reboot required to complete VDA installation" -ForegroundColor Yellow
                    }
                } else {
                    Write-Host "Citrix VDA installation failed: $($VDAInstallResult.Error)" -ForegroundColor Red
                }
            } else {
                Write-Host "Install-VDAFromISOWithDetection function not found in module" -ForegroundColor Red
            }
        } else {
            Write-Host "VDA ISO not found at: $VDAISOPath" -ForegroundColor Red
        }
    } else {
        Write-Host "Citrix VDA installation skipped - disabled in configuration" -ForegroundColor Yellow
    }
} catch {
    Write-Host "VDA installation failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""
Write-Host "=====================================================" -ForegroundColor Green
Write-Host "STAGE 1 COMPLETED SUCCESSFULLY" -ForegroundColor White
Write-Host "Ready for VDA installation (Stage 2)" -ForegroundColor White
Write-Host "=====================================================" -ForegroundColor Green
