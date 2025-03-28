# Function to check if D:\ drive exists and prompt if it doesn't
function Ensure-DriveExists {
    param (
        [string]$DriveLetter = "D:"
    )
    
    # Check if drive exists
    if(!(Test-Path "$DriveLetter\")) {
        Write-Log "WARNING: $DriveLetter drive not found!"
        
        # Create a GUI prompt (works even in system context)
        $drivePrompt = New-Object -ComObject WScript.Shell
        $result = $drivePrompt.Popup("$DriveLetter drive is not detected. This drive is required for event logs and pagefile. `n`nPlease attach the drive now, then click OK to continue.`n`nIf you click Cancel, these operations will be skipped.", 0, "Drive Required", 1 + 48)
        
        # Wait for user response
        if($result -eq 1) { # OK
            # Give the system a moment to recognize the drive
            Start-Sleep -Seconds 2
            
            # Check again
            if(!(Test-Path "$DriveLetter\")) {
                Write-Log "WARNING: $DriveLetter drive still not detected after user confirmation"
                $secondResult = $drivePrompt.Popup("$DriveLetter drive is still not detected. Do you want to skip the operations that require this drive?", 0, "Drive Not Found", 4 + 48)
                
                if($secondResult -eq 6) { # Yes
                    Write-Log "User opted to skip operations requiring $DriveLetter drive"
                    return $false
                } else {
                    # Give another chance
                    Write-Log "User requested another attempt to find $DriveLetter drive"
                    Start-Sleep -Seconds 5
                    if(!(Test-Path "$DriveLetter\")) {
                        Write-Log "WARNING: $DriveLetter drive not found after multiple attempts"
                        $drivePrompt.Popup("$DriveLetter drive could not be found. Operations requiring this drive will be skipped.", 0, "Drive Not Found", 48)
                        return $false
                    } else {
                        Write-Log "$DriveLetter drive is now available"
                        return $true
                    }
                }
            } else {
                Write-Log "$DriveLetter drive is now available"
                return $true
            }
        } else { # Cancel
            Write-Log "User cancelled the operation to wait for $DriveLetter drive"
            return $false
        }
    } else {
        # Drive exists
        Write-Log "$DriveLetter drive is available"
        return $true
    }
# Finalize App Layer after NGEN optimization

   try {
        $process = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$UberAgentInstallerPath`" $($uberAgentInstallArgs -join ' ')" -Wait -PassThru -NoNewWindow
        $exitCode = $process.ExitCode
        
        if($exitCode -eq 0 -or $exitCode -eq 3010) {
            Write-Log "UberAgent installation completed successfully (Exit Code: $exitCode)"
            if($exitCode -eq 3010) {
                Write-Log "A reboot is required to complete the UberAgent installation"
            }
        } else {
            Write-Log "UberAgent installation failed with exit code: $exitCode"
            Write-Log "Check the installation logs at $LogPath\UberAgent_Install.log for more details"
        }

   try {
    Write-PostLog "Finalizing the application layer"
    
    # Check if we're running in App Layering environment
    `$isAppLayeringEnvironment = `$false
    
    # Check for Unidesk/App Layering processes
    `$layeringProcesses = Get-Process | Where-Object { `$_.Name -like "*Unidesk*" -or `$_.Name -like "*ULayer*" -or `$_.Name -like "*AppLayering*" } -ErrorAction SilentlyContinue
    if(`$layeringProcesses -ne `$null) {
        `$isAppLayeringEnvironment = `$true
    }
    
    # Check for App Layering registry keys
    if(Test-Path "HKLM:\SOFTWARE\Unidesk" -or Test-Path "HKLM:\SOFTWARE\Citrix\AppLayering") {
        `$isAppLayeringEnvironment = `$true
    }
    
    if(`$isAppLayeringEnvironment) {
        Write-PostLog "App Layering environment detected"
        
        # Try to find the ALTool.exe utility
        `$alToolPath = `$null
        `$possiblePaths = @(
            "C:\Program Files\Citrix\AppLayering\ALTool.exe",
            "C:\Program Files\Unidesk\ALTool.exe",
            "C:\Program Files (x86)\Citrix\AppLayering\ALTool.exe",
            "C:\Program Files (x86)\Unidesk\ALTool.exe"
        )
        
        foreach(`$path in `$possiblePaths) {
            if(Test-Path `$path) {
                `$alToolPath = `$path
                break
            }
        }
        
        if(`$alToolPath) {
            Write-PostLog "Found App Layering tool at: `$alToolPath"
            
            # Create a marker file to indicate the layer is ready for finalization
            `$markerContent = "Layer ready for finalization - $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))"
            `$markerContent | Out-File -FilePath "C:\LayerReadyToFinalize.txt" -Force
            
            Write-PostLog "Created finalization marker file at C:\LayerReadyToFinalize.txt"
            
            # Check if we can finalize directly
            if(Test-Path `$alToolPath) {
                # Try to finalize the layer
                Write-PostLog "Attempting to finalize the layer using ALTool.exe"
                `$finalizeResult = Start-Process -FilePath `$alToolPath -ArgumentList "finalize" -Wait -PassThru -NoNewWindow
                
                if(`$finalizeResult.ExitCode -eq 0) {
                    Write-PostLog "Layer finalization initiated successfully"
                } else {
                    Write-PostLog "WARNING: Layer finalization returned exit code: `$(`$finalizeResult.ExitCode)"
                }
            } else {
                Write-PostLog "ALTool.exe not available. Finalization will need to be completed manually."
            }
        } else {
            Write-PostLog "App Layering tool not found. Finalization will need to be completed manually."
            
            # If we can't find the tool, create a desktop shortcut with instructions
            `$desktopPath = [Environment]::GetFolderPath("Desktop")
            `$shortcutFile = "`$desktopPath\Finalize App Layer.txt"
            
            `$instructionContent = @"
The Citrix platform layer installation is complete and optimized.
You can now finalize the application layer using the App Layering management console.

Layer was prepared on: $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))
"@
            
            `$instructionContent | Out-File -FilePath `$shortcutFile -Force
            Write-PostLog "Created instructions file at: `$shortcutFile"
        }
    } else {
        Write-PostLog "Not running in an App Layering environment. Skipping layer finalization."
    }
} catch {
    Write-PostLog "WARNING: Error during layer finalization: `$_"
}if($RedirectEventLogs) {
    Write-Host "  - Redirected Event Logs to D:\EventLogs"
}if($ClearTempFiles) {
    Write-Host "  - Cleared temp files"
}
if($EmptyRecycleBin) {
    Write-Host "  - Emptied recycle bin"
}
if($RunNGEN) {
    Write-Host "  - Optimized .NET Framework with NGEN"
}Write-Host "System changes:"
if($RemoveGhostDevices) {
    Write-Host "  - Removed ghost devices from Device Manager"
}
if($MovePageFile) {
    Write-Host "  - Moved page file to D: drive"
}
if($JoinDomain) {
    Write-Host "  - Joined domain: $DomainName"
}
if($ClearEventLogs) {
    Write-Host "  - Cleared Event Logs"
}
if($RearmKMS) {
    Write-Host "  - Rearmed KMS licensing"
}# Install UberAgent
if($InstallUberAgent) {
    Write-Log "Starting UberAgent installation"
    
    # Set up UberAgent installation arguments
    $uberAgentInstallArgs = @(
        "/quiet",
        "/norestart",
        "/log $LogPath\UberAgent_Install.log"
    )
    
    Write-Log "Starting UberAgent installation with arguments: $($uberAgentInstallArgs -join ' ')"
    try {
        $process = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$UberAgentInstallerPath`" $($uberAgentInstallArgs -join ' ')" -Wait -PassThru -NoNewWindow
        $exitCode = $process.ExitCode
        
        if($exitCode -eq 0 -or $exitCode -eq 3010) {
            Write-Log "UberAgent installation completed successfully (Exit Code: $exitCode)"
            if($exitCode -eq 3010) {
                Write-Log "A reboot is required to complete the UberAgent installation"
            }
        } else {
            Write-Log "UberAgent installation failed with exit code: $exitCode"
            Write-Log "Check the installation logs at $LogPath\UberAgent_Install.log for more details"
        }
    } catch {
        Write-Log "ERROR: An exception occurred during UberAgent installation: $_"
    }
    
    # Configure UberAgent for VDI environment if optimizing for layering
    if($OptimizeForLayering) {
        Write-Log "Optimizing UberAgent for VDI environment"
        
        # Create UberAgent optimization settings
        $uberAgentOptSettings = @{
            "HKLM:\SOFTWARE\vastlimit\uberAgent\Settings" = @{
                "EnableCitrixOptimizations" = 1
                "EnableVDIMode" = 1
                "CollectionInterval" = 60
                "BufferInterval" = 300
            }
        }
        
        # Apply UberAgent optimization settings
        foreach($regPath in $uberAgentOptSettings.Keys) {
            if(!(Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }
            
            foreach($name in $uberAgentOptSettings[$regPath].Keys) {
                Set-ItemProperty -Path $regPath -Name $name -Value $uberAgentOptSettings[$regPath][$name] -ErrorAction SilentlyContinue
            }
        }
    }
}# Citrix Platform Layer Installation Script
# This script automates the installation of Citrix Virtual Delivery Agent (VDA), Provisioning Services (PVS) Target Device software,
# Workspace Environment Management (WEM) Agent, and runs Citrix Optimizer for use in a platform layer
# Usage: Run as administrator in PowerShell

# Define parameters
param(
    [string]$VDAInstallerPath = ".\VDAServerSetup.exe",
    [string]$PVSInstallerPath = ".\PVS_Device.exe",
    [string]$WEMAgentInstallerPath = ".\Citrix Workspace Environment Management Agent.exe",
    [string]$UberAgentInstallerPath = ".\UberAgent.msi",
    [string]$CitrixOptimizerPath = ".\CtxOptimizerEngine.ps1",
    [string]$OptimizerTemplatePath = "",  # If empty, will use the built-in templates
    [string]$LogPath = "C:\Logs\Citrix_Install",
    [string]$ControllerAddress,
    [string]$PVSServerAddress,
    [string]$WEMInfrastructureServer,
    [int]$WEMAgentPort = 8286,
    [switch]$InstallPVS = $true,
    [switch]$InstallWEM = $true,
    [switch]$InstallUberAgent = $true,
    [switch]$RunOptimizer = $true,
    [string]$OptimizerMode = "Execute",  # Options: "Analyze", "Execute", "ExecuteForce", "Rollback"
    [string]$PVSBootMode = "VM-AUTO", # Options: "VM-AUTO", "VM-STATIC", "VM-DHCP"
    [switch]$OptimizeForLayering = $true,
    [switch]$RearmKMS = $true,
    [switch]$ClearEventLogs = $true,
    [switch]$RemoveGhostDevices = $true,
    [switch]$MovePageFile = $true,
    [switch]$ClearTempFiles = $true,
    [switch]$EmptyRecycleBin = $true,
    [switch]$RedirectEventLogs = $true,
    [switch]$RunNGEN = $true,
    [switch]$FinalizeAppLayer = $true,
    [switch]$CreatePostRebootTasks = $true,
    [switch]$JoinDomain = $true,
    [string]$DomainName = "example.local",
    [string]$DomainOU = "OU=Citrix,DC=example,DC=local",
    [string]$DomainUser,
    [string]$DomainPassword,
    [switch]$IncludeAdditionalComponents = $true,
    [string]$AdditionalComponents = "VDA_PLUGINS,PERSONALIZATION",
    [string]$ServicesUser = "",
    [string]$ServicesPassword = ""
)

# Create log directory if it doesn't exist
if(!(Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force
    Write-Host "Created log directory at $LogPath"
}

# Function to log messages
function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] $Message"
    Add-Content -Path "$LogPath\VDA_Install.log" -Value "[$timestamp] $Message"
}

# Check if running as administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if(-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log "ERROR: This script must be run as Administrator"
    exit 1
}

# Verify VDA installer exists
if(!(Test-Path $VDAInstallerPath)) {
    Write-Log "ERROR: VDA installer not found at $VDAInstallerPath"
    exit 1
}

# Verify PVS installer exists if required
if($InstallPVS -and !(Test-Path $PVSInstallerPath)) {
    Write-Log "ERROR: PVS target device installer not found at $PVSInstallerPath"
    exit 1
}

# Verify WEM Agent installer exists if required
if($InstallWEM -and !(Test-Path $WEMAgentInstallerPath)) {
    Write-Log "ERROR: WEM Agent installer not found at $WEMAgentInstallerPath"
    exit 1
}

# Verify UberAgent installer exists if required
if($InstallUberAgent -and !(Test-Path $UberAgentInstallerPath)) {
    Write-Log "ERROR: UberAgent installer not found at $UberAgentInstallerPath"
    exit 1
}

# Verify Citrix Optimizer script exists if required
if($RunOptimizer -and !(Test-Path $CitrixOptimizerPath)) {
    Write-Log "ERROR: Citrix Optimizer script not found at $CitrixOptimizerPath"
    exit 1
}

# Check if custom template exists if specified
if($RunOptimizer -and ![string]::IsNullOrEmpty($OptimizerTemplatePath) -and !(Test-Path $OptimizerTemplatePath)) {
    Write-Log "ERROR: Citrix Optimizer template not found at $OptimizerTemplatePath"
    exit 1
}

Write-Log "Starting Citrix component installation for Platform Layer"
Write-Log "Using VDA installer: $VDAInstallerPath"
Write-Log "Delivery Controller(s): $ControllerAddress"

if($InstallPVS) {
    Write-Log "Will install PVS target device software"
    Write-Log "Using PVS installer: $PVSInstallerPath"
    Write-Log "PVS Server(s): $PVSServerAddress"
    Write-Log "PVS Boot Mode: $PVSBootMode"
}

if($InstallWEM) {
    Write-Log "Will install WEM Agent software"
    Write-Log "Using WEM Agent installer: $WEMAgentInstallerPath"
    Write-Log "WEM Infrastructure Server: $WEMInfrastructureServer"
    Write-Log "WEM Agent Port: $WEMAgentPort"
}

if($InstallUberAgent) {
    Write-Log "Will install UberAgent software"
    Write-Log "Using UberAgent installer: $UberAgentInstallerPath"
}

if($RunOptimizer) {
    Write-Log "Will run Citrix Optimizer"
    Write-Log "Using Optimizer script: $CitrixOptimizerPath"
    Write-Log "Optimization mode: $OptimizerMode"
    if(![string]::IsNullOrEmpty($OptimizerTemplatePath)) {
        Write-Log "Using custom template: $OptimizerTemplatePath"
    } else {
        Write-Log "Using built-in templates"
    }
}

# Disable Windows Update service during installation
Write-Log "Disabling Windows Update service during installation"
Stop-Service -Name wuauserv -Force
Set-Service -Name wuauserv -StartupType Disabled

# Set up installation arguments
$installArgs = @(
    "/quiet",
    "/logpath $LogPath",
    "/noreboot",
    "/components VDA",
    "/controllers $ControllerAddress",
    "/enable_hdx_ports",
    "/enable_real_time_transport",
    "/virtualmachine"
)

# Add optional arguments based on parameters
if($OptimizeForLayering) {
    $installArgs += "/optimize"
}

if($IncludeAdditionalComponents -and -not [string]::IsNullOrEmpty($AdditionalComponents)) {
    $installArgs += "/includeadditional $AdditionalComponents"
}

if($VDAInstallMode -eq "Server") {
    $installArgs += "/servervdi"
}

if($ServicesUser -and $ServicesPassword) {
    $installArgs += "/servicesaccount $ServicesUser"
    $installArgs += "/servicespassword $ServicesPassword"
}

# Special optimizations for layering
if($OptimizeForLayering) {
    Write-Log "Applying special optimizations for platform layering"
    
    # Registry settings for layering optimization
    # Disable automatic Windows Updates
    Write-Log "Configuring registry settings for layering"
    
    $regSettings = @{
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" = @{
            "NoAutoUpdate" = 1
            "AUOptions" = 1
        }
        "HKLM:\SOFTWARE\Citrix\VirtualDesktopAgent" = @{
            "EnableUserProfileRedirection" = 0
            "ListOfDDCs" = $ControllerAddress
        }
    }
    
    foreach($regPath in $regSettings.Keys) {
        if(!(Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        
        foreach($name in $regSettings[$regPath].Keys) {
            Set-ItemProperty -Path $regPath -Name $name -Value $regSettings[$regPath][$name]
        }
    }
}

# Start the VDA installation
Write-Log "Starting VDA installation with arguments: $($installArgs -join ' ')"
try {
    $process = Start-Process -FilePath $VDAInstallerPath -ArgumentList $installArgs -Wait -PassThru
    $exitCode = $process.ExitCode
    
    if($exitCode -eq 0 -or $exitCode -eq 3010) {
        Write-Log "VDA installation completed successfully (Exit Code: $exitCode)"
        if($exitCode -eq 3010) {
            Write-Log "A reboot is required to complete the installation"
        }
    } else {
        Write-Log "VDA installation failed with exit code: $exitCode"
        Write-Log "Check the installation logs at $LogPath for more details"
    }
} catch {
    Write-Log "ERROR: An exception occurred during installation: $_"
    exit 1
}

# Install PVS Target Device Software
if($InstallPVS) {
    Write-Log "Starting PVS Target Device Software installation"
    
    # Set up PVS installation arguments
    $pvsInstallArgs = @(
        "/quiet",
        "/noreboot",
        "/log $LogPath\PVS_Install.log"
    )
    
    # Add PVS server addresses
    $pvsInstallArgs += "/storageserver $PVSServerAddress"
    
    # Add boot mode configuration
    $pvsInstallArgs += "/bootmode=$PVSBootMode"
    
    # Add optimization for virtual machines
    $pvsInstallArgs += "/virtualmachine"
    
    Write-Log "Starting PVS installation with arguments: $($pvsInstallArgs -join ' ')"
    try {
        $process = Start-Process -FilePath $PVSInstallerPath -ArgumentList $pvsInstallArgs -Wait -PassThru
        $exitCode = $process.ExitCode
        
        if($exitCode -eq 0 -or $exitCode -eq 3010) {
            Write-Log "PVS Target Device installation completed successfully (Exit Code: $exitCode)"
            if($exitCode -eq 3010) {
                Write-Log "A reboot is required to complete the PVS installation"
            }
        } else {
            Write-Log "PVS Target Device installation failed with exit code: $exitCode"
            Write-Log "Check the installation logs at $LogPath\PVS_Install.log for more details"
        }
    } catch {
        Write-Log "ERROR: An exception occurred during PVS installation: $_"
    }
    
    # Configure PVS Target Device for optimal performance in a layer
    if($OptimizeForLayering) {
        Write-Log "Optimizing PVS settings for layering"
        
        # Registry settings for PVS
        $pvsRegSettings = @{
            "HKLM:\SYSTEM\CurrentControlSet\Services\BNIStack\Parameters" = @{
                "DisableOSRecovery" = 1  # Prevent recovery mode for better layering compatibility
                "MaximumTransmissionUnit" = 1506  # Optimize network performance
                "EnableWinsRedirection" = 0  # Disable WINS for layer
            }
            "HKLM:\SYSTEM\CurrentControlSet\Services\BNNS\Parameters" = @{
                "EnableOffloadStaticIp" = 1  # Enhance network performance
            }
            "HKLM:\SOFTWARE\Citrix\ProvisioningServices" = @{
                "UseTemplateDevice" = 1  # Optimize for template/golden image use
            }
        }
        
        foreach($regPath in $pvsRegSettings.Keys) {
            if(!(Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }
            
            foreach($name in $pvsRegSettings[$regPath].Keys) {
                Set-ItemProperty -Path $regPath -Name $name -Value $pvsRegSettings[$regPath][$name] -ErrorAction SilentlyContinue
            }
        }
    }
}

# Install WEM Agent
if($InstallWEM) {
    Write-Log "Starting WEM Agent installation"
    
    # Create WEM Agent installation answer file
    $wemAgentAnswerFilePath = "$LogPath\WEM_Agent_Install.xml"
    
    $wemAgentAnswerContent = @"
<?xml version="1.0" encoding="UTF-8"?>
<Citrix>
  <WorkspaceEnvironmentManagement>
    <AgentInstallation>
      <InstallationMode>Silent</InstallationMode>
      <AgentConfiguration>
        <AgentPort>$WEMAgentPort</AgentPort>
        <AgentServiceDebugMode>false</AgentServiceDebugMode>
        <AgentCacheRefreshDelay>30</AgentCacheRefreshDelay>
        <AgentServiceLogLevel>Normal</AgentServiceLogLevel>
      </AgentConfiguration>
      <AgentLocation>
        <ServerUrl>$WEMInfrastructureServer</ServerUrl>
      </AgentLocation>
    </AgentInstallation>
  </WorkspaceEnvironmentManagement>
</Citrix>
"@
    
    # Save the answer file
    $wemAgentAnswerContent | Out-File -FilePath $wemAgentAnswerFilePath -Encoding utf8 -Force
    Write-Log "Created WEM Agent answer file at $wemAgentAnswerFilePath"
    
    # Set up WEM Agent installation arguments
    $wemAgentInstallArgs = @(
        "/quiet",
        "/noreboot",
        "/log $LogPath\WEM_Install.log",
        "/Answerfile $wemAgentAnswerFilePath"
    )
    
    Write-Log "Starting WEM Agent installation with arguments: $($wemAgentInstallArgs -join ' ')"
    try {
        $process = Start-Process -FilePath $WEMAgentInstallerPath -ArgumentList $wemAgentInstallArgs -Wait -PassThru
        $exitCode = $process.ExitCode
        
        if($exitCode -eq 0 -or $exitCode -eq 3010) {
            Write-Log "WEM Agent installation completed successfully (Exit Code: $exitCode)"
            if($exitCode -eq 3010) {
                Write-Log "A reboot is required to complete the WEM Agent installation"
            }
        } else {
            Write-Log "WEM Agent installation failed with exit code: $exitCode"
            Write-Log "Check the installation logs at $LogPath\WEM_Install.log for more details"
        }
    } catch {
        Write-Log "ERROR: An exception occurred during WEM Agent installation: $_"
    }
    
    # Optimize WEM Agent for layering
    if($OptimizeForLayering) {
        Write-Log "Optimizing WEM Agent settings for layering"
        
        # Registry settings for WEM Agent
        $wemRegSettings = @{
            "HKLM:\SOFTWARE\Policies\Citrix\WEM\Agent" = @{
                "AgentServiceStartupType" = 2  # Automatic
                "AgentAllowCloudConnectors" = 0  # Disable cloud connectors for platform layer
                "AgentServiceDebugMode" = 0  # Disable debug mode in production
                "AgentSyncData" = 1  # Enable data sync
                "AgentCacheRefreshDelay" = 30  # 30 minutes cache refresh
                "EnableVUEMAppsOnLogon" = 1  # Process applications on logon
            }
        }
        
        foreach($regPath in $wemRegSettings.Keys) {
            if(!(Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }
            
            foreach($name in $wemRegSettings[$regPath].Keys) {
                Set-ItemProperty -Path $regPath -Name $name -Value $wemRegSettings[$regPath][$name] -ErrorAction SilentlyContinue
            }
        }
        
        # Configure WEM Agent Service for Automatic start
        Set-Service -Name "Citrix WEM Agent Host Service" -StartupType Automatic -ErrorAction SilentlyContinue
    }
}

# Run Citrix Optimizer
if($RunOptimizer) {
    Write-Log "Starting Citrix Optimizer"
    
    # Build Citrix Optimizer parameters
    $optimizerParams = @{
        "Mode" = $OptimizerMode
    }
    
    # Add template path if specified
    if(![string]::IsNullOrEmpty($OptimizerTemplatePath)) {
        $optimizerParams.Add("TemplatePath", $OptimizerTemplatePath)
    }
    
    # Add logging parameters
    $optimizerLogPath = "$LogPath\CitrixOptimizer_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    $optimizerParams.Add("OutputLogPath", $optimizerLogPath)
    
    # Add additional parameters for platform layer optimization
    if($OptimizeForLayering) {
        $optimizerParams.Add("DisableNotification", $true)
    }
    
    # Determine OS version for template selection if not specified
    if([string]::IsNullOrEmpty($OptimizerTemplatePath)) {
        $osInfo = Get-WmiObject -Class Win32_OperatingSystem
        $osVersion = $osInfo.Version
        $osCaption = $osInfo.Caption
        
        Write-Log "Detected OS: $osCaption (Version: $osVersion)"
        
        # Determine template based on OS version and VDA mode
        $templateName = ""
        
        if($osVersion -match "^10\.") {
            # Windows 10/11 or Server 2016/2019/2022
            if($osCaption -match "Server") {
                if($osCaption -match "2022") {
                    $templateName = "Windows Server 2022"
                } elseif($osCaption -match "2019") {
                    $templateName = "Windows Server 2019"
                } elseif($osCaption -match "2016") {
                    $templateName = "Windows Server 2016"
                }
            } else {
                # Windows 10/11 detection
                $buildNumber = $osInfo.BuildNumber
                if($buildNumber -ge 22000) {
                    # Windows 11
                    $templateName = "Windows 11"
                } else {
                    # Windows 10
                    $templateName = "Windows 10"
                }
            }
        } elseif($osVersion -match "^6\.3") {
            $templateName = "Windows Server 2012 R2"
        }
        
        if(![string]::IsNullOrEmpty($templateName)) {
            Write-Log "Automatically selected template: $templateName"
            $optimizerParams.Add("DisplayName", $templateName)
        } else {
            Write-Log "WARNING: Could not automatically select template based on OS version. Using default template."
        }
    }
    
    # Convert parameters to string format for PowerShell
    $optimizerParamString = ""
    foreach($key in $optimizerParams.Keys) {
        $value = $optimizerParams[$key]
        if($value -is [string]) {
            $optimizerParamString += "-$key '$value' "
        } elseif($value -is [bool]) {
            if($value) {
                $optimizerParamString += "-$key "
            }
        } else {
            $optimizerParamString += "-$key $value "
        }
    }
    
    Write-Log "Running Citrix Optimizer with parameters: $optimizerParamString"
    
    try {
        # Run Citrix Optimizer
        $optimizerCommand = "& '$CitrixOptimizerPath' $optimizerParamString"
        Write-Log "Executing: $optimizerCommand"
        
        $optimizerOutput = Invoke-Expression $optimizerCommand
        
        # Log output
        $optimizerOutput | ForEach-Object {
            Write-Log "Optimizer: $_"
        }
        
        Write-Log "Citrix Optimizer completed"
        
        # Save optimizer results
        if(Test-Path $optimizerLogPath) {
            # Copy optimizer log to standard location
            Copy-Item -Path $optimizerLogPath -Destination "C:\Program Files\Citrix\PlatformLayer_OptimizerResults.log" -Force
            Write-Log "Optimizer results saved to C:\Program Files\Citrix\PlatformLayer_OptimizerResults.log"
        }
    } catch {
        Write-Log "ERROR: An exception occurred during optimization: $_"
    }
}

# Post-installation tasks
Write-Log "Performing post-installation tasks"

# Remove Ghost Devices if enabled
if($RemoveGhostDevices) {
    try {
        Write-Log "Removing ghost devices from Device Manager"
        
        # Creates and runs a temporary script to remove ghost devices, it deletes the script after use.
        $ghostDevicesScript = @"
# Set DevMgr_Show_NonPresent_Devices = 1 to show hidden devices
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name "DEVMGR_SHOW_NONPRESENT_DEVICES" -Value 1

# Get all devices
`$devices = Get-PnpDevice -Status Unknown | Where-Object { `$_.Problem -eq 45 -or `$_.Problem -eq 24 }

# Count of removed devices
`$count = 0

# Remove each ghost device
foreach(`$device in `$devices) {
    try {
        Write-Output "Removing ghost device: `$(`$device.FriendlyName) [`$(`$device.InstanceId)]"
        `$device | Remove-PnpDevice -Force -Confirm:`$false
        `$count++
    } catch {
        Write-Output "Failed to remove device: `$(`$device.FriendlyName) - `$_"
    }
}

# Return count
Write-Output "`nRemoved `$count ghost devices"

# Reset DevMgr_Show_NonPresent_Devices
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name "DEVMGR_SHOW_NONPRESENT_DEVICES" -Value 0
"@

        $ghostScriptPath = "$env:TEMP\RemoveGhostDevices.ps1"
        $ghostDevicesScript | Out-File -FilePath $ghostScriptPath -Force
        
        # Run the ghost devices removal script
        $ghostOutput = & powershell.exe -ExecutionPolicy Bypass -File $ghostScriptPath
        
        # Log results
        foreach($line in $ghostOutput) {
            Write-Log "Ghost Device Removal: $line"
        }
        
        # Clean up
        Remove-Item -Path $ghostScriptPath -Force -ErrorAction SilentlyContinue
        
    } catch {
        Write-Log "WARNING: Error removing ghost devices: $_"
    }
}

# Move Page File to D: drive if enabled
if($MovePageFile) {
    try {
        Write-Log "Moving page file from C: to D: drive"
        
        # Check if D: drive exists
        if(Ensure-DriveExists -DriveLetter "D:") {
            # Get current page file settings
            $pageFileSettings = Get-WmiObject -Class Win32_ComputerSystem -EnableAllPrivileges
            
            # Disable automatic page file management
            $pageFileSettings.AutomaticManagedPagefile = $false
            $pageFileSettings.Put() | Out-Null
            
            # Remove existing page file settings
            Get-WmiObject -Class Win32_PageFileSetting | ForEach-Object { $_.Delete() }
            
            # Create a new page file on D: drive
            $newPageFile = New-Object System.Management.ManagementClass("Win32_PageFileSetting")
            $newPageFile.Name = "D:\pagefile.sys"
            $newPageFile.InitialSize = 8192  # 8GB initial size
            $newPageFile.MaximumSize = 8192  # 8GB maximum size
            $newPageFile.Put() | Out-Null
            
            Write-Log "Page file moved to D:\pagefile.sys (8GB initial, 8GB maximum)"
        } else {
            Write-Log "WARNING: Cannot move page file. D: drive not available."
        }
    } catch {
        Write-Log "WARNING: Error moving page file: $_"
    }
}

# Join Domain if enabled
if($JoinDomain) {
    try {
        Write-Log "Joining computer to domain: $DomainName"
        
        # Check if already domain joined
        $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
        if($computerSystem.PartOfDomain -and $computerSystem.Domain -eq $DomainName) {
            Write-Log "Computer is already joined to domain $DomainName"
        } else {
            # Prompt for credentials.
            if([string]::IsNullOrEmpty($DomainUser) -or [string]::IsNullOrEmpty($DomainPassword)) {
                Write-Log "Domain credentials not provided in parameters. Prompting user..."
                $credentials = Get-Credential -Message "Enter domain join credentials" -UserName "$DomainName\Administrator"
            } else {
                $securePassword = ConvertTo-SecureString $DomainPassword -AsPlainText -Force
                $credentials = New-Object System.Management.Automation.PSCredential ($DomainUser, $securePassword)
            }
            
            # Join the domain
            if([string]::IsNullOrEmpty($DomainOU)) {
                # Join without OU
                Add-Computer -DomainName $DomainName -Credential $credentials -Restart:$false -Force
            } else {
                # Join with OU
                Add-Computer -DomainName $DomainName -OUPath $DomainOU -Credential $credentials -Restart:$false -Force
            }
            
            Write-Log "Successfully joined domain $DomainName"
        }
    } catch {
        Write-Log "WARNING: Error joining domain: $_"
    }
}

# Clear Temp Files - Moved to post-reboot tasks

# Run NGEN optimization - Moved to post-reboot tasks

# Disable Windows Update Service After Installation
Write-Log "Disabling Windows Update service"
Set-Service -Name wuauserv -StartupType Disabled
Stop-Service -Name wuauserv

Write-Log "Stage 1 of Citrix platform layer installation script completed"
Write-Log "After reboot, Stage 2 tasks will run automatically to optimize the system" 0
        $deletedFiles = 0
        $errorFiles = 0
        
        # Clear each temp folder
        foreach($folder in $tempFolders) {
            if(Test-Path $folder) {
                Write-Log "Clearing temp folder: $folder"
                
                # Get all files and folders in the temp directory
                $items = Get-ChildItem -Path $folder -Force -ErrorAction SilentlyContinue | 
                         Where-Object { !$_.PSIsContainer }
                
                $totalFiles += $items.Count
                
                # Delete each file
                foreach($item in $items) {
                    try {
                        Remove-Item -Path $item.FullName -Force -ErrorAction Stop
                        $deletedFiles++
                    } catch {
                        $errorFiles++
                        # Just log but continue
                        Write-Log "WARNING: Could not delete file: $($item.FullName) - $_"
                    }
                }
            } else {
                Write-Log "Temp folder not found: $folder"
            }
        }
        
        Write-Log "Temporary files cleanup completed: $deletedFiles of $totalFiles files deleted ($errorFiles errors)"
    } catch {
        Write-Log "WARNING: Error cleaning temporary files: $_"
    }
}

# Empty Recycle Bin if enabled
if($EmptyRecycleBin) {
    try {
        Write-Log "Emptying all recycle bins"
        
        # To avoid errors if the module is not available, load it with a check
        if(-not (Get-Command Clear-RecycleBin -ErrorAction SilentlyContinue)) {
            # If Clear-RecycleBin is not available, use shell.application
            Write-Log "Using Shell.Application to empty recycle bins"
            $shell = New-Object -ComObject Shell.Application
            $shell.Namespace(0xA).Items() | ForEach-Object { Remove-Item $_.Path -Recurse -Force -ErrorAction SilentlyContinue }
        } else {
            # If Clear-RecycleBin is available, use it
            Clear-RecycleBin -Force -ErrorAction SilentlyContinue
        }
        
        Write-Log "Recycle bins emptied successfully"
    } catch {
        Write-Log "WARNING: Error emptying recycle bins: $_"
    }
}

# Create post-reboot tasks for NGEN optimization, temp file cleanup, and event log clearing
if($CreatePostRebootTasks) {
    try {
        Write-Log "Setting up post-reboot tasks for NGEN optimization, temp file cleanup, and event log clearing"
        
        # Create the script content
        $postRebootScriptContent = @"
# Post-reboot tasks script for Citrix platform layer
# This script runs after reboot to perform final cleanup and optimization

# Create log file
`$logPath = "C:\Logs\Citrix_PostReboot"
if(!(Test-Path `$logPath)) {
    New-Item -ItemType Directory -Path `$logPath -Force | Out-Null
}
`$logFile = "`$logPath\PostReboot_`$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Function to log messages
function Write-PostLog {
    param([string]`$Message)
    `$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    `$logEntry = "[`$timestamp] `$Message"
    Add-Content -Path `$logFile -Value `$logEntry
    Write-Host `$logEntry
}

Write-PostLog "Starting post-reboot tasks for Citrix platform layer"

# Clear Event Logs
try {
    Write-PostLog "Clearing Windows Event Logs"
    
    # Get list of logs with records
    `$eventLogs = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | 
                 Where-Object { `$_.RecordCount -gt 0 -and !`$_.IsEnabled } | 
                 Select-Object -ExpandProperty LogName
    
    foreach(`$log in `$eventLogs) {
        try {
            Write-PostLog "Clearing event log: `$log"
            [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog("`$log")
        } catch {
            Write-PostLog "WARNING: Could not clear event log `$log : `$_"
        }
    }
    
    # Also clear standard logs with wevtutil
    `$standardLogs = @("Application", "System", "Security", "Setup", "ForwardedEvents")
    foreach(`$log in `$standardLogs) {
        try {
            Write-PostLog "Clearing standard event log: `$log"
            wevtutil cl `$log
        } catch {
            Write-PostLog "WARNING: Could not clear standard event log `$log : `$_"
        }
    }
    
    Write-PostLog "Event logs cleared successfully"
} catch {
    Write-PostLog "WARNING: Error clearing event logs: `$_"
}

# Clear Temp Files
try {
    Write-PostLog "Clearing temporary files"
    
    # Define temp directories to clean
    `$tempFolders = @(
        "C:\Temp",
        "C:\Windows\Temp",
        `$env:TEMP
    )
    
    # Track statistics
    `$totalFiles = 0
    `$deletedFiles = 0
    `$errorFiles = 0
    
    # Clear each temp folder
    foreach(`$folder in `$tempFolders) {
        if(Test-Path `$folder) {
            Write-PostLog "Clearing temp folder: `$folder"
            
            # Get all files and folders in the temp directory
            `$items = Get-ChildItem -Path `$folder -Force -ErrorAction SilentlyContinue | 
                     Where-Object { !`$_.PSIsContainer }
            
            `$totalFiles += `$items.Count
            
            # Delete each file
            foreach(`$item in `$items) {
                try {
                    Remove-Item -Path `$item.FullName -Force -ErrorAction Stop
                    `$deletedFiles++
                } catch {
                    `$errorFiles++
                    # Just log but continue
                    Write-PostLog "WARNING: Could not delete file: `$(`$item.FullName) - `$_"
                }
            }
        } else {
            Write-PostLog "Temp folder not found: `$folder"
        }
    }
    
    Write-PostLog "Temporary files cleanup completed: `$deletedFiles of `$totalFiles files deleted (`$errorFiles errors)"
} catch {
    Write-PostLog "WARNING: Error cleaning temporary files: `$_"
}

# Run NGEN optimization
try {
    Write-PostLog "Running NGEN.exe to optimize .NET Framework performance"
    
    # Get list of .NET Framework versions installed
    `$netFrameworkVersions = Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' | 
                           Where-Object { `$_.Name -match 'v[0-9]' }
    
    # Run NGEN for each version if available
    foreach(`$version in `$netFrameworkVersions) {
        `$versionName = `$version.PSChildName
        Write-PostLog "Optimizing .NET Framework `$versionName"
        
        # 32-bit NGEN
        if(Test-Path "`${env:SystemRoot}\Microsoft.NET\Framework\`$versionName") {
            `$ngenPath = "`${env:SystemRoot}\Microsoft.NET\Framework\`$versionName\ngen.exe"
            if(Test-Path `$ngenPath) {
                Write-PostLog "Running 32-bit NGEN: `$ngenPath executeQueuedItems"
                Start-Process -FilePath `$ngenPath -ArgumentList "executeQueuedItems" -Wait -NoNewWindow
            }
        }
        
        # 64-bit NGEN
        if(Test-Path "`${env:SystemRoot}\Microsoft.NET\Framework64\`$versionName") {
            `$ngenPath = "`${env:SystemRoot}\Microsoft.NET\Framework64\`$versionName\ngen.exe"
            if(Test-Path `$ngenPath) {
                Write-PostLog "Running 64-bit NGEN: `$ngenPath executeQueuedItems"
                Start-Process -FilePath `$ngenPath -ArgumentList "executeQueuedItems" -Wait -NoNewWindow
            }
        }
    }
    
    Write-PostLog "NGEN optimization completed successfully"
} catch {
    Write-PostLog "WARNING: Error running NGEN optimization: `$_"
}

# Finalize App Layer after NGEN optimization
try {

# Write completion marker
Write-PostLog "Post-reboot tasks completed successfully"

# Clean up by removing the scheduled task and this script
try {
    # Remove the scheduled task
    Unregister-ScheduledTask -TaskName "CitrixPlatformLayer_PostReboot" -Confirm:`$false -ErrorAction SilentlyContinue
    
    # Self-delete this script (delayed)
    `$selfDeleteScript = @"
Start-Sleep -Seconds 5
Remove-Item -Path "`$PSCommandPath" -Force
"@
    
    # Save and run the self-delete script
    `$selfDeletePath = "`$env:TEMP\selfdelete.ps1"
    `$selfDeleteScript | Out-File -FilePath `$selfDeletePath -Force
    Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -File `"`$selfDeletePath`"" -WindowStyle Hidden
    
} catch {
    Write-PostLog "WARNING: Error during cleanup: `$_"
}
"@

        # Save the script to a file
        $postRebootScriptPath = "C:\Scripts\CitrixPlatformLayer_PostReboot.ps1"
        $scriptFolder = Split-Path -Path $postRebootScriptPath -Parent
        if(!(Test-Path $scriptFolder)) {
            New-Item -ItemType Directory -Path $scriptFolder -Force | Out-Null
        }
        
        $postRebootScriptContent | Out-File -FilePath $postRebootScriptPath -Force -Encoding UTF8
        Write-Log "Created post-reboot script at: $postRebootScriptPath"
        
        # Create the scheduled task to run this script at startup
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$postRebootScriptPath`""
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        
        # Register the scheduled task
        Register-ScheduledTask -TaskName "CitrixPlatformLayer_PostReboot" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
        
        Write-Log "Registered scheduled task 'CitrixPlatformLayer_PostReboot' to run post-reboot tasks"
        
        # Notify that Stage 1 is complete and Stage 2 will run after reboot
        Write-Log "Stage 1 is complete. Stage 2 (NGEN optimization, temp file cleanup, event log clearing) will run after reboot."
        
    } catch {
        Write-Log "ERROR: Failed to create post-reboot tasks: $_"
    }
}

# Clear Event Logs - Moved to post-reboot tasks

# Run KMS Rearm if enabled
if($RedirectEventLogs) {
    try {
        Write-Log "Redirecting Event Logs to D:\EventLogs"
        
        # Create destination directory if it doesn't exist
        $eventLogPath = "D:\EventLogs"
        if(!(Test-Path -Path $eventLogPath)) {
            New-Item -Path $eventLogPath -ItemType Directory -Force | Out-Null
            Write-Log "Created Event Logs directory: $eventLogPath"
        }
        
        # Set appropriate permissions on the folder
        $acl = Get-Acl -Path $eventLogPath
        $systemAccount = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
        $adminGroup = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
        
        $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule($systemAccount, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule($adminGroup, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        
        $acl.AddAccessRule($systemRule)
        $acl.AddAccessRule($adminRule)
        Set-Acl -Path $eventLogPath -AclObject $acl
        
        # Get list of standard event logs
        $standardLogs = @("Application", "System", "Security", "Setup", "ForwardedEvents")
        
        # Stop Windows Event Log service to make changes
        Stop-Service -Name EventLog -Force
        
        # Redirect each log
        foreach($logName in $standardLogs) {
            $logFile = "$eventLogPath\$logName.evtx"
            try {
                # Set registry key to redirect the log
                $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\$logName"
                if(Test-Path $regPath) {
                    Write-Log "Redirecting $logName event log to $logFile"
                    Set-ItemProperty -Path $regPath -Name "File" -Value $logFile -Type String
                } else {
                    Write-Log "WARNING: Event log registry path not found: $regPath"
                }
            } catch {
                Write-Log "WARNING: Failed to redirect $logName event log: $_"
            }
        }
        
        # Restart the Event Log service
        Start-Service -Name EventLog
        Write-Log "Event Logs redirection complete"
        
    } catch {
        Write-Log "WARNING: Error redirecting event logs: $_"
        # Make sure Event Log service is running even if there was an error
        Start-Service -Name EventLog -ErrorAction SilentlyContinue
    }
}

# Run KMS Rearm if enabled
if($RearmKMS) {
    try {
        Write-Log "Rearming KMS licensing (slmgr /rearm)"
        $rearmProcess = Start-Process -FilePath "slmgr.vbs" -ArgumentList "/rearm" -Wait -PassThru -WindowStyle Hidden
        if($rearmProcess.ExitCode -eq 0) {
            Write-Log "KMS rearm completed successfully"
        } else {
            Write-Log "KMS rearm returned exit code: $($rearmProcess.ExitCode)"
        }
    } catch {
        Write-Log "WARNING: Error executing KMS rearm: $_"
    }
}

# Configure Citrix components for platform layer use
$postInstallTasks = @(
    # Apply recommended firewall rules
    { 
        Write-Log "Configuring firewall rules for Citrix VDA"
        Get-NetFirewallRule -DisplayGroup "Citrix Virtual Desktop Agent" | Enable-NetFirewallRule 
    },
    
    # Optimize service settings
    {
        Write-Log "Optimizing service settings"
        $servicesToOptimize = @{
            "BrokerAgent" = "Automatic"
            "CitrixTelemetryService" = "Disabled"  # Disable telemetry for platform layer
        }
        
        foreach($service in $servicesToOptimize.Keys) {
            Set-Service -Name $service -StartupType $servicesToOptimize[$service] -ErrorAction SilentlyContinue
        }
    },
    
    # Create marker file to indicate successful installation
    {
        Write-Log "Creating installation marker file"
        $markerContent = @"
Citrix components installed on: $(Get-Date)
Controllers: $ControllerAddress
"@
        
        if($InstallPVS) {
            $pvsMarkerContent = @"
PVS Target Device installed on: $(Get-Date)
PVS Boot Mode: $PVSBootMode
PVS Servers: $PVSServerAddress
"@
            $markerContent += "`n`n$pvsMarkerContent"
        }
        
        if($InstallWEM) {
            $wemMarkerContent = @"
WEM Agent installed on: $(Get-Date)
WEM Infrastructure Server: $WEMInfrastructureServer
WEM Agent Port: $WEMAgentPort
"@
            $markerContent += "`n`n$wemMarkerContent"
        }
        
        if($InstallUberAgent) {
            $uberAgentMarkerContent = @"
UberAgent installed on: $(Get-Date)
"@
            $markerContent += "`n`n$uberAgentMarkerContent"
        }
        
        if($RunOptimizer) {
            $optimizerMarkerContent = @"
Citrix Optimizer run on: $(Get-Date)
Optimizer Mode: $OptimizerMode
"@
            if(![string]::IsNullOrEmpty($OptimizerTemplatePath)) {
                $optimizerMarkerContent += "Optimizer Template: $OptimizerTemplatePath`n"
            }
            $markerContent += "`n`n$optimizerMarkerContent"
        }
        
        $markerContent | Out-File -FilePath "C:\Program Files\Citrix\PlatformLayer_Install.txt" -Force
        
        # Create a separate marker in VDA folder
        if(Test-Path "C:\Program Files\Citrix\Virtual Desktop Agent") {
            $markerContent | Out-File -FilePath "C:\Program Files\Citrix\Virtual Desktop Agent\VDA_PlatformLayer_Install.txt" -Force
        }
        
        # Create a separate marker in PVS folder
        if($InstallPVS -and (Test-Path "C:\Program Files\Citrix\Provisioning Services")) {
            $markerContent | Out-File -FilePath "C:\Program Files\Citrix\Provisioning Services\PVS_PlatformLayer_Install.txt" -Force
        }
        
        # Create a separate marker in WEM folder
        if($InstallWEM -and (Test-Path "C:\Program Files\Citrix\Workspace Environment Management Agent")) {
            $markerContent | Out-File -FilePath "C:\Program Files\Citrix\Workspace Environment Management Agent\WEM_PlatformLayer_Install.txt" -Force
        }
    }
)

# Execute post-installation tasks
foreach($task in $postInstallTasks) {
    try {
        & $task
    } catch {
        Write-Log "WARNING: Post-installation task failed: $_"
    }
}

# Re-enable Windows Update service after installation
Write-Log "Re-enabling Windows Update service"
Set-Service -Name wuauserv -StartupType Automatic
Start-Service -Name wuauserv

# Run NGEN optimization if enabled - must be run last after all other tasks
if($RunNGEN) {
    try {
        Write-Log "Running NGEN.exe to optimize .NET Framework performance"
        
        # Get list of .NET Framework versions installed
        $netFrameworkVersions = Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' | 
                               Where-Object { $_.Name -match 'v[0-9]' }
        
        # Run NGEN for each version if available
        foreach($version in $netFrameworkVersions) {
            $versionName = $version.PSChildName
            Write-Log "Optimizing .NET Framework $versionName"
            
            # 32-bit NGEN
            if(Test-Path "${env:SystemRoot}\Microsoft.NET\Framework\$versionName") {
                $ngenPath = "${env:SystemRoot}\Microsoft.NET\Framework\$versionName\ngen.exe"
                if(Test-Path $ngenPath) {
                    Write-Log "Running 32-bit NGEN: $ngenPath executeQueuedItems"
                    Start-Process -FilePath $ngenPath -ArgumentList "executeQueuedItems" -Wait -NoNewWindow
                }
            }
            
            # 64-bit NGEN
            if(Test-Path "${env:SystemRoot}\Microsoft.NET\Framework64\$versionName") {
                $ngenPath = "${env:SystemRoot}\Microsoft.NET\Framework64\$versionName\ngen.exe"
                if(Test-Path $ngenPath) {
                    Write-Log "Running 64-bit NGEN: $ngenPath executeQueuedItems"
                    Start-Process -FilePath $ngenPath -ArgumentList "executeQueuedItems" -Wait -NoNewWindow
                }
            }
        }
        
        Write-Log "NGEN optimization completed successfully"
    } catch {
        Write-Log "WARNING: Error running NGEN optimization: $_"
    }
}

Write-Log "Citrix platform layer installation script completed"
Write-Log "A reboot is recommended before capturing the layer"

# Output for user
Write-Host "`n----------------------------------------" -ForegroundColor Green
Write-Host "Citrix Platform Layer Installation" -ForegroundColor Green
Write-Host "----------------------------------------" -ForegroundColor Green
Write-Host "Status: Installation completed"
Write-Host "Components installed:"
Write-Host "  - Citrix VDA"
if($InstallPVS) {
    Write-Host "  - Citrix PVS Target Device Software"
}
if($InstallWEM) {
    Write-Host "  - Citrix WEM Agent"
}
if($InstallUberAgent) {
    Write-Host "  - UberAgent Monitoring Software"
}
if($RunOptimizer) {
    Write-Host "  - Citrix Optimizer ($OptimizerMode mode)"
}
Write-Host "Log path: $LogPath"
Write-Host "`nIMPORTANT: Reboot the system before finalizing the platform layer" -ForegroundColor Yellow
