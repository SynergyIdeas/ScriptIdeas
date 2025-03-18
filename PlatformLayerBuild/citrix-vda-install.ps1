# Citrix Platform Layer Installation Script
# This script automates the installation of Citrix Virtual Delivery Agent (VDA), Provisioning Services (PVS) Target Device software,
# Workspace Environment Management (WEM) Agent, and runs Citrix Optimizer for use in a platform layer
# Usage: Run as administrator in PowerShell

# Define parameters
param(
    [string]$VDAInstallerPath = ".\VDAServerSetup.exe",
    [string]$PVSInstallerPath = ".\PVS_Device.exe",
    [string]$WEMAgentInstallerPath = ".\Citrix Workspace Environment Management Agent.exe",
    [string]$CitrixOptimizerPath = ".\CtxOptimizerEngine.ps1",
    [string]$OptimizerTemplatePath = "",  # If empty, will use the built-in templates
    [string]$LogPath = "C:\Logs\Citrix_Install",
    [string]$ControllerAddress,
    [string]$PVSServerAddress,
    [string]$WEMInfrastructureServer,
    [int]$WEMAgentPort = 8286,
    [switch]$InstallPVS = $true,
    [switch]$InstallWEM = $true,
    [switch]$RunOptimizer = $true,
    [string]$OptimizerMode = "Execute",  # Options: "Analyze", "Execute", "ExecuteForce", "Rollback"
    [string]$PVSBootMode = "VM-AUTO", # Options: "VM-AUTO", "VM-STATIC", "VM-DHCP"
    [switch]$EnableRemoteAssistance = $true,
    [switch]$OptimizeForLayering = $true,
    [switch]$IncludeAdditionalComponents = $true,
    [string]$AdditionalComponents = "VDA_PLUGINS,PERSONALIZATION,USB_REDIRECTION",
    [string]$VDAInstallMode = "Server",  # "Server" or "Workstation"
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

# Check if Delivery Controller is specified
if([string]::IsNullOrEmpty($ControllerAddress)) {
    $ControllerAddress = Read-Host "Enter Delivery Controller address (comma-separated for multiple)"
}

# Check if PVS Server is specified when installing PVS
if($InstallPVS -and [string]::IsNullOrEmpty($PVSServerAddress)) {
    $PVSServerAddress = Read-Host "Enter PVS Server address (comma-separated for multiple)"
}

# Check if WEM Infrastructure Server is specified when installing WEM Agent
if($InstallWEM -and [string]::IsNullOrEmpty($WEMInfrastructureServer)) {
    $WEMInfrastructureServer = Read-Host "Enter WEM Infrastructure Server address"
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
if($EnableRemoteAssistance) {
    $installArgs += "/enable_remote_assistance"
}

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

# Re-enable Windows Update service after installation
Write-Log "Re-enabling Windows Update service"
Set-Service -Name wuauserv -StartupType Automatic
Start-Service -Name wuauserv

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
VDA Installation mode: $VDAInstallMode
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
if($RunOptimizer) {
    Write-Host "  - Citrix Optimizer ($OptimizerMode mode)"
}
Write-Host "Log path: $LogPath"
Write-Host "`nIMPORTANT: Reboot the system before finalizing the platform layer" -ForegroundColor Yellow
