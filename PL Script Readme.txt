PowerShell script automates the installation of a Citrix VDA (Virtual Delivery Agent) for use in a platform layer. Key features include:

Customizable installation with parameters for controller address, installation mode, and component selection
Optimizations specifically for platform layering environments
Registry tweaks to ensure proper functioning in a layered environment
Automatic logging to track the installation process
Post-installation tasks to configure firewall rules and service settings
Support for both server and workstation VDA types

To use the script:

Download the Citrix VDA installer
Run the script as Administrator in PowerShell
Provide the Delivery Controller address(es) when prompted or as a parameter
Reboot the system after installation before finalizing the platform layer

You can customize the installation by modifying the parameters at the top of the script to match the environment.

Updated the script to add the functionality to install Citrix Provisioning Server (PVS) target device software to the VDA Platform Layer Installation 

New Parameters:

$PVSInstallerPath: Path to the PVS target device installer
$PVSServerAddress: Address of your PVS server(s)
$InstallPVS: Switch to enable/disable PVS installation
$PVSBootMode: Boot mode for the PVS device (VM-AUTO, VM-STATIC, or VM-DHCP)

PVS Installation Section:

Added validation for the PVS installer path
Created a dedicated section to install the PVS target device software
Added PVS-specific command-line arguments for silent installation

PVS Optimization:

Added registry tweaks specifically for PVS in a layered environment
Configured optimal network and boot settings for virtual environments

Documentation and Logging:

Updated logs to include PVS installation details
Added PVS-specific markers to identify successful installation
Enhanced console output to show all installed components

Updated the script to include the installation of the Citrix Workspace Environment Management (WEM) agent alongside the VDA and PVS target device software. Here's what I've added:

New WEM-Specific Parameters:

$WEMAgentInstallerPath: Path to the WEM agent installer
$WEMInfrastructureServer: Address of your WEM infrastructure server
$WEMAgentPort: Port for the WEM agent (default: 8286)
$InstallWEM: Switch to enable/disable WEM agent installation


WEM Agent Installation Section:

Added validation for the WEM agent installer path
Created an XML answer file for unattended installation
Added WEM-specific installation arguments for silent deployment
Implemented error handling and logging for the WEM agent installation


WEM Agent Optimization:

Added registry tweaks specifically for WEM in a layered environment
Configured the WEM agent service to start automatically
Applied performance optimizations for virtual environments


Documentation Updates:

Updated logs to include WEM agent installation details
Added WEM-specific markers to identify successful installation
Enhanced console output to show all installed components

To use the script with all three components, you would run it like this:

powershellCopy.\CitrixPlatformLayer.ps1 -VDAInstallerPath "C:\Install\VDAServerSetup.exe" `
  -PVSInstallerPath "C:\Install\PVS_Device.exe" `
  -WEMAgentInstallerPath "C:\Install\Citrix Workspace Environment Management Agent.exe" `
  -ControllerAddress "ddc01.domain.local" `
  -PVSServerAddress "pvs01.domain.local" `
  -WEMInfrastructureServer "wem01.domain.local" `
  -InstallPVS -InstallWEM

The script will now handle all three Citrix components (VDA, PVS, and WEM) in the correct order and apply the appropriate optimizations for a platform layer environment. 
You can also selectively enable or disable any of the components using the -InstallPVS and -InstallWEM switches.

Added the Citrix Optimizer as the final step in the installation process. This addition provides comprehensive optimization specifically for Citrix environments.

New Citrix Optimizer Parameters:

$CitrixOptimizerPath: Path to the Citrix Optimizer PowerShell script (CtxOptimizerEngine.ps1)
$OptimizerTemplatePath: Optional path to a custom optimization template
$RunOptimizer: Switch to enable/disable running the optimizer
$OptimizerMode: Mode for the optimizer (Analyze, Execute, ExecuteForce, or Rollback)


Optimizer Execution Features:

Automatic OS detection to select the appropriate optimization template
Support for Windows 10/11 and Windows Server 2016/2019/2022
Detailed logging of optimization results
Parameter handling for different optimization scenarios


Intelligent Template Selection:

The script will automatically detect your OS version (Server versions)
It selects the appropriate built-in template if no custom template is specified
Logs the template selection for reference


Documentation and Reporting:

Adds optimizer information to the installation marker files
Updates console output to show optimizer execution details
Saves optimization results to a standard location for reference

To use the script with all components including the optimizer, run it like this:
powershellCopy.\CitrixPlatformLayer.ps1 `
  -VDAInstallerPath "C:\Install\VDAServerSetup.exe" `
  -PVSInstallerPath "C:\Install\PVS_Device.exe" `
  -WEMAgentInstallerPath "C:\Install\Citrix Workspace Environment Management Agent.exe" `
  -CitrixOptimizerPath "C:\Install\CtxOptimizerEngine.ps1" `
  -ControllerAddress "ddc01.domain.local" `
  -PVSServerAddress "pvs01.domain.local" `
  -WEMInfrastructureServer "wem01.domain.local" `
  -InstallPVS -InstallWEM -RunOptimizer -OptimizerMode "Execute"

You can also specify a custom template if needed:
powershell Copy.\CitrixPlatformLayer.ps1 ... -OptimizerTemplatePath "C:\Templates\CustomOptimization.xml"