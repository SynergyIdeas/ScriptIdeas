# Citrix PowerShell Installation Suite - Configuration & Usage Guide

## Overview

This PowerShell automation suite provides enterprise-grade installation and configuration for Citrix Virtual Delivery Agent (VDA), Provisioning Services (PVS), and Workspace Environment Management (WEM) components. The scripts feature automatic file copying from network sources, ISO-based installations, comprehensive system optimization, and complete post-installation verification.

## Key Features

- **Automated Network File Transfer**: Copies installation files from network sources to local directories
- **ISO-Based Installation Workflow**: Mounts ISOs, executes installations, and automatically unmounts
- **No Server Dependencies**: Installs components without requiring delivery controllers, PVS servers, or WEM infrastructure
- **Enterprise System Optimization**: Applies VDI-specific optimizations and performance tuning
- **Comprehensive Verification**: Stage 2 post-reboot validation ensures successful deployment
- **Enhanced Error Handling**: Detailed logging and robust error recovery mechanisms

---

## Installation Files Required

### Network Source Locations
Place the following files on your network file server:

```
\\fileserver\citrix\installers\
├── VDA_Server.iso          (Citrix Virtual Delivery Agent ISO)
├── PVS_Agent.iso           (Provisioning Services Target Device ISO)
├── Citrix_WEM_Agent.msi    (Workspace Environment Management Agent)
├── uberAgent.msi           (Optional: UberAgent monitoring)
├── VC_redist.x64.exe       (Visual C++ Redistributable)
└── ndp48-x86-x64-allos-enu.exe (.NET Framework 4.8)
```

### Script Directories
Configure network locations for startup/shutdown scripts:

```
\\fileserver\scripts\
├── startup\                (Startup scripts to copy)
└── shutdown\               (Shutdown scripts to copy)
```

---

## Configuration Setup

### 1. Edit CitrixConfig.txt

The main configuration file controls all installation parameters. Key sections to configure:

#### Network Sources
```ini
# Source Installation Files (Network Locations)
VDAISOSourcePath=\\fileserver\citrix\installers\VDA_Server.iso
PVSISOSourcePath=\\fileserver\citrix\installers\PVS_Agent.iso
WEMInstallerSourcePath=\\fileserver\citrix\installers\Citrix_WEM_Agent.msi

# Network Paths
NetworkSourcePath=\\fileserver\citrix\installers
StartupScriptsSource=\\fileserver\scripts\startup
ShutdownScriptsSource=\\fileserver\scripts\shutdown
```

#### Local Destinations
```ini
# Destination Paths (Local Copy Locations)
VDAISOPath=C:\Temp\VDA_Server.iso
PVSISOPath=C:\Temp\PVS_Agent.iso
WEMInstallerPath=C:\Temp\Citrix_WEM_Agent.msi
LocalInstallPath=C:\Temp
StartupScriptsDestination=C:\Scripts\Startup
ShutdownScriptsDestination=C:\Scripts\Shutdown
```

#### Domain Configuration
```ini
# Domain Settings
DomainName=company.local
DomainJoinOU=OU=Citrix,OU=Servers,DC=company,DC=local
PrimaryDNSSuffix=company.local
DNSSuffixSearchList=company.local,corp.company.com,company.com
```

#### Performance Optimization
```ini
# SMB Performance Parameters
MaxWorkItems=2000
MaxMpxCt=800
MaxRawWorkItems=200
MaxFreeConnections=64
MinFreeConnections=20

# System Configuration
PagefileSizeGB=8
DisableNetBIOS=true
ConfigureSMB=true
OptimizeServices=true
```

### 2. Component Selection

Configure which components to install by setting the appropriate source paths:

- **VDA (Required)**: Always installed - set `VDAISOSourcePath`
- **PVS (Optional)**: Set `PVSISOSourcePath` if using Provisioning Services
- **WEM (Optional)**: Set `WEMInstallerSourcePath` if using Workspace Environment Management
- **UberAgent (Optional)**: Set `UberAgentInstallerPath` for monitoring

---

## Execution Guide

### Prerequisites

1. **Administrative Privileges**: Scripts must run as Administrator
2. **Network Access**: Ensure connectivity to source file locations
3. **PowerShell Execution Policy**: Set to allow script execution
4. **Available Disk Space**: Minimum 2GB free space in C:\Temp

### Running the Installation

#### Step 1: Prepare Environment
```powershell
# Set execution policy (if needed)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine

# Ensure C:\Temp directory exists
if (!(Test-Path "C:\Temp")) { New-Item -Path "C:\Temp" -ItemType Directory -Force }
```

#### Step 2: Execute Stage 1 Installation
```powershell
# Run from elevated PowerShell prompt
.\citrix_stage1_script.ps1
```

**Stage 1 Process:**
1. Validates configuration and prerequisites
2. Copies installation files from network sources to C:\Temp
3. Applies system optimizations and VDI tuning
4. Installs VDA, PVS, and WEM components from ISOs/MSI files
5. Configures startup/shutdown scripts
6. Schedules Stage 2 for post-reboot execution
7. Initiates system reboot

#### Step 3: Automatic Stage 2 Execution
After reboot, Stage 2 runs automatically and performs:
1. Post-installation verification
2. Service status validation
3. System integrity checks
4. Performance testing
5. Final readiness assessment
6. Comprehensive reporting

---

## Installation Workflow Detail

### File Copy Process
1. **Network Validation**: Verifies source files exist and are accessible
2. **Local Directory Creation**: Creates destination directories if needed
3. **Robocopy Transfer**: Uses Robocopy for reliable network file copying with retry logic
4. **Integrity Verification**: Validates file size matches after copy
5. **Fallback Mechanism**: Uses PowerShell Copy-Item if Robocopy fails

### ISO Installation Process
1. **ISO Mounting**: Mounts ISO files to available drive letters
2. **Installer Discovery**: Locates installation executables on mounted drives
3. **Silent Installation**: Executes installers with appropriate silent parameters
4. **Exit Code Analysis**: Interprets installation results and reboot requirements
5. **Automatic Cleanup**: Unmounts ISOs and removes temporary files

### System Optimization
Applied optimizations include:
- **SMB Performance Tuning**: MaxWorkItems, MaxMpxCt, MaxRawWorkItems settings
- **Service Optimization**: Disables unnecessary services for VDI environments
- **Network Configuration**: NetBIOS disabling, offload parameter optimization
- **Firewall Configuration**: Opens required Citrix ports
- **Registry Optimizations**: Performance and stability improvements
- **VDI-Specific Tuning**: Pagefile, crash dump, and memory optimizations

---

## Logging and Monitoring

### Log File Locations
- **Installation Log**: `%USERPROFILE%\Desktop\CitrixInstallation.log`
- **Final Report**: `%USERPROFILE%\Desktop\CitrixInstallationReport.txt`
- **Component Logs**: `C:\Logs\` (individual component installation logs)

### Log Contents
- Detailed step-by-step installation progress
- Configuration validation results
- Error messages and troubleshooting information
- Performance test results
- System readiness assessment
- Final deployment status

---

## Troubleshooting

### Common Issues

#### Network File Access
- **Issue**: Cannot access source files on network share
- **Solution**: Verify network connectivity, check file server availability, ensure proper permissions

#### ISO Mounting Failures
- **Issue**: Unable to mount ISO files
- **Solution**: Verify ISO file integrity, check available drive letters, ensure sufficient disk space

#### Installation Failures
- **Issue**: Component installation returns error codes
- **Solution**: Check component-specific logs in C:\Logs\, verify prerequisites, review system requirements

#### Domain Join Issues
- **Issue**: Cannot join domain during installation
- **Solution**: Domain credentials are prompted during execution - provide valid domain admin credentials when requested

### Validation Modes
- **Strict Mode**: Stops installation on any validation failures
- **Permissive Mode**: Continues installation with warnings logged
- **Validation Only**: Performs checks without installation

### Manual Recovery
If installation fails:
1. Review logs in `%USERPROFILE%\Desktop\CitrixInstallation.log`
2. Check Windows Event Logs for system errors
3. Manually run Stage 2 script if reboot occurred: `.\citrix_stage2_script.ps1`
4. Use validation mode to identify specific issues: Add `ValidationMode=ValidationOnly` to config

---

## Post-Installation Configuration

### Required Manual Steps
After successful installation, complete these tasks:

1. **Delivery Controller Registration**: Configure VDA to communicate with Citrix Cloud or on-premises delivery controllers via Group Policy
2. **PVS Configuration**: Configure target device settings if PVS was installed
3. **WEM Policy Assignment**: Assign WEM policies via Citrix Cloud or WEM Infrastructure Server
4. **User Profile Management**: Configure Citrix Profile Management settings
5. **Published Applications**: Configure and publish applications as needed

### Group Policy Configuration
Key Group Policy settings to configure post-installation:
- Citrix Virtual Delivery Agent settings
- Profile Management configuration
- Session sharing and HDX policies
- Printer redirection settings
- Drive mapping policies

---

## Security Considerations

- **Credential Management**: Domain credentials are prompted during execution rather than stored in configuration files
- **Network Security**: Uses authenticated network shares for file access
- **Service Security**: Applies security-hardened service configurations
- **Registry Security**: Implements secure registry settings for VDI environments

---

## Support and Maintenance

### Regular Maintenance
- Monitor log files for installation warnings or errors
- Verify component functionality after Windows updates
- Update installation source files when new Citrix versions are released
- Review and update optimization settings as needed

### Version Compatibility
This script suite is designed for:
- Windows Server 2019/2022
- Citrix Virtual Apps and Desktops 7.x
- Current Long Term Service Release (LTSR) versions

For the latest updates and support information, refer to Citrix documentation and knowledge base articles.