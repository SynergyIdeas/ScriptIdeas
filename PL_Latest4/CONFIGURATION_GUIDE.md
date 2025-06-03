# Citrix PowerShell Suite - Configuration Guide

## Configuration File Overview

The `CitrixConfig.txt` file controls all aspects of the Citrix installation automation. This guide explains each configuration parameter and provides examples for different deployment scenarios.

## Configuration File Structure

### Installation Source Paths
Configure network locations using the base NetworkSourcePath for consistency:

```ini
# Base Network Source Path (all other paths derive from this)
NetworkSourcePath=\\fileserver\citrix

# Citrix VDA Installation
VDAISOSourcePath=%NetworkSourcePath%\installers\VDA\VDAServerSetup_2402.iso
VDASize=2048

# Provisioning Services
PVSISOSourcePath=%NetworkSourcePath%\installers\PVS\PVS_Server_x64_2402.iso

# Workspace Environment Management  
WEMPath=%NetworkSourcePath%\installers\WEM\Citrix_WEM_Agent_2402.msi

# UberAgent Monitoring
UberAgentPath=%NetworkSourcePath%\installers\UberAgent\uberAgent_7.0.0.msi

# Startup and Shutdown Scripts
StartupScriptsSourceWin2019=%NetworkSourcePath%\scripts\startup\win2019
StartupScriptsSourceWin2022=%NetworkSourcePath%\scripts\startup\win2022
ShutdownScriptsSourceWin2019=%NetworkSourcePath%\scripts\shutdown\win2019
ShutdownScriptsSourceWin2022=%NetworkSourcePath%\scripts\shutdown\win2022
```

### Feature Control Toggles
Enable or disable components based on deployment requirements:

```ini
# Core Components
InstallVDA=true
InstallPVS=true
InstallWEM=true
InstallUberAgent=false

# System Optimizations
EnableVDIOptimizations=true
EnableRegistryOptimizations=true
ConfigureCrashDumps=true

# Network Configuration
DisableNetBiosOverTCP=true
DisableNetworkOffload=true
ConfigureSMBSettings=true

# Security Features
ConfigureIBMTADDM=false
RemoveWEMRSAKeys=true
```

### System Configuration
Define system-level settings and behavior:

```ini
# Logging Configuration
EnableDesktopLogging=true
EnableVerboseLogging=true
LogRetentionDays=30

# System Settings
PagefileSizeGB=8192
OptimizeForVDI=true
DisableMaintenanceTasks=true

# Validation Configuration
ValidationMode=Enhanced
ContinueOnWarnings=true

# Domain Integration
EnableDomainJoin=true
DomainJoinOU=OU=Citrix,OU=Servers,DC=company,DC=com
```

## Network Path Configuration

### NetworkSourcePath Base Configuration
All network paths use the base NetworkSourcePath with variable substitution:

```ini
# Base Path Configuration
NetworkSourcePath=\\server\citrix

# Correct Format (using variable substitution)
VDAISOSourcePath=%NetworkSourcePath%\installers\VDA\VDAServerSetup.iso
StartupScriptsSourceWin2019=%NetworkSourcePath%\scripts\startup\win2019

# Alternative Direct Format (also supported)
VDAISOSourcePath=\\server\citrix\installers\VDA\VDAServerSetup.iso

# Incorrect Formats
VDAISOSourcePath=Z:\installers\VDA\VDAServerSetup.iso    # Mapped drive
VDAISOSourcePath=server\citrix\installers\VDA\file.iso   # Missing leading slashes
```

### File Share Requirements
- **Read Access**: Service account must have read permissions
- **Network Connectivity**: Target system must reach file shares
- **File Availability**: All specified files must exist at runtime

## Component-Specific Configuration

### Citrix Virtual Delivery Agent (VDA)
```ini
# Required Settings
VDAISOSourcePath=\\fileserver\citrix\VDAServerSetup_2402.iso
VDASize=2048
InstallVDA=true

# Optional VDA Features
EnableVDAOptimizations=true
ConfigureVDAServices=true
```

### Provisioning Services (PVS)
```ini
# PVS Target Device Installation
PVSISOSourcePath=\\fileserver\citrix\PVS_Server_x64_2402.iso
InstallPVS=true

# PVS Configuration
ConfigurePVSServices=true
EnablePVSOptimizations=true
```

### Workspace Environment Management (WEM)
```ini
# WEM Agent Installation
WEMInstallerSourcePath=\\fileserver\citrix\Citrix WEM Agent Setup.exe
InstallWEM=true

# WEM Configuration
RemoveWEMRSAKeys=true
ConfigureWEMServices=true
```

### UberAgent Monitoring
```ini
# UberAgent Installation (Optional)
UberAgentInstallerSourcePath=\\fileserver\monitoring\\uberAgent_7.1.0.msi
UberAgentConfigPath=\\fileserver\monitoring\uberAgent.conf
InstallUberAgent=true

# UberAgent Features
EnableUberAgentLogging=true
ConfigureUberAgentServices=true
```

### Startup and Shutdown Scripts
```ini
# OS-Specific Script Sources (Network Locations)
StartupScriptsSourceWin2019=\\fileserver\scripts\startup\win2019
StartupScriptsSourceWin2022=\\fileserver\scripts\startup\win2022
ShutdownScriptsSourceWin2019=\\fileserver\scripts\shutdown\win2019
ShutdownScriptsSourceWin2022=\\fileserver\scripts\shutdown\win2022

# Local Destination Paths (Fully Configurable)
StartupScriptsDestination=C:\Scripts\Startup
ShutdownScriptsDestination=C:\Scripts\Shutdown

# Alternative Destination Examples:
# StartupScriptsDestination=C:\Windows\System32\GroupPolicy\Machine\Scripts\Startup
# ShutdownScriptsDestination=C:\Windows\System32\GroupPolicy\Machine\Scripts\Shutdown
# StartupScriptsDestination=D:\Corporate\Scripts\Startup
# ShutdownScriptsDestination=D:\Corporate\Scripts\Shutdown
```

## Environment-Specific Examples

### Production Environment
```ini
# Production Network Base Path
NetworkSourcePath=\\prod-fileserver\citrix

# Production Citrix Deployment
VDAISOSourcePath=%NetworkSourcePath%\installers\VDA\VDAServerSetup_2402_LTSR.iso
PVSISOSourcePath=%NetworkSourcePath%\installers\PVS\PVS_Server_x64_2402_LTSR.iso
WEMPath=%NetworkSourcePath%\installers\WEM\Citrix_WEM_Agent_2402_LTSR.msi

# Production Optimizations
EnableVDIOptimizations=true
EnableRegistryOptimizations=true
ConfigureCrashDumps=true
DisableMaintenanceTasks=true

# Production Security
RemoveWEMRSAKeys=true
DisableNetBiosOverTCP=true
ConfigureIBMTADDM=true

# Production Script Management
StartupScriptsSourceWin2019=%NetworkSourcePath%\scripts\production\startup\2019
StartupScriptsSourceWin2022=%NetworkSourcePath%\scripts\production\startup\2022
ShutdownScriptsSourceWin2019=%NetworkSourcePath%\scripts\production\shutdown\2019
ShutdownScriptsSourceWin2022=%NetworkSourcePath%\scripts\production\shutdown\2022
StartupScriptsDestination=C:\Production\Scripts\Startup
ShutdownScriptsDestination=C:\Production\Scripts\Shutdown

# Domain Configuration
EnableDomainJoin=true
DomainJoinOU=OU=CitrixServers,OU=Production,DC=company,DC=com
```

### Test Environment
```ini
# Test Network Base Path
NetworkSourcePath=\\test-fileserver\citrix

# Test Citrix Deployment
VDAISOSourcePath=%NetworkSourcePath%\installers\VDA\VDAServerSetup_2402_CR.iso
PVSISOSourcePath=%NetworkSourcePath%\installers\PVS\PVS_Server_x64_2402_CR.iso
WEMPath=%NetworkSourcePath%\installers\WEM\Citrix_WEM_Agent_2402_CR.msi

# Test Environment Settings
EnableVDIOptimizations=false
EnableRegistryOptimizations=true
ConfigureCrashDumps=false

# Test Script Management
StartupScriptsSourceWin2019=%NetworkSourcePath%\scripts\test\startup\2019
StartupScriptsSourceWin2022=%NetworkSourcePath%\scripts\test\startup\2022
ShutdownScriptsSourceWin2019=%NetworkSourcePath%\scripts\test\shutdown\2019
ShutdownScriptsSourceWin2022=%NetworkSourcePath%\scripts\test\shutdown\2022
StartupScriptsDestination=C:\Test\Scripts\Startup
ShutdownScriptsDestination=C:\Test\Scripts\Shutdown

# Test Monitoring
InstallUberAgent=true
UberAgentPath=%NetworkSourcePath%\installers\UberAgent\uberAgent.msi
EnableVerboseLogging=true

# Domain Configuration
EnableDomainJoin=true
DomainJoinOU=OU=CitrixServers,OU=Test,DC=test,DC=company,DC=com
```

### Minimal Installation
```ini
# Minimal Network Base Path
NetworkSourcePath=\\fileserver\citrix

# Minimal VDA-Only Deployment
VDAISOSourcePath=%NetworkSourcePath%\installers\VDA\VDAServerSetup.iso
InstallVDA=true

# Disable Optional Components
InstallPVS=false
InstallWEM=false
InstallUberAgent=false

# Skip Script Management
StartupScriptsSourceWin2019=
StartupScriptsSourceWin2022=
ShutdownScriptsSourceWin2019=
ShutdownScriptsSourceWin2022=
StartupScriptsDestination=
ShutdownScriptsDestination=

# Basic Optimizations Only
EnableVDIOptimizations=true
EnableRegistryOptimizations=false
ConfigureCrashDumps=false

# Skip Domain Join
EnableDomainJoin=false
```

## Configuration Validation

### Pre-Deployment Checklist
Before running Stage 1, verify:

1. **Network Paths**: All UNC paths are accessible
2. **File Existence**: All specified installers exist
3. **Permissions**: Service account has read access
4. **Syntax**: Configuration file follows key=value format
5. **Boolean Values**: Use lowercase true/false only

### Common Configuration Errors
```ini
# Incorrect Boolean Values
InstallVDA=True    # Should be: InstallVDA=true
InstallPVS=1       # Should be: InstallPVS=true
InstallWEM=yes     # Should be: InstallWEM=true

# Incorrect Path Format
VDAISOSourcePath=Z:\citrix\VDA.iso              # Should use UNC path
VDAISOSourcePath=\\server\citrix\VDA.iso\       # Remove trailing slash
VDAISOSourcePath="\\server\citrix\VDA.iso"      # Remove quotes

# Missing Required Values
VDAISOSourcePath=                                # Must specify path
InstallVDA=                                      # Must specify true/false
```

## Dynamic Configuration Features

### Automatic Path Detection
If network paths are not accessible, the scripts will:
- Check for local copies in C:\temp
- Log path resolution attempts
- Provide fallback options
- Continue with available components

### Runtime Configuration Override
Configuration values can be modified during execution:
- Domain join credentials prompted at runtime
- Installation paths can be corrected during execution
- Component installation can be skipped on errors

### Configuration Persistence
Stage 1 saves runtime configuration to C:\temp\CitrixConfig.json for Stage 2:
- Installation results tracking
- Component status validation
- Error condition preservation
- System state information

## Security Considerations

### Credential Management
- Domain join credentials prompted at runtime (never stored)
- Service account permissions verified before execution
- Network path access validated during startup

### File Integrity
- Installation files validated before execution
- Digital signature verification where available
- File size validation for ISO images

### Network Security
- UNC path access only (no local credential storage)
- Network connectivity verification
- Secure file transfer validation

## Troubleshooting Configuration Issues

### Path Resolution Problems
```powershell
# Test network path connectivity
Test-Path "\\fileserver\citrix\VDAServerSetup.iso"

# Verify UNC path format
$path = "\\fileserver\citrix\VDAServerSetup.iso"
[System.IO.Path]::IsPathRooted($path)
```

### Permission Issues
```powershell
# Test file access permissions
Get-Acl "\\fileserver\citrix" | Format-List

# Verify current user context
whoami /all
```

### Configuration Syntax Validation
The scripts automatically validate configuration syntax and provide detailed error messages for:
- Missing required parameters
- Incorrect boolean values
- Invalid path formats
- Inaccessible network locations

## Best Practices

1. **Use Consistent Naming**: Follow standard UNC path conventions
2. **Test Connectivity**: Verify all paths before deployment
3. **Document Changes**: Track configuration modifications
4. **Version Control**: Maintain configuration file versions
5. **Security Review**: Regularly audit file share permissions
6. **Backup Configuration**: Keep copies of working configurations
7. **Environment Separation**: Use different configurations per environment

This configuration guide ensures successful deployment of the Citrix automation suite across various enterprise environments.