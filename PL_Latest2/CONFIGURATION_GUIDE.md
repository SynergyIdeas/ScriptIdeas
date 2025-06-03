# Citrix PowerShell Suite - Configuration Guide

## Configuration File Overview

The `CitrixConfig.txt` file controls all aspects of the Citrix installation automation. This guide explains each configuration parameter and provides examples for different deployment scenarios.

## Configuration File Structure

### Installation Source Paths
Configure network locations for all installation components:

```ini
# Citrix VDA Installation
VDAISOSourcePath=\\fileserver\citrix\VDAServerSetup.iso
VDASize=2048

# Provisioning Services
PVSISOSourcePath=\\fileserver\citrix\PVS_Server_x64.iso

# Workspace Environment Management  
WEMInstallerSourcePath=\\fileserver\citrix\Citrix Workspace Environment Management Agent Setup.exe

# UberAgent Monitoring
UberAgentInstallerSourcePath=\\fileserver\monitoring\uberAgent.msi
UberAgentConfigPath=\\fileserver\monitoring\uberAgent.conf
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

# Performance Settings
PagefileSizeGB=8192
OptimizeForVDI=true
DisableMaintenanceTasks=true

# Domain Integration
EnableDomainJoin=true
DomainJoinOU=OU=Citrix,OU=Servers,DC=company,DC=com
```

## Network Path Configuration

### UNC Path Format
All network paths must use Universal Naming Convention (UNC) format:

```ini
# Correct Format
VDAISOSourcePath=\\server\share\folder\file.iso

# Incorrect Formats
VDAISOSourcePath=Z:\folder\file.iso          # Mapped drive
VDAISOSourcePath=server\share\folder\file.iso # Missing leading slashes
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
UberAgentInstallerSourcePath=\\fileserver\monitoring\uberAgent_7.1.0.msi
UberAgentConfigPath=\\fileserver\monitoring\uberAgent.conf
InstallUberAgent=true

# UberAgent Features
EnableUberAgentLogging=true
ConfigureUberAgentServices=true
```

## Environment-Specific Examples

### Production Environment
```ini
# Production Citrix Deployment
VDAISOSourcePath=\\prod-fileserver\citrix\VDAServerSetup_2402_LTSR.iso
PVSISOSourcePath=\\prod-fileserver\citrix\PVS_Server_x64_2402_LTSR.iso
WEMInstallerSourcePath=\\prod-fileserver\citrix\Citrix WEM Agent Setup.exe

# Production Optimizations
EnableVDIOptimizations=true
EnableRegistryOptimizations=true
ConfigureCrashDumps=true
DisableMaintenanceTasks=true

# Production Security
RemoveWEMRSAKeys=true
DisableNetBiosOverTCP=true
ConfigureIBMTADDM=true

# Domain Configuration
EnableDomainJoin=true
DomainJoinOU=OU=CitrixServers,OU=Production,DC=company,DC=com
```

### Test Environment
```ini
# Test Citrix Deployment
VDAISOSourcePath=\\test-fileserver\citrix\VDAServerSetup_2402_CR.iso
PVSISOSourcePath=\\test-fileserver\citrix\PVS_Server_x64_2402_CR.iso
WEMInstallerSourcePath=\\test-fileserver\citrix\Citrix WEM Agent Setup.exe

# Test Environment Settings
EnableVDIOptimizations=false
EnableRegistryOptimizations=true
ConfigureCrashDumps=false

# Test Monitoring
InstallUberAgent=true
UberAgentInstallerSourcePath=\\test-fileserver\monitoring\uberAgent.msi
EnableVerboseLogging=true

# Domain Configuration
EnableDomainJoin=true
DomainJoinOU=OU=CitrixServers,OU=Test,DC=test,DC=company,DC=com
```

### Minimal Installation
```ini
# Minimal VDA-Only Deployment
VDAISOSourcePath=\\fileserver\citrix\VDAServerSetup.iso
InstallVDA=true

# Disable Optional Components
InstallPVS=false
InstallWEM=false
InstallUberAgent=false

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