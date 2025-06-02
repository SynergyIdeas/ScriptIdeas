# Citrix PowerShell Script Suite - Configuration Guide

## Overview
All hardcoded values have been moved to `CitrixConfig.txt` for easy customization without modifying the PowerShell scripts.

## Configuration File: CitrixConfig.txt

### Key Features
- **Centralized Configuration**: All paths, domain settings, and parameters in one file
- **Easy Customization**: Simple key=value format
- **Environment Flexibility**: Adapt to any environment by editing the config file
- **Default Fallbacks**: Scripts use sensible defaults if config values are missing

### Configuration Categories

#### Network Configuration
```
NetworkSourcePath=\\fileserver\citrix\installers
LocalInstallPath=C:\Temp
StartupScriptsSource=\\fileserver\scripts\startup
StartupScriptsDestination=C:\Scripts\Startup
```

#### Domain Configuration
```
DomainName=company.local
DomainJoinOU=OU=Citrix,OU=Servers,DC=company,DC=local
DomainJoinUsername=administrator@company.local
```

#### DNS Configuration
```
PrimaryDNSSuffix=company.local
DNSSuffixSearchList=company.local,corp.company.com,company.com
```

#### Installation Paths
```
VDAInstallerPath=C:\Temp\VDAServerSetup.exe
PVSInstallerPath=C:\Temp\PVS_Agent.msi
WEMInstallerPath=C:\Temp\Citrix_WEM_Agent.msi
UberAgentInstallerPath=C:\Temp\uberAgent.msi
```

#### Logging Configuration
```
LogPath=%USERPROFILE%\Desktop\CitrixInstallation.log
ReportPath=%USERPROFILE%\Desktop\CitrixInstallationReport.txt
```

#### Citrix Optimizer Configuration
```
CitrixOptimizerPath=C:\Temp\CitrixOptimizer.exe
CitrixOptimizerSourceFolder=C:\Temp\CitrixOptimizer
CitrixOptimizerTemplate=Windows_10_VDI.xml
RunCitrixOptimizer=true
```

#### Citrix Services Management
```
DisableCitrixServices=true
CitrixServicesToDisable=BrokerAgent,CitrixCloudServicesAgent,CitrixTelemetryService,CitrixConfigSyncService,CitrixHighAvailabilityService
```

#### Event Logs Configuration
```
ConfigureEventLogs=true
EventLogsLocation=D:\Logs\EventLogs
EventLogsMaxSizeMB=512
EventLogsToRelocate=Application,System,Security,Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
```

#### SMB Optimization Values
```
MaxWorkItems=2000
MaxMpxCt=800
MaxRawWorkItems=200
MaxFreeConnections=64
MinFreeConnections=20
```

#### Network Optimization Settings
```
DisableNetBIOS=true
DisableNetworkOffload=true
ConfigureSMB=true
EnableMultiChannel=true
```

## Functions Using Configuration

### Updated Functions
1. **Read-ConfigFile**: Loads and parses the configuration file with environment variable expansion
2. **Get-ConfigValue**: Retrieves configuration values with fallback defaults
3. **Get-DesktopLogPath**: Determines user's desktop path for log file creation
4. **Initialize-InstallConfig**: Now uses config file for all settings
5. **Configure-SMBSettings**: Uses configurable SMB parameters
6. **Copy-StartupScripts**: Uses configurable source/destination paths
7. **Copy-InstallationFiles**: Uses configurable network and local paths
8. **Invoke-CitrixOptimizer**: Executes Citrix Optimizer with configurable templates
9. **Disable-CitrixServices**: Manages Citrix services based on configuration
10. **Configure-EventLogs**: Relocates event logs to configurable locations
11. **Disable-NetBiosOverTCP**: Network optimization with configuration control
12. **Disable-NetworkOffloadParameters**: PVS-specific network optimizations
13. **Set-DNSSuffix**: DNS configuration management
14. **Join-Domain**: Domain joining with configurable parameters

### Configuration Loading Process
1. Scripts automatically load `CitrixConfig.txt` at startup
2. Missing config file triggers warning but continues with defaults
3. Individual missing keys use default values with warnings
4. Boolean and numeric values are automatically converted

## Usage Instructions

### Before Running Scripts
1. **Edit CitrixConfig.txt** with your environment values:
   - Update domain names and DNS suffixes
   - Set correct network paths for installers
   - Configure SMB optimization parameters
   - Specify organizational unit for domain join
   - Set Citrix Optimizer template and execution preference
   - Configure logging paths (defaults to user's desktop)
   - Specify services to disable and event log settings

2. **Verify Paths**: Ensure all file paths in the config exist and are accessible

3. **Download Required Software**:
   - Citrix VDA installer
   - PVS Agent installer  
   - Citrix WEM Agent installer
   - UberAgent installer (optional)
   - Citrix Optimizer tool and templates

4. **Test Configuration**: Run scripts with `-WhatIf` if available or in test environment

### Example Customization
```
# Production Environment
DomainName=prod.company.com
NetworkSourcePath=\\prod-fileserver\citrix\installers
PrimaryDNSSuffix=prod.company.com

# Development Environment  
DomainName=dev.company.local
NetworkSourcePath=\\dev-fileserver\citrix\installers
PrimaryDNSSuffix=dev.company.local
```

## Benefits

### Flexibility
- No script modification required for different environments
- Easy A/B testing with different configurations
- Simplified deployment across multiple sites

### Maintenance
- Single file to update for environment changes
- Version control friendly configuration management
- Clear separation of code and configuration

### Security
- Credentials and sensitive paths externalized
- Configuration can be secured separately from scripts
- Environment-specific settings isolated

## Migration from Hardcoded Values

### What Changed
- All hardcoded paths moved to config file
- Domain and DNS settings externalized  
- SMB parameters made configurable
- Installation paths standardized
- Desktop-based logging system implemented
- Citrix Optimizer integration added
- Service management externalized
- Event log configuration made flexible
- Network optimizations made configurable

### New Enterprise Features
- **Desktop Logging**: Log files automatically created on user's desktop
- **Citrix Optimizer**: Automated optimization with configurable templates
- **Service Management**: Selective disabling of unnecessary Citrix services
- **Event Log Relocation**: Configurable event log location and size management
- **Network Optimizations**: NetBIOS disabling and network offload parameter tuning
- **PVS Target Preparation**: Specialized optimizations for PVS environments

### Backward Compatibility
- Scripts work without config file (uses defaults)
- Existing functionality preserved
- Enhanced with configuration flexibility
- All new features can be disabled via configuration

## Best Practices

### Configuration Management
1. **Version Control**: Store config files in version control
2. **Environment Separation**: Use different config files per environment  
3. **Documentation**: Comment configuration values for clarity
4. **Validation**: Test configurations before production deployment

### Security Considerations
1. **File Permissions**: Secure config file with appropriate ACLs
2. **Credential Management**: Use service accounts for domain operations
3. **Network Security**: Ensure SMB paths are properly secured
4. **Audit Trail**: Log configuration changes and usage

The configuration system provides enterprise-grade flexibility while maintaining the robust functionality of the PowerShell script suite.