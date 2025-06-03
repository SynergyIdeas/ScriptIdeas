# Citrix App Layering PowerShell Automation Suite

Enterprise-grade PowerShell automation toolkit for Citrix App Layering platform deployments. Streamlines complex multi-stage installations with intelligent configuration management and comprehensive system optimization.

## Overview

This automation suite provides a complete solution for deploying Citrix Virtual Delivery Agent (VDA), Provisioning Services (PVS), Workspace Environment Management (WEM), and UberAgent in enterprise environments. Designed for fresh OS layer installations with zero server configuration dependencies.

## Key Features

### Multi-Stage Deployment Architecture
- **Stage 1**: Pre-reboot installation and system configuration
- **Stage 2**: Post-reboot verification and optimization
- Manual execution control for administrator oversight

### Enterprise Integration
- **Domain Join Automation**: Secure credential prompting with organizational unit support
- **Network-Based Installation**: ISO mounting and file copying from network shares
- **OS-Aware Script Management**: Automatic startup/shutdown script deployment
- **Comprehensive Logging**: Desktop-based logging with detailed diagnostic output

### Advanced System Management
- **VDI Optimizations**: Registry tweaks and performance enhancements
- **Service Configuration**: Citrix service management and validation
- **Memory Management**: VMware memory ballooning configuration
- **Terminal Server Licensing**: Grace period monitoring and configuration

### Security and Compliance
- **WEM RSA Key Cleanup**: Removes conflicting workspace management keys
- **IBM TADDM Permissions**: Enterprise monitoring tool integration
- **Crash Dump Configuration**: Kernel-mode crash dump optimization
- **Network Security**: NetBIOS over TCP/IP management

## File Structure

```
citrix_functions_library.psm1    # Core function library (45 functions)
citrix_stage1_script.ps1         # Pre-reboot installation script
citrix_stage2_script.ps1         # Post-reboot verification script
CitrixConfig.txt                 # Installation configuration file
```

## Quick Start

1. **Configure Installation Sources**
   ```
   Edit CitrixConfig.txt with your network paths:
   - VDA ISO location
   - PVS ISO location  
   - WEM installer path
   - UberAgent installer path
   ```

2. **Execute Stage 1**
   ```powershell
   # Run as Administrator
   .\citrix_stage1_script.ps1
   ```

3. **Reboot System**
   ```
   System will reboot automatically after Stage 1 completion
   ```

4. **Execute Stage 2**
   ```powershell
   # Navigate to C:\temp post-reboot
   # Run as Administrator
   .\citrix_stage2_script.ps1
   ```

## Configuration Management

The suite uses external configuration files for maximum flexibility:

- **Network Path Management**: All installation sources configurable
- **Boolean Feature Toggles**: Enable/disable components as needed
- **Environment Adaptation**: Automatic detection and configuration
- **Fallback Defaults**: Intelligent default values for missing configuration

## System Requirements

- **Operating System**: Windows Server 2016/2019/2022 or Windows 10/11
- **PowerShell**: Version 5.1 or higher
- **Privileges**: Administrator rights required
- **Network Access**: Connectivity to configured installation sources
- **Storage**: Minimum 10GB free space for temporary files

## Architecture Benefits

### Zero Server Dependencies
- No Citrix infrastructure servers required during installation
- Self-contained installation packages
- Network share-based source management

### Enterprise Scalability
- Template-based deployment for multiple systems
- Consistent configuration across environments
- Automated validation and reporting

### Operational Excellence
- Comprehensive error handling and recovery
- Detailed logging for troubleshooting
- Manual execution checkpoints for control

## Support and Documentation

Comprehensive logging provides detailed information for troubleshooting:
- Installation progress tracking
- Component validation results
- System optimization status
- Error details with resolution guidance

## License

Enterprise PowerShell automation suite for Citrix App Layering deployments.