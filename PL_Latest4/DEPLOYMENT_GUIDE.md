# Citrix PowerShell Suite - Deployment Guide

## Pre-Deployment Preparation

### System Requirements Verification
Before deployment, ensure the target system meets these requirements:

**Operating System**
- Windows Server 2016, 2019, or 2022
- Windows 10/11 Enterprise (for VDI deployments)
- PowerShell 5.1 or higher
- .NET Framework 4.7.2 or higher

**System Resources**
- Minimum 8GB RAM (16GB recommended)
- 50GB free disk space
- Network connectivity to file shares
- Administrator privileges

**Network Prerequisites**
- Domain network connectivity
- Access to Citrix installation file shares
- DNS resolution for domain controllers
- Firewall rules for Citrix services

### File Share Preparation
Organize installation files on your network share:

```
\\fileserver\citrix\
├── VDAServerSetup_2402.iso
├── PVS_Server_x64_2402.iso
├── Citrix WEM Agent Setup.exe
└── monitoring\
    ├── uberAgent.msi
    └── uberAgent.conf
```

### Configuration Setup
1. Copy all PowerShell files to deployment location
2. Edit `CitrixConfig.txt` with your environment paths
3. Verify network path accessibility
4. Test file share permissions

## Stage 1 Deployment

### Execution Steps
1. **Copy Files to Target System**
   ```powershell
   # Copy entire suite to target system
   Copy-Item "\\deployment\citrix\*" -Destination "C:\CitrixInstall\" -Recurse
   ```

2. **Open PowerShell as Administrator**
   ```powershell
   # Navigate to installation directory
   Set-Location "C:\CitrixInstall"
   
   # Execution policy is set automatically by the scripts
   ```

3. **Execute Stage 1 Script**
   ```powershell
   # Run the installation script
   .\citrix_stage1_script.ps1
   ```

### Stage 1 Process Flow
The script will automatically perform these actions:

**System Preparation**
- Initialize logging to desktop
- Validate system requirements
- Check network connectivity
- Load configuration settings

**Component Installation**
- Mount and install Citrix VDA
- Install PVS Target Device
- Install WEM Agent
- Install UberAgent (if configured)

**System Configuration**
- Apply VDI optimizations
- Configure Windows services
- Set registry optimizations
- Copy startup/shutdown scripts

**Domain Integration**
- Prompt for domain credentials
- Join system to domain
- Configure organizational unit placement

**Pre-Reboot Preparation**
- Copy Stage 2 files to C:\temp
- Save installation configuration
- Create execution instructions
- Prepare system for reboot

### Expected Stage 1 Output
```
Citrix App Layering Installation - Stage 1
==========================================

System Information:
- Operating System: Windows Server 2019
- Total Memory: 16 GB
- Available Disk Space: 120 GB
- PowerShell Version: 5.1

Configuration Loading:
✓ Configuration file loaded successfully
✓ Network paths validated
✓ Installation sources accessible

Component Installation:
✓ Citrix VDA installed successfully
✓ PVS Target Device installed
✓ WEM Agent installed
✓ UberAgent installation skipped

System Configuration:
✓ VDI optimizations applied
✓ Registry optimizations configured
✓ Windows services configured
✓ Startup scripts deployed

Domain Join:
✓ Successfully joined to domain: company.com
✓ Computer placed in OU: OU=CitrixServers,DC=company,DC=com

Stage 2 Preparation:
✓ Files copied to C:\temp
✓ Configuration saved
✓ Instructions created

STAGE 1 COMPLETED SUCCESSFULLY
==============================
System will reboot in 30 seconds...
Press any key to reboot immediately
```

## System Reboot

After Stage 1 completion:
1. System reboots automatically
2. Domain join takes effect
3. Services initialize with new configuration
4. Stage 2 files available in C:\temp

## Stage 2 Deployment

### Post-Reboot Execution
1. **Login to Domain**
   - Use domain administrator account
   - Verify domain join successful
   - Confirm network connectivity

2. **Navigate to Temp Directory**
   ```powershell
   # Open PowerShell as Administrator
   Set-Location "C:\temp"
   
   # Verify files present
   Get-ChildItem
   ```

3. **Execute Stage 2 Script**
   ```powershell
   # Run verification and optimization script
   .\citrix_stage2_script.ps1
   ```

### Stage 2 Process Flow
The script performs comprehensive verification:

**System Validation**
- Load Stage 1 configuration
- Verify component installations
- Check service status
- Validate domain membership

**Service Verification**
- Test Citrix services
- Verify service registration
- Check automatic startup configuration
- Validate service dependencies

**Optimization Verification**
- Confirm VDI optimizations active
- Verify registry modifications
- Check performance settings
- Validate memory configuration

**Advanced Verification**
- Test automatic maintenance status
- Verify VMware memory ballooning
- Check Terminal Server licensing
- Validate system readiness

**Cleanup Operations**
- Remove domain user profiles from OS layer (C:\Users and D:\Users)
- Remove WEM RSA keys
- Clean temporary files
- Optimize crash dump settings
- Finalize configuration

### Expected Stage 2 Output
```
Citrix App Layering Installation - Stage 2
==========================================

Post-Reboot Verification Started: 2024-06-03 14:30:00

Configuration Loading:
✓ Stage 1 configuration loaded
✓ Installation results validated
✓ System state verified

Component Verification:
✓ Citrix VDA: Installed and running
✓ PVS Target Device: Configured
✓ WEM Agent: Active
✓ UberAgent: Not installed (as configured)

Service Status:
✓ 15 Citrix services found and running
✓ All services configured for automatic startup
✓ Service dependencies verified
✓ Registration status confirmed

System Optimizations:
✓ VDI optimizations: Applied and active
✓ Registry optimizations: Verified
✓ Memory management: Configured
✓ Performance settings: Optimized

Advanced Verification:
✓ Automatic maintenance: Disabled
✓ VMware memory ballooning: Disabled
✓ Terminal Server licensing: Grace period active
✓ System readiness: 95% (Excellent)

Cleanup Operations:
✓ WEM RSA keys removed
✓ Temporary files cleaned
✓ System configuration finalized

STAGE 2 COMPLETED SUCCESSFULLY
==============================
System is ready for production use
Readiness Score: 95% (Excellent)
Total Installation Time: 45 minutes

Final Report saved to: C:\Users\Administrator\Desktop\CitrixInstall-FinalReport.txt
```

## Post-Deployment Verification

### Manual Verification Steps
1. **Service Verification**
   ```powershell
   # Check Citrix services
   Get-Service | Where-Object {$_.Name -like "*Citrix*"} | Format-Table
   
   # Verify automatic startup
   Get-WmiObject Win32_Service | Where-Object {$_.Name -like "*Citrix*"} | Select Name, StartMode
   ```

2. **Registry Verification**
   ```powershell
   # Check VDI optimizations
   Get-ItemProperty "HKLM:\SOFTWARE\Citrix\*" | Format-List
   
   # Verify optimization settings
   Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\*" | Where-Object {$_.Start -eq 4}
   ```

3. **Domain Verification**
   ```powershell
   # Confirm domain membership
   (Get-WmiObject Win32_ComputerSystem).Domain
   
   # Check organizational unit
   dsquery computer -name $env:COMPUTERNAME
   ```

### System Validation
- **Memory Usage**: Verify optimized memory configuration
- **Service Response**: Test Citrix service responsiveness
- **Network Configuration**: Validate optimized network settings
- **Registry Settings**: Confirm optimization registry entries

## Troubleshooting Common Issues

### Stage 1 Issues

**Installation File Access**
```
Error: Cannot access VDA installation file
Solution: Verify network path and permissions
- Test: Test-Path "\\fileserver\citrix\VDAServerSetup.iso"
- Fix: Update CitrixConfig.txt with correct path
```

**Domain Join Failure**
```
Error: Failed to join domain
Solution: Verify credentials and network connectivity
- Check: Domain controller accessibility
- Verify: DNS resolution working
- Confirm: Account has domain join permissions
```

**Service Installation Failure**
```
Error: Citrix service installation failed
Solution: Check prerequisites and permissions
- Verify: Administrator privileges
- Check: Windows version compatibility
- Review: Installation logs for details
```

### Stage 2 Issues

**Configuration File Missing**
```
Error: Cannot load Stage 1 configuration
Solution: Verify Stage 1 completed successfully
- Check: C:\temp\CitrixConfig.json exists
- Verify: File contains valid JSON data
- Confirm: Stage 1 completed without errors
```

**Service Verification Failure**
```
Error: Citrix services not running
Solution: Check service status and dependencies
- Review: Windows Event Logs
- Verify: Service dependencies met
- Check: Registry configuration correct
```

## Production Deployment Strategy

### Pilot Deployment
1. **Test Environment**: Deploy to test systems first
2. **Validation**: Verify all components function correctly
3. **Documentation**: Record any environment-specific issues
4. **Refinement**: Adjust configuration as needed

### Production Rollout
1. **Staged Deployment**: Deploy to production in phases
2. **Monitoring**: Monitor system performance and stability
3. **Support**: Provide helpdesk with troubleshooting guides
4. **Feedback**: Collect user feedback and system metrics

### Maintenance Procedures
1. **Regular Monitoring**: Check service status and performance
2. **Log Review**: Review installation and system logs
3. **Configuration Updates**: Apply configuration changes as needed
4. **Documentation**: Maintain deployment documentation

## Success Criteria

### Technical Validation
- All Citrix components installed and running
- Services configured for automatic startup
- System optimizations applied and active
- Domain join successful and verified

### System Validation
- System readiness score above 85%
- Memory usage optimized
- Service configuration verified
- Network configuration optimized

### Operational Validation
- Comprehensive logging available
- Error handling functional
- Recovery procedures documented
- Support procedures established

This deployment guide ensures successful implementation of the Citrix automation suite in enterprise environments with comprehensive verification and troubleshooting procedures.