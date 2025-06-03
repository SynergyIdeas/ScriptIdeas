# Citrix PowerShell Script Suite - Deployment Checklist

## Pre-Deployment Validation

### System Requirements
- [ ] Windows Server 2019 or 2022 (fresh OS layer)
- [ ] Administrator privileges confirmed
- [ ] PowerShell 5.1 or later available
- [ ] Minimum 10GB free disk space on C: drive
- [ ] Network access to file server confirmed

### File Preparation
- [ ] All 4 core files present in deployment directory:
  - [ ] `citrix_functions_library.psm1` (4,350 lines, 48 functions)
  - [ ] `citrix_stage1_script.ps1` (790 lines)
  - [ ] `citrix_stage2_script.ps1` (823 lines)
  - [ ] `CitrixConfig.txt` (configuration file)

### Configuration Review
- [ ] Network paths updated in CitrixConfig.txt
- [ ] VDA ISO source path verified
- [ ] PVS ISO source path verified (if applicable)
- [ ] Startup/shutdown script paths configured
- [ ] SMB optimization parameters set
- [ ] Installation flags configured appropriately

## Network Infrastructure Validation

### File Server Access
- [ ] VDA installer accessible at configured path
- [ ] PVS installer accessible (if enabled)
- [ ] WEM installer accessible (if enabled)
- [ ] UberAgent installer accessible (if enabled)
- [ ] IBM TADDM accessible (if enabled)
- [ ] OS-specific startup scripts accessible
- [ ] OS-specific shutdown scripts accessible

### Domain Credentials
- [ ] Domain credentials available for network file access
- [ ] Service account permissions verified for file server
- [ ] Network share permissions confirmed

## Script Validation

### Function Library Integrity
- [ ] Module exports 48 functions successfully
- [ ] No syntax errors in PowerShell validation
- [ ] Configuration functions operational
- [ ] Logging functions operational

### Installation Scripts
- [ ] Stage 1 script imports module successfully
- [ ] Configuration loading works with fallback defaults
- [ ] Stage 2 script auto-detection functions properly
- [ ] Scheduled task creation/removal functions

## Component Verification

### Required Components
- [ ] VDA installation enabled and path verified
- [ ] Installation method: ISO copy → mount → install → unmount

### Optional Components
- [ ] PVS Target Device (enabled/disabled as needed)
- [ ] WEM Agent (enabled/disabled as needed)
- [ ] UberAgent (enabled/disabled as needed)
- [ ] IBM TADDM (enabled/disabled as needed)

## Execution Checklist

### Pre-Execution
- [ ] PowerShell execution policy allows module imports
- [ ] Administrator session confirmed
- [ ] Desktop logging path accessible
- [ ] Temporary directory (C:\Temp) available

### Stage 1 Execution
- [ ] Run `citrix_stage1_script.ps1` as Administrator
- [ ] Monitor for configuration loading success
- [ ] Verify network file copying operations
- [ ] Confirm installation progress in logs
- [ ] Allow automatic reboot completion

### Stage 2 Verification
- [ ] Stage 2 auto-executes after reboot
- [ ] Service verification completes successfully
- [ ] System optimization validation passes
- [ ] Final report generation succeeds

## Post-Deployment Validation

### Service Status
- [ ] Citrix VDA services running
- [ ] PVS Target Device services running (if installed)
- [ ] WEM Agent services running (if installed)
- [ ] UberAgent services running (if installed)

### System Configuration
- [ ] Pagefile configured with fixed size
- [ ] Registry optimizations applied
- [ ] Windows services optimized
- [ ] Event logs configured
- [ ] SMB parameters optimized

### Network Configuration
- [ ] NetBIOS over TCP/IP disabled
- [ ] Network adapter offload parameters disabled
- [ ] SMB optimization parameters applied

### Script Installation
- [ ] Startup scripts deployed to correct OS-specific location
- [ ] Shutdown scripts deployed to correct OS-specific location
- [ ] Script execution permissions configured

## Log File Review

### Installation Logs
- [ ] Desktop log file created successfully
- [ ] No critical errors in installation log
- [ ] All components show successful installation
- [ ] Network operations completed without failures

### Component Logs
- [ ] VDA installation log reviewed
- [ ] PVS installation log reviewed (if applicable)
- [ ] WEM installation log reviewed (if applicable)
- [ ] System optimization log reviewed

## Troubleshooting Checklist

### Common Issues Resolution
- [ ] Module import failures → Check execution policy
- [ ] Network access issues → Verify credentials and paths
- [ ] ISO mount failures → Check disk space and file integrity
- [ ] Service startup issues → Review component installation logs

### Debug Mode
- [ ] Enable DebugMode=true if additional logging needed
- [ ] Review detailed debug output for complex issues
- [ ] Verify file copy operations with enhanced logging

## Security Validation

### Permissions
- [ ] Scripts run with appropriate Administrator privileges
- [ ] Network access uses proper domain credentials
- [ ] Local system modifications completed successfully
- [ ] No credential storage in configuration files

### Cleanup
- [ ] Temporary files cleaned up (if configured)
- [ ] Scheduled tasks removed after completion
- [ ] Installation files preserved/removed as configured

## Performance Validation

### System Optimization
- [ ] VDI optimizations applied successfully
- [ ] Pagefile configured for optimal performance
- [ ] Windows services optimized for VDI environment
- [ ] Registry performance settings applied

### Network Performance
- [ ] SMB parameters optimized for enterprise environment
- [ ] Network adapter settings optimized
- [ ] File transfer performance validated

## Documentation

### Configuration Documentation
- [ ] CitrixConfig.txt settings documented
- [ ] Environment-specific customizations recorded
- [ ] Network path mappings documented
- [ ] Component selection rationale documented

### Installation Record
- [ ] Installation date and time recorded
- [ ] Component versions documented
- [ ] System specifications recorded
- [ ] Performance baseline established

## Sign-off Checklist

### Technical Validation
- [ ] All required components installed successfully
- [ ] System optimizations applied and verified
- [ ] Network configuration completed
- [ ] Logging and monitoring operational

### Functional Testing
- [ ] System performance within acceptable parameters
- [ ] All Citrix services operational
- [ ] Script deployment completed successfully
- [ ] Error handling tested and functional

### Final Approval
- [ ] Installation log review completed
- [ ] System ready for production use
- [ ] Documentation updated and stored
- [ ] Deployment marked as successful

## Deployment Complete

Date: _______________
Deployed by: _______________
Reviewed by: _______________
Approved by: _______________

### Key Metrics
- Total installation time: _______________
- Components installed: _______________
- System performance baseline: _______________
- Log file location: _______________

## Notes
Use this section for environment-specific notes, issues encountered, or customizations applied:

_________________________________________________
_________________________________________________
_________________________________________________
_________________________________________________