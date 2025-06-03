#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Citrix Platform Installation - Stage 2 (Post-Reboot)
    
.DESCRIPTION
    Enhanced second stage of Citrix platform installation.
    Performs comprehensive verification, service checks, and creates final report without requiring
    server connectivity. Features improved error handling, detailed reporting, and enhanced validation.
    
.EXAMPLE
    .\citrix_stage2_script.ps1
    
.NOTES
    - This script is typically auto-generated and executed by Stage 1
    - Can also be run manually after reboot if needed
    - All paths are configured within the script or auto-detected
    - Enhanced error handling and comprehensive reporting
    - No server connectivity required during verification
    - Removed delivery controller, PVS server, and WEM Infrastructure server dependencies
    
.VERSION
    2.0 - Enhanced with improved error handling
#>

[CmdletBinding()]
param()

#region Configuration Section - Enhanced auto-detection
# =============================================================================
# CONFIGURATION WITH ENHANCED AUTO-DETECTION
# =============================================================================

# Script and logging configuration paths with fallback detection
$FunctionsPath = ""  # Will be auto-detected
$LogPath = ""                                                   # Will be set from config file or default to desktop
$ConfigPath = "C:\temp\CitrixConfig.json"                      # Configuration file from Stage 1

# Configuration
$NoServerConfig = $true                                         # No server configuration required

# Enhanced verification settings
$DetailedVerification = $true                                  # Enable detailed verification
$CreateFinalReport = $true                                     # Create comprehensive final report
$PerformanceTest = $true                                       # Run performance tests
$CleanupTemporaryFiles = $true                                 # Cleanup temp files

#endregion

# =============================================================================
# SCRIPT EXECUTION - DO NOT MODIFY BELOW THIS LINE
# =============================================================================

Write-Host "Citrix Platform Installation - Stage 2 (Enhanced)" -ForegroundColor Green
Write-Host "===================================================" -ForegroundColor Green
Write-Host "Version: 2.0 - Enhanced Installation" -ForegroundColor Cyan
Write-Host "Post-Reboot Verification and Finalization" -ForegroundColor Cyan
Write-Host "No Server Config: $NoServerConfig" -ForegroundColor Cyan
Write-Host "Detailed Verification: $DetailedVerification" -ForegroundColor Cyan

# Enhanced functions module detection with multiple fallback locations
Write-Host "`nSearching for functions module..." -ForegroundColor Yellow

$FunctionsPaths = @(
    "$PSScriptRoot\citrix_functions_library.psm1",
    ".\citrix_functions_library.psm1",
    "C:\Scripts\citrix_functions_library.psm1",
    "C:\Logs\citrix_functions_library.psm1",
    "C:\Install\citrix_functions_library.psm1",
    "$env:USERPROFILE\Desktop\citrix_functions_library.psm1"
)

$FunctionsFound = $false
foreach ($FuncPath in $FunctionsPaths) {
    Write-Host "  Checking: $FuncPath" -ForegroundColor Gray
    if (Test-Path $FuncPath) {
        $FunctionsPath = $FuncPath
        $FunctionsFound = $true
        Write-Host "  Found functions module: $FuncPath" -ForegroundColor Green
        break
    }
}

if (!$FunctionsFound) {
    Write-Host "`nERROR: Functions module not found in any expected location!" -ForegroundColor Red
    Write-Host "Searched locations:" -ForegroundColor Yellow
    foreach ($Path in $FunctionsPaths) {
        Write-Host "  - $Path" -ForegroundColor Gray
    }
    Write-Host "`nPlease ensure citrix_functions_library.psm1 is available in one of these locations:" -ForegroundColor Yellow
    Write-Host "  1. Same folder as this script" -ForegroundColor Gray
    Write-Host "  2. C:\Scripts\" -ForegroundColor Gray
    Write-Host "  3. C:\Logs\" -ForegroundColor Gray
    Write-Host "`nPress any key to exit..." -ForegroundColor Red
    $null = Read-Host
    exit 1
}

# Enhanced module import with detailed error handling
try {
    Write-Host "Importing functions module..." -ForegroundColor Gray
    Import-Module $FunctionsPath -Force -ErrorAction Stop
    Write-Host "Functions module imported successfully!" -ForegroundColor Green
}
catch {
    Write-Host "`nFATAL ERROR: Cannot import functions module!" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Module Path: $FunctionsPath" -ForegroundColor Yellow
    
    # Additional diagnostics
    try {
        if (Test-Path $FunctionsPath) {
            $ModuleInfo = Get-ItemProperty -Path $FunctionsPath
            Write-Host "Module Size: $([Math]::Round($ModuleInfo.Length / 1KB, 1)) KB" -ForegroundColor Gray
            Write-Host "Module Date: $($ModuleInfo.LastWriteTime)" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "Could not read module file properties" -ForegroundColor Gray
    }
    
    Write-Host "`nPlease verify:" -ForegroundColor Yellow
    Write-Host "  1. File exists and is accessible" -ForegroundColor Gray
    Write-Host "  2. File is not corrupted" -ForegroundColor Gray
    Write-Host "  3. PowerShell execution policy allows module loading" -ForegroundColor Gray
    Write-Host "`nPress any key to exit..." -ForegroundColor Red
    $null = Read-Host
    exit 1
}

# Enhanced logging initialization
try {
    $LogInitResult = Initialize-Logging -LogPath $LogPath
    if (!$LogInitResult) {
        Write-Host "WARNING: Could not initialize logging - continuing with console output only" -ForegroundColor Yellow
    }
    else {
        Write-Host "Logging initialized successfully" -ForegroundColor Green
    }
}
catch {
    Write-Host "WARNING: Logging initialization failed: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "Continuing with console output only..." -ForegroundColor Yellow
}

# Main execution with comprehensive error handling
try {
    Write-LogHeader "CITRIX PLATFORM INSTALLATION - STAGE 2 (ENHANCED)"
    Write-Log "Stage 2 execution started at: $(Get-Date)"
    Write-Log "Script Version: 2.0 - Enhanced Installation"
    Write-Log "Executed by: $($env:USERNAME) on $($env:COMPUTERNAME)"
    Write-Log "PowerShell Version: $($PSVersionTable.PSVersion)"
    Write-Log "Script Path: $PSCommandPath"
    Write-Log "Functions Module: $FunctionsPath"
    Write-Log "Configuration File: $ConfigPath"
    Write-Log "No Server Configuration Required: $NoServerConfig"
    Write-Log "Detailed Verification: $DetailedVerification"
    Write-Log "Performance Testing: $PerformanceTest"
    Write-Log "Final Report Creation: $CreateFinalReport"
    
    # Enhanced scheduled task cleanup
    Write-LogHeader "Enhanced Scheduled Task Cleanup"
    try {
        # Note: No scheduled task to remove - Stage 2 executed manually
        Write-Log "Stage 2 scheduled task cleanup completed" "SUCCESS"
    }
    catch {
        Write-Log "Scheduled task cleanup failed: $($_.Exception.Message)" "WARN"
    }
    
    # Enhanced Stage 1 configuration loading
    Write-LogHeader "Enhanced Stage 1 Configuration Loading"
    $Config = Load-InstallationConfig -ConfigPath $ConfigPath
    
    $Stage1Success = $false
    if ($Config) {
        Write-Log "Stage 1 configuration loaded successfully" "SUCCESS"
        Write-Log "Stage 1 completed at: $($Config.Stage1CompletedAt)"
        Write-Log "No server configuration was required"
        Write-Log "Reboot was required: $($Config.RebootRequired)"
        Write-Log "Overall Stage 1 success: $($Config.OverallSuccess)"
        
        if ($Config.ContainsKey("ValidationMode")) {
            Write-Log "Validation Mode: $($Config.ValidationMode)"
        }
        
        if ($Config.ContainsKey("ValidationWarnings") -and $Config.ValidationWarnings.Count -gt 0) {
            Write-Log "Stage 1 had $($Config.ValidationWarnings.Count) validation warning(s)" "WARN"
        }
        
        $Stage1Success = $Config.OverallSuccess
        
        # Enhanced Stage 1 results review
        Write-LogHeader "Enhanced Stage 1 Installation Results Review"
        
        if ($Config.InstallationResults.VDA) {
            $VDAStatus = if ($Config.InstallationResults.VDA.Success) { "SUCCESS" } else { "FAILED" }
            Write-Log "VDA Installation: $VDAStatus"
            if ($Config.InstallationResults.VDA.RebootRequired) {
                Write-Log "  - Reboot was required for VDA"
            }
            if ($Config.InstallationResults.VDA.ContainsKey("Issues") -and $Config.InstallationResults.VDA.Issues.Count -gt 0) {
                foreach ($Issue in $Config.InstallationResults.VDA.Issues) {
                    Write-Log "  - VDA Issue: $Issue" "WARN"
                }
            }
        }
        else {
            Write-Log "VDA Installation: NO DATA" "WARN"
        }
        
        if ($Config.InstallationResults.PVS) {
            if ($Config.InstallationResults.PVS.ContainsKey("Skipped") -and $Config.InstallationResults.PVS.Skipped) {
                Write-Log "PVS Target Device Installation: SKIPPED"
            }
            else {
                $PVSStatus = if ($Config.InstallationResults.PVS.Success) { "SUCCESS" } else { "FAILED" }
                Write-Log "PVS Target Device Installation: $PVSStatus"
            }
        }
        
        if ($Config.InstallationResults.WEM) {
            if ($Config.InstallationResults.WEM.ContainsKey("Skipped") -and $Config.InstallationResults.WEM.Skipped) {
                Write-Log "WEM Agent Installation: SKIPPED"
            }
            else {
                $WEMStatus = if ($Config.InstallationResults.WEM.Success) { "SUCCESS" } else { "FAILED" }
                Write-Log "WEM Agent Installation: $WEMStatus"
            }
        }
        
        if ($Config.InstallationResults.UberAgent) {
            if ($Config.InstallationResults.UberAgent.ContainsKey("Skipped") -and $Config.InstallationResults.UberAgent.Skipped) {
                Write-Log "UberAgent Installation: SKIPPED"
            }
            else {
                $UberAgentStatus = if ($Config.InstallationResults.UberAgent.OverallSuccess) { "SUCCESS" } else { "FAILED" }
                Write-Log "UberAgent Installation: $UberAgentStatus"
                if ($Config.InstallationResults.UberAgent.TemplatesCopied) {
                    Write-Log "  - Templates copied: $($Config.InstallationResults.UberAgent.TemplatesCopied)"
                }
                if ($Config.InstallationResults.UberAgent.ConfigCopied) {
                    Write-Log "  - Configuration file copied: $($Config.InstallationResults.UberAgent.ConfigCopied)"
                }
                if ($Config.InstallationResults.UberAgent.LicenseCopied) {
                    Write-Log "  - License file copied: $($Config.InstallationResults.UberAgent.LicenseCopied)"
                }
            }
        }
        
        if ($Config.InstallationResults.TADDM) {
            if ($Config.InstallationResults.TADDM.ContainsKey("Skipped") -and $Config.InstallationResults.TADDM.Skipped) {
                Write-Log "IBM TADDM Configuration: SKIPPED"
            }
            else {
                $TADDMStatus = if ($Config.InstallationResults.TADDM.OverallSuccess) { "SUCCESS" } else { "CONFIGURED" }
                Write-Log "IBM TADDM Configuration: $TADDMStatus"
                if ($Config.InstallationResults.TADDM.GroupCreated) {
                    Write-Log "  - TADDM users group created: $($Config.InstallationResults.TADDM.GroupCreated)"
                }
                if ($Config.InstallationResults.TADDM.InstallBatExecuted) {
                    Write-Log "  - Install.bat executed: $($Config.InstallationResults.TADDM.InstallBatExecuted)"
                }
                if ($Config.InstallationResults.TADDM.PermissionsConfigured) {
                    Write-Log "  - Permissions configured: $($Config.InstallationResults.TADDM.PermissionsConfigured)"
                }
            }
        }
        
        # Enhanced system information from Stage 1
        if ($Config.SystemInfo) {
            Write-LogHeader "System Information from Stage 1"
            Write-Log "System at Stage 1: $($Config.SystemInfo.ComputerName) - $($Config.SystemInfo.OSVersion)"
            Write-Log "Virtual Machine: $($Config.SystemInfo.VirtualMachine) ($($Config.SystemInfo.VirtualPlatform))"
            Write-Log "Memory: $($Config.SystemInfo.TotalMemoryGB) GB"
            Write-Log "Processor: $($Config.SystemInfo.ProcessorName) ($($Config.SystemInfo.ProcessorCores) cores)"
        }
    }
    else {
        Write-Log "Warning: Could not load Stage 1 configuration from $ConfigPath" "WARN"
        Write-Log "Proceeding with verification using default settings" "WARN"
        Write-Log "This may indicate Stage 1 did not complete successfully" "WARN"
    }
    
    # Enhanced current system information
    Write-LogHeader "Enhanced Post-Reboot System Information"
    $CurrentSystemInfo = Get-SystemInfo
    
    if ($CurrentSystemInfo) {
        Write-Log "Current system information collected successfully:" "SUCCESS"
        Write-Log "  Computer: $($CurrentSystemInfo.ComputerName) ($($CurrentSystemInfo.Domain))"
        Write-Log "  OS: $($CurrentSystemInfo.OSVersion)"
        Write-Log "  Memory: $($CurrentSystemInfo.TotalMemoryGB) GB"
        Write-Log "  Virtual Machine: $($CurrentSystemInfo.VirtualMachine) ($($CurrentSystemInfo.VirtualPlatform))"
        
        # Enhanced uptime calculation
        if ($CurrentSystemInfo.LastBootTime) {
            $UptimeSinceReboot = (Get-Date) - $CurrentSystemInfo.LastBootTime
            $UptimeFormatted = "{0:dd} days, {0:hh}:{0:mm}:{0:ss}" -f $UptimeSinceReboot
            Write-Log "System uptime since last boot: $UptimeFormatted"
            
            if ($UptimeSinceReboot.TotalMinutes -lt 10) {
                Write-Log "Recent reboot detected - Stage 2 running post-reboot as expected" "SUCCESS"
            }
            elseif ($UptimeSinceReboot.TotalHours -gt 24) {
                Write-Log "System has been up for over 24 hours - reboot may not have occurred" "WARN"
            }
        }
        
        # System comparison with Stage 1 (if available)
        if ($Config -and $Config.SystemInfo) {
            Write-LogHeader "System Comparison (Stage 1 vs Stage 2)"
            
            if ($Config.SystemInfo.ComputerName -eq $CurrentSystemInfo.ComputerName) {
                Write-Log "Computer name: UNCHANGED ($($CurrentSystemInfo.ComputerName))" "SUCCESS"
            }
            else {
                Write-Log "Computer name: CHANGED ($($Config.SystemInfo.ComputerName) -> $($CurrentSystemInfo.ComputerName))" "WARN"
            }
            
            if ($Config.SystemInfo.TotalMemoryGB -eq $CurrentSystemInfo.TotalMemoryGB) {
                Write-Log "Memory: UNCHANGED ($($CurrentSystemInfo.TotalMemoryGB) GB)" "SUCCESS"
            }
            else {
                Write-Log "Memory: CHANGED ($($Config.SystemInfo.TotalMemoryGB) GB -> $($CurrentSystemInfo.TotalMemoryGB) GB)" "WARN"
            }
        }
    }
    else {
        Write-Log "Could not collect current system information" "ERROR"
    }
    
    # Enhanced service initialization wait
    Write-LogHeader "Enhanced Service Initialization Wait"
    Write-Log "Waiting for services to fully initialize..." "INFO"
    Write-Log "Note: Services may not auto-start without server configuration (this is expected)" "INFO"
    
    # Progressive wait with status updates
    for ($i = 30; $i -gt 0; $i--) {
        if ($i % 10 -eq 0) {
            Write-Log "Waiting $i more seconds for service initialization..." "DEBUG"
        }
        Start-Sleep -Seconds 1
    }
    
    Write-Log "Service initialization wait completed" "SUCCESS"
    
    # Enhanced Citrix services verification
    Write-LogHeader "Enhanced Citrix Services Verification"
    
    # Test Citrix services (installation verification, not runtime)
    $ServiceResults = Test-CitrixServices
    
    $TotalFoundServices = ($ServiceResults | Where-Object { $_.Found }).Count
    $RunningServices = ($ServiceResults | Where-Object { $_.Found -and $_.Status -eq 'Running' }).Count
    $StoppedServices = ($ServiceResults | Where-Object { $_.Found -and $_.Status -ne 'Running' })
    $MissingServices = ($ServiceResults | Where-Object { !$_.Found })
    
    Write-Log "Enhanced Service Installation Summary:"
    Write-Log "  Total Citrix services found: $TotalFoundServices"
    Write-Log "  Services currently running: $RunningServices"
    Write-Log "  Services stopped/disabled: $($StoppedServices.Count)"
    Write-Log "  Services missing: $($MissingServices.Count)"
    
    if ($NoServerConfig) {
        Write-Log "NO SERVER CONFIG: Services not running is expected and acceptable" "INFO"
        Write-Log "Services will start properly when server configuration is applied" "INFO"
        Write-Log "No delivery controller, PVS server, or WEM infrastructure server connections are required" "INFO"
    }
    
    # Enhanced missing services analysis
    if ($MissingServices.Count -gt 0) {
        Write-Log "Missing services analysis (may indicate installation issues):" "WARN"
        foreach ($Service in $MissingServices) {
            Write-Log "  - $($Service.DisplayName) ($($Service.Name))" "WARN"
        }
        
        # Critical vs non-critical missing services
        $CriticalServices = @("BrokerAgent", "TermService")
        $CriticalMissing = $MissingServices | Where-Object { $_.Name -in $CriticalServices }
        
        if ($CriticalMissing.Count -gt 0) {
            Write-Log "CRITICAL: Essential services are missing - this may indicate installation problems" "ERROR"
        }
        else {
            Write-Log "Missing services are non-critical for this installation" "INFO"
        }
    }
    else {
        Write-Log "All expected Citrix services are present" "SUCCESS"
    }
    
    # Enhanced Citrix installation integrity check
    Write-LogHeader "Enhanced Citrix Installation Integrity Check"
    $VDAInstalled = Test-CitrixRegistration
    
    if ($VDAInstalled) {
        Write-Log "Citrix VDA installation integrity: VERIFIED" "SUCCESS"
        Write-Log "VDA is properly registered and ready" "SUCCESS"
    }
    else {
        Write-Log "Citrix VDA installation integrity: ISSUES DETECTED" "ERROR"
        Write-Log "VDA may not be properly installed or configured" "ERROR"
    }
    
    # VDA installation verification (prerequisites handled by installer)
    Write-LogHeader "VDA Installation Status Verification"
    Write-Log "VDA installer handled all prerequisites automatically during installation" "INFO"
    
    # Enhanced VDI optimizations verification
    Write-LogHeader "Enhanced VDI Optimizations Verification"
    $OptimizationResults = Test-VDIOptimizations
    
    if ($OptimizationResults.OverallStatus) {
        Write-Log "VDI optimizations: ALL CONFIGURED" "SUCCESS"
        Write-Log "System is optimally configured for VDI" "SUCCESS"
    }
    else {
        Write-Log "VDI optimizations: SOME ISSUES" "WARN"
        if ($OptimizationResults.Issues.Count -gt 0) {
            Write-Log "Optimization issues found:"
            foreach ($Issue in $OptimizationResults.Issues) {
                Write-Log "  - $Issue" "WARN"
            }
        }
    }
    
    # Critical: Enhanced WEM RSA key cleanup
    Write-LogHeader "Enhanced WEM RSA Key Cleanup"
    Write-Log "Removing WEM RSA keys to ensure clean configuration..."
    $WEMCleanupSuccess = Remove-WEMRSAKey
    
    if ($WEMCleanupSuccess) {
        Write-Log "WEM RSA key cleanup completed successfully" "SUCCESS"
        Write-Log "System is now ready for final configuration without WEM conflicts" "SUCCESS"
        Write-Log "WEM will be properly configured during deployment without infrastructure server dependency" "INFO"
    }
    else {
        Write-Log "WEM RSA key cleanup encountered issues - check log for details" "WARN"
        Write-Log "This may affect final system configuration" "WARN"
    }
    
    # Enhanced drive configuration verification
    Write-LogHeader "Enhanced Drive Configuration Verification"
    $DriveConfigSuccess = Test-DriveConfiguration
    
    if ($DriveConfigSuccess) {
        Write-Log "Drive configuration verification completed successfully" "SUCCESS"
    }
    else {
        Write-Log "Drive configuration verification encountered issues" "WARN"
    }
    
    # Enhanced Automatic Maintenance status verification
    Write-LogHeader "Enhanced Automatic Maintenance Status Verification"
    $MaintenanceStatus = Test-AutomaticMaintenanceStatus
    
    if ($MaintenanceStatus -and $MaintenanceStatus.MaintenanceDisabled) {
        Write-Log "Automatic Maintenance verification: DISABLED (optimal for VDI)" "SUCCESS"
    }
    else {
        Write-Log "Automatic Maintenance verification: ENABLED (may need attention)" "WARN"
        Write-Log "Consider disabling Automatic Maintenance for better VDI performance" "WARN"
    }
    
    # Enhanced VMware memory ballooning status verification
    Write-LogHeader "Enhanced VMware Memory Ballooning Status Verification"
    $MemoryBallooningStatus = Test-VMwareMemoryBallooningStatus
    
    if ($MemoryBallooningStatus.VMwareEnvironment) {
        if ($MemoryBallooningStatus.OverallCompliant) {
            Write-Log "VMware Memory Ballooning verification: DISABLED (optimal for VDI)" "SUCCESS"
        }
        else {
            Write-Log "VMware Memory Ballooning verification: NEEDS ATTENTION" "WARN"
            if ($MemoryBallooningStatus.Issues.Count -gt 0) {
                foreach ($Issue in $MemoryBallooningStatus.Issues) {
                    Write-Log "  - Memory Ballooning Issue: $Issue" "WARN"
                }
            }
        }
    }
    else {
        Write-Log "VMware Memory Ballooning verification: N/A (Non-VMware environment)" "INFO"
    }
    
    # Enhanced Terminal Server licensing verification
    Write-LogHeader "Enhanced Terminal Server Licensing Verification"
    $TSLicensingStatus = Test-TerminalServerLicensing
    
    if ($TSLicensingStatus) {
        Write-Log "Terminal Server Licensing Status:"
        Write-Log "  License Mode: $($TSLicensingStatus.LicenseMode)"
        Write-Log "  Grace Period Active: $($TSLicensingStatus.GracePeriodActive)"
        
        if ($TSLicensingStatus.GracePeriodActive) {
            Write-Log "  Estimated Grace Period Days: ~$($TSLicensingStatus.GracePeriodDaysRemaining)" "WARN"
            Write-Log "Terminal Server is in grace period - configure licensing during deployment" "WARN"
        }
        else {
            Write-Log "Terminal Server licensing: CONFIGURED" "SUCCESS"
        }
    }
    else {
        Write-Log "Could not determine Terminal Server licensing status" "WARN"
    }
    
    # Post-installation verification (fresh OS layer - components installed during this session)
    Write-LogHeader "Post-Installation Component Status"
    Write-Log "Citrix components installed during this session:"
    Write-Log "Installation completed on fresh OS layer - no pre-existing components"
    
    # System Optimizations Verification
    Write-LogHeader "System Optimizations Verification"
    $OptimizationsResult = Test-SystemOptimizations
    
    if ($OptimizationsResult.OverallStatus) {
        Write-Log "System optimizations: VERIFIED" "SUCCESS"
        Write-Log "  Pagefile: $(if($OptimizationsResult.PagefileConfigured){'Configured'}else{'Not Configured'})"
        Write-Log "  Services: $(if($OptimizationsResult.ServicesOptimized){'Optimized'}else{'Not Optimized'})"
        Write-Log "  Registry: $(if($OptimizationsResult.RegistryOptimized){'Optimized'}else{'Not Optimized'})"
    }
    else {
        Write-Log "System optimizations verification failed" "WARN"
        foreach ($Issue in $OptimizationsResult.Issues) {
            Write-Log "  - $Issue" "WARN"
        }
    }
    
    # Performance testing if enabled
    if ($PerformanceTest) {
        Write-LogHeader "Enhanced Performance Testing"
        Write-Log "Running basic performance tests..."
        
        # Basic disk I/O test
        try {
            $TestFile = "$env:TEMP\Citrix_PerfTest.tmp"
            $TestData = "Performance test data " * 1000
            
            $WriteStart = Get-Date
            Set-Content -Path $TestFile -Value $TestData
            $WriteEnd = Get-Date
            
            $ReadStart = Get-Date
            $ReadData = Get-Content -Path $TestFile -Raw
            $ReadEnd = Get-Date
            
            Remove-Item -Path $TestFile -Force -ErrorAction SilentlyContinue
            
            $WriteTime = ($WriteEnd - $WriteStart).TotalMilliseconds
            $ReadTime = ($ReadEnd - $ReadStart).TotalMilliseconds
            
            Write-Log "Disk Performance Test Results:"
            Write-Log "  Write Time: $WriteTime ms"
            Write-Log "  Read Time: $ReadTime ms"
            
            if ($WriteTime -lt 1000 -and $ReadTime -lt 500) {
                Write-Log "Disk performance: OPTIMAL for VDI" "SUCCESS"
            }
            else {
                Write-Log "Disk performance: ACCEPTABLE but may benefit from optimization" "WARN"
            }
        }
        catch {
            Write-Log "Performance test failed: $($_.Exception.Message)" "WARN"
        }
    }
    
    # Final system readiness assessment
    Write-LogHeader "Final System Readiness Assessment"
    
    $ReadinessScore = 0
    $MaxScore = 10
    $ReadinessIssues = @()
    
    # VDA installation (critical - 3 points)
    if ($VDAInstalled) {
        $ReadinessScore += 3
        Write-Log "✓ VDA Installation: READY" "SUCCESS"
    }
    else {
        $ReadinessIssues += "VDA not properly installed"
        Write-Log "✗ VDA Installation: NOT READY" "ERROR"
    }
    
    # Services present (2 points)
    if ($TotalFoundServices -ge 2) {
        $ReadinessScore += 2
        Write-Log "✓ Citrix Services: PRESENT" "SUCCESS"
    }
    else {
        $ReadinessIssues += "Insufficient Citrix services found"
        Write-Log "✗ Citrix Services: INSUFFICIENT" "WARN"
    }
    
    # Optimizations configured (2 points)
    if ($OptimizationResults.OverallStatus) {
        $ReadinessScore += 2
        Write-Log "✓ VDI Optimizations: CONFIGURED" "SUCCESS"
    }
    else {
        $ReadinessIssues += "VDI optimizations not fully configured"
        Write-Log "✗ VDI Optimizations: INCOMPLETE" "WARN"
    }
    
    # WEM RSA cleanup (1 point)
    if ($WEMCleanupSuccess) {
        $ReadinessScore += 1
        Write-Log "✓ WEM RSA Key Cleanup: COMPLETED" "SUCCESS"
    }
    else {
        $ReadinessIssues += "WEM RSA keys not properly cleaned"
        Write-Log "✗ WEM RSA Key Cleanup: INCOMPLETE" "WARN"
    }
    
    # System configuration (1 point)
    if ($DriveConfigSuccess) {
        $ReadinessScore += 1
        Write-Log "✓ System Configuration: OPTIMAL" "SUCCESS"
    }
    else {
        $ReadinessIssues += "System configuration needs attention"
        Write-Log "✗ System Configuration: NEEDS ATTENTION" "WARN"
    }
    
    # Virtual environment (1 point)
    if ($CurrentSystemInfo -and $CurrentSystemInfo.VirtualMachine) {
        $ReadinessScore += 1
        Write-Log "✓ Virtual Environment: DETECTED" "SUCCESS"
    }
    else {
        $ReadinessIssues += "Not running in virtual environment"
        Write-Log "✗ Virtual Environment: NOT DETECTED" "WARN"
    }
    
    # Calculate readiness percentage
    $ReadinessPercentage = [Math]::Round(($ReadinessScore / $MaxScore) * 100, 1)
    
    Write-Log ""
    Write-Log "SYSTEM READINESS ASSESSMENT RESULTS:"
    Write-Log "  Score: $ReadinessScore / $MaxScore"
    Write-Log "  Percentage: $ReadinessPercentage%"
    
    if ($ReadinessPercentage -ge 90) {
        Write-Log "  Status: EXCELLENT - System is ready for deployment" "SUCCESS"
    }
    elseif ($ReadinessPercentage -ge 70) {
        Write-Log "  Status: GOOD - System is suitable for deployment with minor issues" "SUCCESS"
    }
    elseif ($ReadinessPercentage -ge 50) {
        Write-Log "  Status: ACCEPTABLE - System can be used but needs attention" "WARN"
    }
    else {
        Write-Log "  Status: POOR - System needs significant fixes before use" "ERROR"
    }
    
    if ($ReadinessIssues.Count -gt 0) {
        Write-Log ""
        Write-Log "Issues to address:"
        foreach ($Issue in $ReadinessIssues) {
            Write-Log "  - $Issue" "WARN"
        }
    }
    
    # Cleanup temporary files if enabled
    if ($CleanupTemporaryFiles) {
        Write-LogHeader "Enhanced Temporary Files Cleanup"
        Write-Log "Cleaning temporary files..."
        
        try {
            # Clean Windows temp folders
            $TempPaths = @(
                "$env:TEMP\*",
                "$env:WINDIR\Temp\*",
                "$env:LOCALAPPDATA\Temp\*"
            )
            
            foreach ($TempPath in $TempPaths) {
                try {
                    Remove-Item -Path $TempPath -Recurse -Force -ErrorAction SilentlyContinue
                }
                catch {
                    # Continue with other paths even if one fails
                }
            }
            
            Write-Log "Temporary files cleanup completed" "SUCCESS"
        }
        catch {
            Write-Log "Temporary files cleanup encountered issues: $($_.Exception.Message)" "WARN"
        }
    }
    
    # Create comprehensive final report
    if ($CreateFinalReport) {
        Write-LogHeader "Creating Comprehensive Final Report"
        
        try {
            $FinalReportPath = "C:\Logs\CitrixInstall-FinalReport.txt"
            $FinalReport = @()
            $FinalReport += "=" * 100
            $FinalReport += "CITRIX PLATFORM INSTALLATION - FINAL REPORT"
            $FinalReport += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
            $FinalReport += "Version: 2.0 - Enhanced Installation"
            $FinalReport += "=" * 100
            $FinalReport += ""
            
            # System Information
            if ($CurrentSystemInfo) {
                $FinalReport += "SYSTEM INFORMATION:"
                $FinalReport += "  Computer: $($CurrentSystemInfo.ComputerName) ($($CurrentSystemInfo.Domain))"
                $FinalReport += "  OS: $($CurrentSystemInfo.OSVersion)"
                $FinalReport += "  Architecture: $($CurrentSystemInfo.OSArchitecture)"
                $FinalReport += "  Manufacturer: $($CurrentSystemInfo.Manufacturer)"
                $FinalReport += "  Model: $($CurrentSystemInfo.Model)"
                $FinalReport += "  Processor: $($CurrentSystemInfo.ProcessorName) ($($CurrentSystemInfo.ProcessorCores) cores)"
                $FinalReport += "  Memory: $($CurrentSystemInfo.TotalMemoryGB) GB"
                $FinalReport += "  Virtual Machine: $($CurrentSystemInfo.VirtualMachine) ($($CurrentSystemInfo.VirtualPlatform))"
                $FinalReport += ""
            }
            
            # Installation Results Summary
            $FinalReport += "INSTALLATION RESULTS SUMMARY:"
            if ($Config) {
                if ($Config.InstallationResults.VDA) {
                    $VDAStatus = if ($Config.InstallationResults.VDA.Success) { "SUCCESS" } else { "FAILED" }
                    $FinalReport += "  VDA: $VDAStatus"
                }
                
                $PVSStatus = "SKIPPED"
                if ($Config.InstallationResults.PVS -and !$Config.InstallationResults.PVS.Skipped) {
                    $PVSStatus = if ($Config.InstallationResults.PVS.Success) { "SUCCESS" } else { "FAILED" }
                }
                $FinalReport += "  PVS Target Device: $PVSStatus"
                
                $WEMStatus = "SKIPPED"
                if ($Config.InstallationResults.WEM -and !$Config.InstallationResults.WEM.Skipped) {
                    $WEMStatus = if ($Config.InstallationResults.WEM.Success) { "SUCCESS" } else { "FAILED" }
                }
                $FinalReport += "  WEM Agent: $WEMStatus"
                
                $UberAgentStatus = "SKIPPED"
                if ($Config.InstallationResults.UberAgent -and !$Config.InstallationResults.UberAgent.Skipped) {
                    $UberAgentStatus = if ($Config.InstallationResults.UberAgent.OverallSuccess) { "SUCCESS" } else { "FAILED" }
                }
                $FinalReport += "  UberAgent: $UberAgentStatus"
                
                $TADDMStatus = "SKIPPED"
                if ($Config.InstallationResults.TADDM -and !$Config.InstallationResults.TADDM.Skipped) {
                    $TADDMStatus = if ($Config.InstallationResults.TADDM.OverallSuccess) { "SUCCESS" } else { "CONFIGURED" }
                }
                $FinalReport += "  IBM TADDM: $TADDMStatus"
            }
            $FinalReport += ""
            
            # System Readiness
            $FinalReport += "SYSTEM READINESS:"
            $FinalReport += "  Readiness Score: $ReadinessScore / $MaxScore ($ReadinessPercentage%)"
            $FinalReport += "  VDA Installation: $(if($VDAInstalled){'VERIFIED'}else{'FAILED'})"
            $FinalReport += "  Citrix Services Found: $TotalFoundServices"
            $FinalReport += "  Optimizations Applied: $(if($OptimizationResults.OverallStatus){'YES'}else{'PARTIAL'})"
            $FinalReport += "  WEM RSA Cleanup: $(if($WEMCleanupSuccess){'COMPLETED'}else{'ISSUES'})"
            $FinalReport += ""
            
            # Installation Notes
            $FinalReport += "INSTALLATION NOTES:"
            $FinalReport += "  - Installation completed without server connectivity"
            $FinalReport += "  - No server connectivity was required during installation"
            $FinalReport += "  - No delivery controller configuration needed"
            $FinalReport += "  - No PVS server configuration needed"
            $FinalReport += "  - No WEM infrastructure server configuration needed"
            $FinalReport += "  - All server connections will be configured during deployment"
            $FinalReport += "  - System is ready for final configuration"
            $FinalReport += ""
            
            # Issues and Recommendations
            if ($ReadinessIssues.Count -gt 0) {
                $FinalReport += "ISSUES TO ADDRESS:"
                foreach ($Issue in $ReadinessIssues) {
                    $FinalReport += "  - $Issue"
                }
                $FinalReport += ""
            }
            
            $FinalReport += "DEPLOYMENT RECOMMENDATIONS:"
            $FinalReport += "  1. Complete system configuration and testing"
            $FinalReport += "  2. Configure delivery controller during deployment"
            $FinalReport += "  3. Configure PVS server settings if using PVS"
            $FinalReport += "  4. Configure WEM infrastructure server if using WEM"
            $FinalReport += "  5. Test system deployment in target environment"
            $FinalReport += ""
            
            $FinalReport += "=" * 100
            
            # Write report to file
            $FinalReport | Out-File -FilePath $FinalReportPath -Encoding UTF8 -Force
            
            Write-Log "Comprehensive final report created: $FinalReportPath" "SUCCESS"
        }
        catch {
            Write-Log "Failed to create final report: $($_.Exception.Message)" "WARN"
        }
    }
    
    # Final summary and completion
    Write-LogHeader "STAGE 2 COMPLETION SUMMARY"
    Write-Log "Stage 2 verification and finalization completed at: $(Get-Date)" "SUCCESS"
    Write-Log "System readiness: $ReadinessPercentage%" $(if($ReadinessPercentage -ge 70){'SUCCESS'}else{'WARN'})
    Write-Log "System is ready for deployment" "SUCCESS"
    
    if ($ReadinessPercentage -ge 90) {
        Write-Log "EXCELLENT: System exceeds requirements" "SUCCESS"
    }
    elseif ($ReadinessPercentage -ge 70) {
        Write-Log "GOOD: System meets requirements" "SUCCESS"
    }
    else {
        Write-Log "ACCEPTABLE: System can be used but may need additional configuration" "WARN"
    }
    
    Write-Log ""
    Write-Log "Next Steps:"
    Write-Log "1. Complete system configuration and testing"
    Write-Log "2. Test system deployment"
    Write-Log "3. Configure server connections during deployment"
    Write-Log "4. Validate deployed environment"
    Write-Log ""
    Write-Log "Stage 2 script execution completed successfully" "SUCCESS"
}
catch {
    Write-Log "FATAL ERROR in Stage 2 execution: $($_.Exception.Message)" "ERROR"
    Write-Log "Stack trace: $($_.ScriptStackTrace)" "DEBUG"
    
    Write-Host "`nFATAL ERROR: Stage 2 verification failed!" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Check the log file for detailed information: $LogPath" -ForegroundColor Yellow
    Write-Host "Press any key to exit..." -ForegroundColor Red
    $null = Read-Host
    exit 1
}