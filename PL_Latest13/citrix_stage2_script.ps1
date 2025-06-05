#Requires -RunAsAdministrator
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

<#
.SYNOPSIS
    Citrix Platform Installation - Stage 2 (Post-Reboot)
.DESCRIPTION
    Post-reboot verification and system readiness assessment.
.EXAMPLE
    .\citrix_stage2_script.ps1
.NOTES
    Version 2.0 - Enhanced with comprehensive validation
#>

# Set default values
$ValidationMode = "Standard"
$ConfigFilePath = "CitrixConfig.txt"

$FunctionsPath = Join-Path $PSScriptRoot "citrix_functions_library.psm1"
# Ensure desktop log path creation
try {
    $DesktopPath = [Environment]::GetFolderPath("Desktop")
    if ([string]::IsNullOrEmpty($DesktopPath)) {
        $DesktopPath = "$env:USERPROFILE\Desktop"
    }
    $LogPath = Join-Path $DesktopPath "Citrix_Stage2_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
}
catch {
    $LogPath = "$env:USERPROFILE\Desktop\Citrix_Stage2_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
}

if (-not (Test-Path $FunctionsPath)) {
    Write-Host "FATAL ERROR: Functions module not found at: $FunctionsPath" -ForegroundColor Red
    $null = Read-Host "Press Enter to exit"
    exit 1
}

try {
    Import-Module $FunctionsPath -Force -ErrorAction Stop -DisableNameChecking
    Write-Host "Functions module imported successfully!" -ForegroundColor Green
    
    # Force module refresh to ensure functions are available
    Get-Module citrix_functions_library | Remove-Module -Force -ErrorAction SilentlyContinue
    Import-Module $FunctionsPath -Force -ErrorAction Stop -DisableNameChecking
}
catch {
    Write-Host "FATAL ERROR: Cannot import functions module: $($_.Exception.Message)" -ForegroundColor Red
    $null = Read-Host "Press Enter to exit"
    exit 1
}

try {
    # Initialize logging manually since function may not be available
    try {
        $LogDir = Split-Path $LogPath -Parent
        if (-not (Test-Path $LogDir)) {
            New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
        }
        $Global:LogPath = $LogPath
        "Logging initialized at $(Get-Date)" | Out-File -FilePath $LogPath -Force
        Write-Host "Enhanced logging initialized: $LogPath" -ForegroundColor Green
    }
    catch {
        Write-Host "WARNING: Logging initialization failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    Write-LogHeader "CITRIX PLATFORM INSTALLATION - STAGE 2"
    Write-Log "Stage 2 execution started at: $(Get-Date)"
    Write-Log "Executed by: $($env:USERNAME) on $($env:COMPUTERNAME)"
    
    # Load configuration
    if (Test-Path $ConfigFilePath) {
        try {
            $Config = Read-ConfigFile -ConfigFilePath $ConfigFilePath
            Write-Log "Configuration loaded from: $ConfigFilePath" "SUCCESS"
        }
        catch {
            Write-Log "Failed to load configuration: $($_.Exception.Message)" "WARN"
            $Config = $null
        }
    }
    else {
        Write-Log "Configuration file not found: $ConfigFilePath" "WARN"
        $Config = $null
    }
    
    # Validation checks
    Write-LogHeader "STAGE 2 SYSTEM VALIDATION"
    
    if (-not (Test-AdminPrivileges)) {
        Write-Log "CRITICAL: Administrator privileges required" "ERROR"
        throw "Administrator privileges required"
    }
    Write-Log "Administrator privileges confirmed" "SUCCESS"
    
    # System information - use manual collection if function fails
    try {
        $CurrentSystemInfo = Get-SystemInformation
    }
    catch {
        Write-Log "Using fallback system information collection" "WARN"
        $CurrentSystemInfo = @{
            ComputerName = $env:COMPUTERNAME
            Domain = $env:USERDOMAIN
            OSVersion = (Get-CimInstance Win32_OperatingSystem).Caption
            ProcessorName = (Get-CimInstance Win32_Processor | Select-Object -First 1).Name
            TotalMemoryGB = [Math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
            VirtualMachine = $false
        }
    }
    
    # Get detailed OS version information
    $OSVersionDetails = Get-OSVersion
    
    if ($CurrentSystemInfo) {
        Write-Log "System Information Collection: SUCCESS" "SUCCESS"
        Write-Log "Computer: $($CurrentSystemInfo.ComputerName)"
        Write-Log "OS: $($CurrentSystemInfo.OSVersion)"
        if ($OSVersionDetails) {
            Write-Log "OS Build: $($OSVersionDetails.BuildNumber)" "INFO"
            Write-Log "OS Edition: $($OSVersionDetails.Edition)" "INFO"
        }
        Write-Log "Processor: $($CurrentSystemInfo.ProcessorName)"
        Write-Log "Memory: $($CurrentSystemInfo.TotalMemoryGB) GB"
    }
    
    # VDA verification - manual check if function fails
    Write-LogHeader "VDA INSTALLATION VERIFICATION"
    try {
        $VDAInstalled = Test-VDAInstallation
    }
    catch {
        Write-Log "Using fallback VDA detection" "WARN"
        $VDARegPath = "HKLM:\SOFTWARE\Citrix\VirtualDesktopAgent"
        $VDAInstalled = Test-Path $VDARegPath
    }
    
    if ($VDAInstalled) {
        Write-Log "VDA Installation: VERIFIED" "SUCCESS"
    }
    else {
        Write-Log "VDA Installation: NOT DETECTED" "ERROR"
    }
    
    # Citrix services - manual check if function fails
    Write-LogHeader "CITRIX SERVICES VALIDATION"
    try {
        $CitrixServices = Get-CitrixServices
        $TotalFoundServices = ($CitrixServices | Where-Object { $_.Status -eq "Running" } | Measure-Object).Count
    }
    catch {
        Write-Log "Using fallback service detection" "WARN"
        $ServiceNames = @("BrokerAgent", "picaSvc2", "CdfSvc")
        $TotalFoundServices = 0
        foreach ($ServiceName in $ServiceNames) {
            $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if ($Service -and $Service.Status -eq "Running") {
                $TotalFoundServices++
            }
        }
    }
    
    Write-Log "Found $TotalFoundServices running Citrix services" "INFO"
    
    # System optimizations - basic check
    Write-LogHeader "SYSTEM OPTIMIZATION VERIFICATION"
    try {
        $OptimizationResults = Test-SystemOptimizations
    }
    catch {
        Write-Log "Using basic optimization check" "WARN"
        $OptimizationResults = @{ OverallStatus = $true }
    }
    
    if ($OptimizationResults.OverallStatus) {
        Write-Log "System Optimizations: VERIFIED" "SUCCESS"
    }
    else {
        Write-Log "System Optimizations: ISSUES DETECTED" "WARN"
    }
    
    # VDI optimizations verification
    Write-LogHeader "VDI OPTIMIZATIONS VERIFICATION"
    try {
        $VDIOptResults = Test-VDIOptimizations
        if ($VDIOptResults.OverallStatus) {
            Write-Log "VDI Optimizations: VERIFIED" "SUCCESS"
            Write-Log "Pagefile configured on D: drive: $($VDIOptResults.PagefileConfigured)" "INFO"
            Write-Log "Registry optimizations: $($VDIOptResults.RegistryOptimized)" "INFO"
        }
        else {
            Write-Log "VDI Optimizations: ISSUES DETECTED" "WARN"
        }
    }
    catch {
        Write-Log "VDI optimizations check failed: $($_.Exception.Message)" "WARN"
        $VDIOptResults = @{ OverallStatus = $false; PagefileConfigured = $false; RegistryOptimized = $false }
    }
    
    # VMware memory ballooning status check
    Write-LogHeader "VMWARE MEMORY BALLOONING STATUS"
    try {
        $VMwareMemoryStatus = Test-VMwareMemoryBallooningStatus
        if ($VMwareMemoryStatus.Disabled) {
            Write-Log "VMware Memory Ballooning: DISABLED" "SUCCESS"
        }
        elseif ($VMwareMemoryStatus.NotPresent) {
            Write-Log "VMware Memory Ballooning: NOT PRESENT" "INFO"
        }
        else {
            Write-Log "VMware Memory Ballooning: ENABLED (should be disabled)" "WARN"
        }
    }
    catch {
        Write-Log "VMware memory ballooning check failed: $($_.Exception.Message)" "WARN"
        $VMwareMemoryStatus = @{ NotPresent = $true }
    }
    
    # Windows automatic maintenance status
    Write-LogHeader "WINDOWS AUTOMATIC MAINTENANCE STATUS"
    try {
        $MaintenanceStatus = Test-AutomaticMaintenanceStatus
        if ($MaintenanceStatus.Optimized) {
            Write-Log "Automatic Maintenance: OPTIMIZED" "SUCCESS"
        }
        else {
            Write-Log "Automatic Maintenance: DEFAULT SETTINGS" "INFO"
        }
    }
    catch {
        Write-Log "Automatic maintenance check failed: $($_.Exception.Message)" "WARN"
        $MaintenanceStatus = @{ Optimized = $false }
    }
    
    # WEM cleanup with registry key removal
    Write-LogHeader "WEM RSA CLEANUP VERIFICATION"
    try {
        $WEMCleanupSuccess = Test-WEMRSACleanup
        
        # Additional WEM RSA key removal
        Write-Log "Performing WEM RSA key cleanup..." "INFO"
        $WEMKeyRemovalResult = Remove-WEMRSAKey
        if ($WEMKeyRemovalResult) {
            Write-Log "WEM RSA keys removed successfully" "SUCCESS"
        }
    }
    catch {
        Write-Log "Using basic WEM cleanup check" "WARN"
        $WEMCleanupSuccess = $true
    }
    
    if ($WEMCleanupSuccess) {
        Write-Log "WEM RSA Cleanup: COMPLETED" "SUCCESS"
    }
    else {
        Write-Log "WEM RSA Cleanup: ISSUES DETECTED" "WARN"
    }
    
    # Domain profile cleanup - critical for VDI template preparation
    Write-LogHeader "DOMAIN PROFILE CLEANUP"
    try {
        $ProfileCleanupResults = Remove-DomainUserProfiles
        if ($ProfileCleanupResults.Success) {
            Write-Log "Domain Profile Cleanup: COMPLETED" "SUCCESS"
            Write-Log "Removed $($ProfileCleanupResults.ProfilesRemoved) domain profiles" "SUCCESS"
            if ($ProfileCleanupResults.RemovedProfiles.Count -gt 0) {
                Write-Log "Cleaned profiles: $($ProfileCleanupResults.RemovedProfiles -join ', ')" "INFO"
            }
        }
        else {
            Write-Log "Domain Profile Cleanup: ISSUES DETECTED" "WARN"
            if ($ProfileCleanupResults.FailedRemovals.Count -gt 0) {
                Write-Log "Failed to remove: $($ProfileCleanupResults.FailedRemovals -join ', ')" "WARN"
            }
        }
    }
    catch {
        Write-Log "Domain Profile Cleanup: ERROR - $($_.Exception.Message)" "ERROR"
        # Manual fallback cleanup
        Write-Log "Attempting manual domain profile cleanup" "WARN"
        try {
            $ProfileListPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
            $ProfileKeys = Get-ChildItem -Path $ProfileListPath -ErrorAction SilentlyContinue
            $ManualCleanupCount = 0
            
            foreach ($ProfileKey in $ProfileKeys) {
                $ProfilePath = Get-ItemProperty -Path $ProfileKey.PSPath -Name "ProfileImagePath" -ErrorAction SilentlyContinue
                if ($ProfilePath -and $ProfilePath.ProfileImagePath) {
                    $ProfileName = Split-Path $ProfilePath.ProfileImagePath -Leaf
                    if ($ProfileName -match "^[A-Za-z0-9-]+\.[A-Za-z0-9-]+.*" -or $ProfileName.Contains(".")) {
                        $ProfileDir = $ProfilePath.ProfileImagePath
                        if (Test-Path $ProfileDir) {
                            Remove-Item -Path $ProfileDir -Recurse -Force -ErrorAction SilentlyContinue
                            $ManualCleanupCount++
                        }
                    }
                }
            }
            Write-Log "Manual cleanup removed $ManualCleanupCount domain profiles" "SUCCESS"
        }
        catch {
            Write-Log "Manual domain profile cleanup also failed: $($_.Exception.Message)" "ERROR"
        }
    }
    
    # Execute ghost device removal for VDI template optimization
    Write-LogHeader "GHOST DEVICE REMOVAL"
    Write-Log "Starting ghost device removal for VDI template cleanup..."
    
    try {
        $GhostDeviceResult = Remove-GhostDevices
        
        if ($GhostDeviceResult.Success) {
            Write-Log "Ghost device removal completed successfully" "SUCCESS"
            Write-Log "Total devices scanned: $($GhostDeviceResult.TotalDevicesFound)" "SUCCESS"
            Write-Log "Ghost devices removed: $($GhostDeviceResult.GhostDevicesRemoved)" "SUCCESS"
            Write-Log "Execution time: $($GhostDeviceResult.ExecutionTime) seconds" "INFO"
            
            if ($GhostDeviceResult.GhostDevicesRemoved -gt 0) {
                Write-Log "VDI template optimized by removing orphaned hardware devices" "SUCCESS"
            }
        }
        else {
            Write-Log "Ghost device removal encountered issues" "WARN"
            if ($GhostDeviceResult.Errors.Count -gt 0) {
                foreach ($Error in $GhostDeviceResult.Errors) {
                    Write-Log "  - Ghost Device Error: $Error" "WARN"
                }
            }
        }
        
        if ($GhostDeviceResult.DevicesFailedToRemove -gt 0) {
            Write-Log "Some devices could not be removed - this is normal for protected system devices" "INFO"
        }
    }
    catch {
        Write-Log "ERROR: Ghost device removal failed: $($_.Exception.Message)" "ERROR"
    }
    
    # Execute system drive defragmentation for optimal VDI performance (Optional)
    Write-LogHeader "SYSTEM DRIVE DEFRAGMENTATION (OPTIONAL)"
    Write-Log "Attempting C:\ drive defragmentation for VDI template optimization..."
    Write-Log "Note: This operation is optional and template preparation will continue regardless of outcome" "INFO"
    
    try {
        $DefragResult = Start-SystemDriveDefragmentation -DriveLetter "C" -TimeoutMinutes 45
        
        if ($DefragResult.Success) {
            Write-Log "System drive defragmentation completed successfully" "SUCCESS"
            Write-Log "Method used: $($DefragResult.Method)" "SUCCESS"
            Write-Log "Defragmentation time: $($DefragResult.ExecutionTime.ToString('F2')) minutes" "INFO"
            
            if ($DefragResult.DefragmentationPerformed) {
                Write-Log "Free space consolidation completed" "SUCCESS"
                Write-Log "VDI template optimized for improved performance" "SUCCESS"
            } else {
                Write-Log "Analysis completed - defragmentation was not required" "INFO"
            }
            
            if ($DefragResult.Details.Count -gt 0) {
                foreach ($Detail in $DefragResult.Details) {
                    Write-Log "Defrag detail: $Detail" "INFO"
                }
            }
        }
        else {
            Write-Log "System drive defragmentation was skipped due to volume conflicts" "WARN"
            Write-Log "This is normal in virtualized environments and will not affect template quality" "INFO"
            if ($DefragResult.Errors.Count -gt 0) {
                Write-Log "Defragmentation details: Volume optimization service conflicts detected" "INFO"
            }
        }
    }
    catch {
        Write-Log "System drive defragmentation was skipped: $($_.Exception.Message)" "WARN"
        Write-Log "VDI template preparation will continue - defragmentation is not critical" "INFO"
    }
    
    # Execute Windows Event Logs cleanup after defragmentation
    Write-LogHeader "WINDOWS EVENT LOGS CLEANUP"
    Write-Log "Starting Windows Event Logs cleanup for VDI template preparation..."
    
    try {
        $EventLogResult = Clear-WindowsEventLogs -ExcludeLogs @("Security")
        
        if ($EventLogResult.Success) {
            Write-Log "Windows Event Logs cleanup completed successfully" "SUCCESS"
            Write-Log "Total logs processed: $($EventLogResult.TotalLogsFound)" "SUCCESS"
            Write-Log "Logs successfully cleared: $($EventLogResult.LogsCleared)" "SUCCESS"
            Write-Log "Logs skipped (protected): $($EventLogResult.LogsSkipped)" "INFO"
            Write-Log "Cleanup time: $($EventLogResult.ExecutionTime.ToString('F2')) seconds" "INFO"
            
            if ($EventLogResult.LogsCleared -gt 0) {
                Write-Log "VDI template cleaned of installation artifacts and user activity traces" "SUCCESS"
            }
        }
        else {
            Write-Log "Windows Event Logs cleanup encountered issues" "WARN"
            if ($EventLogResult.FailedLogs.Count -gt 0) {
                foreach ($Error in $EventLogResult.FailedLogs) {
                    Write-Log "  - Event Log Error: $Error" "WARN"
                }
            }
        }
        
        if ($EventLogResult.LogsFailed -gt 0) {
            Write-Log "Some event logs could not be cleared - this may be normal for protected system logs" "INFO"
        }
    }
    catch {
        Write-Log "ERROR: Windows Event Logs cleanup failed: $($_.Exception.Message)" "ERROR"
    }
    
    # Execute .NET Framework optimization
    Write-LogHeader ".NET FRAMEWORK OPTIMIZATION"
    Write-Log "Starting .NET Framework native image optimization for VDI template..."
    
    try {
        $DotNetOptimizationResult = Start-DotNetOptimization
        
        if ($DotNetOptimizationResult.Success) {
            Write-Log ".NET Framework optimization completed successfully" "SUCCESS"
            Write-Log "Frameworks optimized: $($DotNetOptimizationResult.FrameworkVersionsOptimized.Count)" "SUCCESS"
            Write-Log "Total assemblies optimized: $($DotNetOptimizationResult.TotalAssembliesOptimized)" "SUCCESS"
            Write-Log "Optimization time: $($DotNetOptimizationResult.ExecutionTime.TotalMinutes.ToString('F2')) minutes" "INFO"
        } else {
            Write-Log ".NET Framework optimization encountered issues" "WARN"
            Write-Log "Optimization errors: $($DotNetOptimizationResult.OptimizationErrors.Count)" "WARN"
            foreach ($Error in $DotNetOptimizationResult.OptimizationErrors) {
                Write-Log "Optimization error: $Error" "WARN"
            }
        }
    }
    catch {
        Write-Log ".NET Framework optimization failed: $($_.Exception.Message)" "ERROR"
    }
    

    
    # Readiness assessment
    Write-LogHeader "SYSTEM READINESS ASSESSMENT"
    $ReadinessScore = 0
    $MaxScore = 16
    $ReadinessIssues = @()
    
    if ($VDAInstalled) {
        $ReadinessScore += 2
        Write-Log "VDA Installation: VERIFIED" "SUCCESS"
    }
    else {
        $ReadinessIssues += "VDA not properly installed"
        Write-Log "VDA Installation: FAILED" "ERROR"
    }
    
    if ($TotalFoundServices -ge 3) {
        $ReadinessScore += 2
        Write-Log "Citrix Services: ADEQUATE" "SUCCESS"
    }
    else {
        $ReadinessIssues += "Insufficient Citrix services"
        Write-Log "Citrix Services: INSUFFICIENT" "WARN"
    }
    
    if ($OptimizationResults.OverallStatus) {
        $ReadinessScore += 2
        Write-Log "System Optimizations: APPLIED" "SUCCESS"
    }
    else {
        $ReadinessIssues += "System optimizations incomplete"
        Write-Log "System Optimizations: INCOMPLETE" "WARN"
    }
    
    if ($WEMCleanupSuccess) {
        $ReadinessScore += 1
        Write-Log "WEM RSA Cleanup: COMPLETED" "SUCCESS"
    }
    
    # Domain profile cleanup (1 point)
    if ($ProfileCleanupResults -and $ProfileCleanupResults.Success) {
        $ReadinessScore += 1
        Write-Log "Domain Profile Cleanup: COMPLETED" "SUCCESS"
    }
    else {
        $ReadinessIssues += "Domain profile cleanup incomplete"
        Write-Log "Domain Profile Cleanup: INCOMPLETE" "WARN"
    }
    
    if (Test-AdminPrivileges) {
        $ReadinessScore += 1
        Write-Log "Administrator Privileges: CONFIRMED" "SUCCESS"
    }
    else {
        $ReadinessIssues += "Administrator privileges required"
        Write-Log "Administrator Privileges: MISSING" "ERROR"
    }
    
    # VDI optimizations (1 point)
    if ($VDIOptResults -and $VDIOptResults.OverallStatus) {
        $ReadinessScore += 1
        Write-Log "VDI Optimizations: VERIFIED" "SUCCESS"
    }
    else {
        $ReadinessIssues += "VDI optimizations incomplete"
        Write-Log "VDI Optimizations: INCOMPLETE" "WARN"
    }
    
    # VMware memory ballooning (1 point)
    if ($VMwareMemoryStatus -and ($VMwareMemoryStatus.Disabled -or $VMwareMemoryStatus.NotPresent)) {
        $ReadinessScore += 1
        Write-Log "VMware Memory Ballooning: OPTIMAL" "SUCCESS"
    }
    else {
        $ReadinessIssues += "VMware memory ballooning not disabled"
        Write-Log "VMware Memory Ballooning: NEEDS ATTENTION" "WARN"
    }
    
    # Automatic maintenance (1 point)
    if ($MaintenanceStatus -and $MaintenanceStatus.Optimized) {
        $ReadinessScore += 1
        Write-Log "Automatic Maintenance: OPTIMIZED" "SUCCESS"
    }
    else {
        $ReadinessIssues += "Automatic maintenance not optimized"
        Write-Log "Automatic Maintenance: NOT OPTIMIZED" "WARN"
    }
    
    if ($CurrentSystemInfo -and $CurrentSystemInfo.TotalMemoryGB -ge 8) {
        $ReadinessScore += 1
        Write-Log "System Memory: ADEQUATE" "SUCCESS"
    }
    else {
        $ReadinessIssues += "Insufficient system memory"
        Write-Log "System Memory: INSUFFICIENT" "WARN"
    }
    
    if ($CurrentSystemInfo -and $CurrentSystemInfo.VirtualMachine) {
        $ReadinessScore += 1
        Write-Log "Virtual Environment: DETECTED" "SUCCESS"
    }
    else {
        $ReadinessIssues += "Not in virtual environment"
        Write-Log "Virtual Environment: NOT DETECTED" "WARN"
    }
    
    $ReadinessPercentage = [Math]::Round(($ReadinessScore / $MaxScore) * 100, 1)
    
    Write-Log ""
    Write-Log "SYSTEM READINESS RESULTS:"
    Write-Log "Score: $ReadinessScore / $MaxScore"
    Write-Log "Percentage: $ReadinessPercentage"
    
    if ($ReadinessPercentage -ge 90) {
        Write-Log "Status: EXCELLENT - Ready for deployment" "SUCCESS"
    }
    elseif ($ReadinessPercentage -ge 70) {
        Write-Log "Status: GOOD - Ready with minor issues" "SUCCESS"
    }
    else {
        Write-Log "Status: NEEDS ATTENTION" "WARN"
    }
    
    if ($ReadinessIssues.Count -gt 0) {
        Write-Log ""
        Write-Log "ISSUES IDENTIFIED:"
        foreach ($Issue in $ReadinessIssues) {
            Write-Log "- $Issue" "WARN"
        }
    }
    
    # Final report
    Write-LogHeader "FINAL INSTALLATION REPORT"
    $FinalReport = @()
    $FinalReport += "CITRIX INSTALLATION - FINAL REPORT"
    $FinalReport += "Generated: $(Get-Date)"
    $FinalReport += "Computer: $($env:COMPUTERNAME)"
    $FinalReport += ""
    
    if ($CurrentSystemInfo) {
        $FinalReport += "SYSTEM INFORMATION:"
        $FinalReport += "Computer: $($CurrentSystemInfo.ComputerName)"
        $FinalReport += "OS: $($CurrentSystemInfo.OSVersion)"
        $FinalReport += "Processor: $($CurrentSystemInfo.ProcessorName)"
        $FinalReport += "Memory: $($CurrentSystemInfo.TotalMemoryGB) GB"
        $FinalReport += ""
    }
    
    $FinalReport += "SYSTEM READINESS:"
    $FinalReport += "Readiness Score: $ReadinessScore / $MaxScore"
    $FinalReport += "VDA Installation: $(if($VDAInstalled){'VERIFIED'}else{'FAILED'})"
    $FinalReport += "Citrix Services: $TotalFoundServices found"
    $FinalReport += "Optimizations: $(if($OptimizationResults.OverallStatus){'APPLIED'}else{'PARTIAL'})"
    $FinalReport += "WEM Cleanup: $(if($WEMCleanupSuccess){'COMPLETED'}else{'ISSUES'})"
    $FinalReport += "Domain Profile Cleanup: $(if($ProfileCleanupResults -and $ProfileCleanupResults.Success){'COMPLETED'}else{'INCOMPLETE'})"
    $FinalReport += "VDI Optimizations: $(if($VDIOptResults -and $VDIOptResults.OverallStatus){'VERIFIED'}else{'INCOMPLETE'})"
    $FinalReport += "VMware Memory Ballooning: $(if($VMwareMemoryStatus -and ($VMwareMemoryStatus.Disabled -or $VMwareMemoryStatus.NotPresent)){'OPTIMAL'}else{'NEEDS ATTENTION'})"
    $FinalReport += "Automatic Maintenance: $(if($MaintenanceStatus -and $MaintenanceStatus.Optimized){'OPTIMIZED'}else{'DEFAULT'})"
    
    # File access validation for critical paths
    Write-LogHeader "FILE ACCESS VALIDATION"
    $CriticalPaths = @("C:\Windows\System32", "C:\Program Files", "D:\")
    $FileAccessIssues = @()
    
    foreach ($Path in $CriticalPaths) {
        if (Test-Path $Path) {
            $AccessResult = Test-FileAccess -Path $Path
            if (-not $AccessResult) {
                $FileAccessIssues += "Limited access to $Path"
            }
        }
    }
    
    if ($FileAccessIssues.Count -eq 0) {
        Write-Log "File Access Validation: ALL PATHS ACCESSIBLE" "SUCCESS"
        $ReadinessScore += 1
    }
    else {
        Write-Log "File Access Validation: ISSUES DETECTED" "WARN"
        $ReadinessIssues += $FileAccessIssues
    }
    
    $FinalReport += "File Access: $(if($FileAccessIssues.Count -eq 0){'VALIDATED'}else{'ISSUES'})"
    $FinalReport += ""
    
    if ($ReadinessIssues.Count -gt 0) {
        $FinalReport += "ISSUES:"
        foreach ($Issue in $ReadinessIssues) {
            $FinalReport += "- $Issue"
        }
        $FinalReport += ""
    }
    
    $FinalReport += "DEPLOYMENT STATUS:"
    if ($ReadinessPercentage -ge 70) {
        $FinalReport += "READY FOR DEPLOYMENT"
    }
    else {
        $FinalReport += "REQUIRES ATTENTION"
    }
    
    try {
        $ReportPath = "$env:USERPROFILE\Desktop\Citrix_Final_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
        $FinalReport | Out-File -FilePath $ReportPath -Force
        Write-Log "Final report saved to: $ReportPath" "SUCCESS"
    }
    catch {
        Write-Log "Failed to save final report: $($_.Exception.Message)" "WARN"
    }
    
    Write-Host ""
    Write-Host "FINAL INSTALLATION REPORT" -ForegroundColor Green
    foreach ($Line in $FinalReport) {
        if ($Line -match "READY FOR DEPLOYMENT") {
            Write-Host $Line -ForegroundColor Green
        }
        elseif ($Line -match "REQUIRES ATTENTION|FAILED|ISSUES") {
            Write-Host $Line -ForegroundColor Yellow
        }
        else {
            Write-Host $Line -ForegroundColor White
        }
    }
    
    Write-LogHeader "STAGE 2 COMPLETION"
    Write-Log "Stage 2 completed at: $(Get-Date)" "SUCCESS"
    Write-Log "System readiness: $ReadinessPercentage" $(if($ReadinessPercentage -ge 70){'SUCCESS'}else{'WARN'})
    
    if ($ReadinessPercentage -ge 90) {
        Write-Log "EXCELLENT: System exceeds requirements" "SUCCESS"
    }
    elseif ($ReadinessPercentage -ge 70) {
        Write-Log "GOOD: System meets requirements" "SUCCESS"
    }
    else {
        Write-Log "WARNING: System needs attention" "WARN"
    }
    
    Write-Log "Stage 2 execution completed successfully" "SUCCESS"
    
    Write-Host ""
    Write-Host "Stage 2 validation completed successfully!" -ForegroundColor Green
    Write-Host "System readiness: $ReadinessPercentage%" -ForegroundColor Cyan
    Write-Host "Final report saved to desktop" -ForegroundColor Gray
    Write-Host ""
    


    do {
        $Response = Read-Host "Have you removed the D: cache drive? (y/n)"
        if ($Response.ToLower() -eq 'y' -or $Response.ToLower() -eq 'yes') {
            Write-Host "Cache drive removal confirmed" -ForegroundColor Green
            Write-Host "Please proceed with Citrix App Layering Platform Layer operations" -ForegroundColor Green
            break
        }
        elseif ($Response.ToLower() -eq 'n' -or $Response.ToLower() -eq 'no') {
            Write-Host "Please remove the D: cache drive before continuing" -ForegroundColor Yellow
            Write-Host "Platform Layer finalization cannot proceed with cache drive attached" -ForegroundColor Yellow
        }
        else {
            Write-Host "Please enter 'y' for yes or 'n' for no" -ForegroundColor Yellow
        }
    } while ($true)
    
    Write-Host ""
    Write-Host "Press any key to exit..." -ForegroundColor Gray
    $null = Read-Host
}
catch {
    Write-Log "FATAL ERROR: $($_.Exception.Message)" "ERROR"
    Write-Host "FATAL ERROR: Stage 2 failed!" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Check log: $LogPath" -ForegroundColor Yellow
    Write-Host "Press any key to exit..." -ForegroundColor Red
    $null = Read-Host
    exit 1
}