# Fixed Stage 2 Script with Clean 22-Operation Readiness Assessment
# This script replaces the corrupted version with proper scoring logic

# Import the functions library
try {
    Import-Module ".\citrix_functions_library.psm1" -Force -ErrorAction Stop
    Write-Host "Functions library imported successfully" -ForegroundColor Green
}
catch {
    Write-Host "Error importing functions library: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Initialize global variables
$Global:LogFile = ""
$Global:ScriptStartTime = Get-Date
$PasswordAgeResult = $false
$RecycleBinResult = $false
$QuickAccessResult = $false
$MaintenanceStatus = @{ Optimized = $false }

# Start execution
try {
    Write-LogHeader "CITRIX STAGE 2 DEPLOYMENT"
    Write-Log "Starting Stage 2 deployment at $(Get-Date)" "INFO"
    
    # Initialize system info
    $CurrentSystemInfo = Get-SystemInformation
    if ($CurrentSystemInfo) {
        Write-Log "System detected: $($CurrentSystemInfo.ComputerName) - $($CurrentSystemInfo.OSVersion)" "INFO"
        Write-Log "Memory: $($CurrentSystemInfo.TotalMemoryGB) GB" "INFO"
    }
    
    # VDA Detection
    Write-LogHeader "VDA DETECTION"
    $VDAInstalled = Test-VDAInstallation
    if ($VDAInstalled) {
        Write-Log "VDA installation detected successfully" "SUCCESS"
    } else {
        Write-Log "VDA installation not detected" "WARN"
    }
    
    # Citrix Services Detection
    Write-LogHeader "CITRIX SERVICES DETECTION"
    $CitrixServices = Get-CitrixServices
    $TotalFoundServices = $CitrixServices.Count
    Write-Log "Found $TotalFoundServices Citrix services" "INFO"
    
    # System Optimizations
    Write-LogHeader "SYSTEM OPTIMIZATIONS"
    try {
        $OptimizationResults = Invoke-SystemOptimizations
        Write-Log "System optimizations completed" "SUCCESS"
    }
    catch {
        Write-Log "System optimizations failed: $($_.Exception.Message)" "ERROR"
        $OptimizationResults = @{ OverallStatus = $false }
    }
    
    # VDI Optimizations
    Write-LogHeader "VDI OPTIMIZATIONS"
    try {
        $VDIOptResults = Invoke-VDIOptimizations
        Write-Log "VDI optimizations completed" "SUCCESS"
    }
    catch {
        Write-Log "VDI optimizations failed: $($_.Exception.Message)" "ERROR"
        $VDIOptResults = @{ OverallStatus = $false; Success = $false }
    }
    
    # WEM RSA Cleanup
    Write-LogHeader "WEM RSA CLEANUP"
    try {
        $WEMCleanupSuccess = Invoke-WEMCleanup
        if ($WEMCleanupSuccess) {
            Write-Log "WEM RSA cleanup completed successfully" "SUCCESS"
        } else {
            Write-Log "WEM RSA cleanup completed with warnings" "WARN"
        }
    }
    catch {
        Write-Log "WEM RSA cleanup failed: $($_.Exception.Message)" "ERROR"
        $WEMCleanupSuccess = $false
    }
    
    # Domain Profile Cleanup
    Write-LogHeader "DOMAIN PROFILE CLEANUP"
    try {
        $ProfileCleanupResults = Invoke-ProfileCleanup
        if ($ProfileCleanupResults.Success) {
            Write-Log "Domain profile cleanup completed successfully" "SUCCESS"
        }
    }
    catch {
        Write-Log "Domain profile cleanup failed: $($_.Exception.Message)" "ERROR"
        $ProfileCleanupResults = @{ Success = $false }
    }
    
    # VMware Memory Optimization
    Write-LogHeader "VMWARE MEMORY OPTIMIZATION"
    try {
        $VMwareMemoryStatus = Disable-VMwareMemoryBallooning
        if ($VMwareMemoryStatus.Success) {
            Write-Log "VMware memory optimization completed" "SUCCESS"
        }
    }
    catch {
        Write-Log "VMware memory optimization failed: $($_.Exception.Message)" "ERROR"
        $VMwareMemoryStatus = @{ Success = $false; OverallCompliant = $false }
    }
    
    # Password Age Registry Cleanup
    Write-LogHeader "PASSWORD AGE REGISTRY CLEANUP"
    try {
        $PasswordAgeResult = Remove-PasswordAgeRegistry
        if ($PasswordAgeResult) {
            Write-Log "Password age registry cleanup completed" "SUCCESS"
        } else {
            Write-Log "Password age registry cleanup - no action needed" "INFO"
        }
    }
    catch {
        Write-Log "Password age registry cleanup failed: $($_.Exception.Message)" "ERROR"
        $PasswordAgeResult = $false
    }
    
    # RDS Grace Period Reset
    Write-LogHeader "RDS GRACE PERIOD RESET"
    try {
        $RDSGraceResult = Reset-RDSGracePeriod
        if ($RDSGraceResult.Success) {
            Write-Log "RDS grace period reset completed" "SUCCESS"
        }
    }
    catch {
        Write-Log "RDS grace period reset failed: $($_.Exception.Message)" "ERROR"
        $RDSGraceResult = @{ Success = $false }
    }
    
    # Network Optimizations
    Write-LogHeader "NETWORK OPTIMIZATIONS"
    try {
        $NetworkOptResults = Optimize-NetworkSettings
        if ($NetworkOptResults.Success) {
            Write-Log "Network optimizations completed" "SUCCESS"
        }
    }
    catch {
        Write-Log "Network optimizations failed: $($_.Exception.Message)" "ERROR"
        $NetworkOptResults = @{ Success = $false }
    }
    
    # Storage Optimizations
    Write-LogHeader "STORAGE OPTIMIZATIONS"
    try {
        $StorageOptResults = Optimize-StorageSettings
        if ($StorageOptResults.Success) {
            Write-Log "Storage optimizations completed" "SUCCESS"
        }
    }
    catch {
        Write-Log "Storage optimizations failed: $($_.Exception.Message)" "ERROR"
        $StorageOptResults = @{ Success = $false }
    }
    
    # Ghost Device Removal
    Write-LogHeader "GHOST DEVICE REMOVAL"
    try {
        $GhostDeviceResults = Remove-GhostDevices
        if ($GhostDeviceResults.Success) {
            Write-Log "Ghost device removal completed" "SUCCESS"
        }
    }
    catch {
        Write-Log "Ghost device removal failed: $($_.Exception.Message)" "ERROR"
        $GhostDeviceResults = @{ Success = $false }
    }
    
    # System Defragmentation
    Write-LogHeader "SYSTEM DEFRAGMENTATION"
    try {
        $DefragResults = Invoke-SystemDefragmentation
        if ($DefragResults.Success -or $DefragResults.Skipped) {
            Write-Log "System defragmentation completed" "SUCCESS"
        }
    }
    catch {
        Write-Log "System defragmentation failed: $($_.Exception.Message)" "ERROR"
        $DefragResults = @{ Success = $false; Skipped = $false }
    }
    
    # Event Logs Cleanup
    Write-LogHeader "EVENT LOGS CLEANUP"
    try {
        $EventLogCleanupResults = Clear-EventLogs
        if ($EventLogCleanupResults.Success) {
            Write-Log "Event logs cleanup completed" "SUCCESS"
        }
    }
    catch {
        Write-Log "Event logs cleanup failed: $($_.Exception.Message)" "ERROR"
        $EventLogCleanupResults = @{ Success = $false }
    }
    
    # .NET Framework Optimization
    Write-LogHeader ".NET FRAMEWORK OPTIMIZATION"
    try {
        $DotNetResults = Optimize-DotNetFramework
        if ($DotNetResults.Success) {
            Write-Log ".NET Framework optimization completed" "SUCCESS"
        }
    }
    catch {
        Write-Log ".NET Framework optimization failed: $($_.Exception.Message)" "ERROR"
        $DotNetResults = @{ Success = $false }
    }
    
    # Automatic Maintenance Disable
    Write-LogHeader "AUTOMATIC MAINTENANCE CONFIGURATION"
    try {
        $MaintenanceStatus = Disable-AutomaticMaintenance
        if ($MaintenanceStatus.Optimized) {
            Write-Log "Automatic maintenance disabled successfully" "SUCCESS"
        }
    }
    catch {
        Write-Log "Automatic maintenance configuration failed: $($_.Exception.Message)" "ERROR"
        $MaintenanceStatus = @{ Optimized = $false }
    }
    
    # Recycle Bin Disable
    Write-LogHeader "RECYCLE BIN CONFIGURATION"
    try {
        $RecycleBinResult = Disable-RecycleBinCreation
        if ($RecycleBinResult) {
            Write-Log "Recycle Bin creation disabled successfully" "SUCCESS"
        }
    }
    catch {
        Write-Log "Recycle Bin configuration failed: $($_.Exception.Message)" "ERROR"
        $RecycleBinResult = $false
    }
    
    # Quick Access Disable
    Write-LogHeader "QUICK ACCESS CONFIGURATION"
    try {
        $QuickAccessResult = Disable-QuickAccessAndUserFolders
        if ($QuickAccessResult) {
            Write-Log "Quick Access and user folders disabled successfully" "SUCCESS"
        }
    }
    catch {
        Write-Log "Quick Access configuration failed: $($_.Exception.Message)" "ERROR"
        $QuickAccessResult = $false
    }
    
    # Event Log Redirection
    Write-LogHeader "EVENT LOG REDIRECTION"
    try {
        $EventLogResult = Set-EventLogRedirection
        if ($EventLogResult) {
            Write-Log "Event log redirection configured successfully" "SUCCESS"
        }
    }
    catch {
        Write-Log "Event log redirection failed: $($_.Exception.Message)" "ERROR"
        $EventLogResult = $false
    }
    
    # User Profile Redirection
    Write-LogHeader "USER PROFILE REDIRECTION"
    try {
        $UserProfileResult = Set-UserProfileRedirection
        if ($UserProfileResult) {
            Write-Log "User profile redirection configured successfully" "SUCCESS"
        }
    }
    catch {
        Write-Log "User profile redirection failed: $($_.Exception.Message)" "ERROR"
        $UserProfileResult = $false
    }
    
    # Pagefile Configuration
    Write-LogHeader "PAGEFILE CONFIGURATION"
    try {
        $PagefileResult = Set-PagefileConfiguration
        if ($PagefileResult.Success -or $PagefileResult.Skipped) {
            Write-Log "Pagefile configuration completed successfully" "SUCCESS"
        }
    }
    catch {
        Write-Log "Pagefile configuration failed: $($_.Exception.Message)" "ERROR"
        $PagefileResult = @{ Success = $false; Skipped = $false }
    }
    
    # Virtual Cache Drive Removal
    Write-LogHeader "VIRTUAL CACHE DRIVE REMOVAL"
    try {
        $VirtualCacheRemovalResult = Remove-VirtualCacheDrives
        if ($VirtualCacheRemovalResult.Success -or $VirtualCacheRemovalResult.Skipped) {
            Write-Log "Virtual cache drive removal completed successfully" "SUCCESS"
        }
    }
    catch {
        Write-Log "Virtual cache drive removal failed: $($_.Exception.Message)" "ERROR"
        $VirtualCacheRemovalResult = @{ Success = $false; Skipped = $false }
    }
    
    # Active Setup Components Cleanup
    Write-LogHeader "ACTIVE SETUP COMPONENTS CLEANUP"
    try {
        $ActiveSetupResult = Clear-ActiveSetupComponents
        if ($ActiveSetupResult.Success) {
            Write-Log "Active Setup cleanup completed: $($ActiveSetupResult.RemovedCount) removed, $($ActiveSetupResult.PreservedCount) preserved" "SUCCESS"
        } else {
            Write-Log "Active Setup cleanup failed" "ERROR"
        }
    }
    catch {
        Write-Log "Active Setup cleanup failed: $($_.Exception.Message)" "ERROR"
        $ActiveSetupResult = @{ Success = $false; RemovedCount = 0; PreservedCount = 0 }
    }

    # CLEAN READINESS ASSESSMENT - EXACTLY 23 OPERATIONS
    Write-LogHeader "SYSTEM READINESS ASSESSMENT"
    $ReadinessScore = 0
    $MaxScore = 23
    $ReadinessIssues = @()
    
    Write-Log "Evaluating 23 Stage 2 operations for readiness assessment..." "INFO"
    
    # 1. VDA Verification
    if ($VDAInstalled) {
        $ReadinessScore += 1
        Write-Log "1. VDA Verification: PASSED" "SUCCESS"
    } else {
        $ReadinessIssues += "VDA verification failed"
        Write-Log "1. VDA Verification: FAILED" "ERROR"
    }
    
    # 2. Citrix Services
    if ($TotalFoundServices -ge 3) {
        $ReadinessScore += 1
        Write-Log "2. Citrix Services: ADEQUATE ($TotalFoundServices found)" "SUCCESS"
    } else {
        $ReadinessIssues += "Insufficient Citrix services"
        Write-Log "2. Citrix Services: INSUFFICIENT ($TotalFoundServices found)" "WARN"
    }
    
    # 3. System Optimizations
    if ($OptimizationResults -and $OptimizationResults.OverallStatus) {
        $ReadinessScore += 1
        Write-Log "3. System Optimizations: VERIFIED" "SUCCESS"
    } else {
        $ReadinessIssues += "System optimizations incomplete"
        Write-Log "3. System Optimizations: INCOMPLETE" "WARN"
    }
    
    # 4. VDI Optimizations
    if ($VDIOptResults -and ($VDIOptResults.OverallStatus -or $VDIOptResults.Success)) {
        $ReadinessScore += 1
        Write-Log "4. VDI Optimizations: COMPLETED" "SUCCESS"
    } else {
        $ReadinessIssues += "VDI optimizations incomplete"
        Write-Log "4. VDI Optimizations: INCOMPLETE" "WARN"
    }
    
    # 5. WEM RSA Cleanup
    if ($WEMCleanupSuccess) {
        $ReadinessScore += 1
        Write-Log "5. WEM RSA Cleanup: COMPLETED" "SUCCESS"
    } else {
        $ReadinessIssues += "WEM RSA cleanup incomplete"
        Write-Log "5. WEM RSA Cleanup: INCOMPLETE" "WARN"
    }
    
    # 6. Domain Profile Cleanup
    if ($ProfileCleanupResults -and $ProfileCleanupResults.Success) {
        $ReadinessScore += 1
        Write-Log "6. Domain Profile Cleanup: COMPLETED" "SUCCESS"
    } else {
        $ReadinessIssues += "Domain profile cleanup incomplete"
        Write-Log "6. Domain Profile Cleanup: INCOMPLETE" "WARN"
    }
    
    # 7. VMware Memory Optimization
    if ($VMwareMemoryStatus -and ($VMwareMemoryStatus.Success -or $VMwareMemoryStatus.OverallCompliant)) {
        $ReadinessScore += 1
        Write-Log "7. VMware Memory Optimization: OPTIMIZED" "SUCCESS"
    } else {
        $ReadinessIssues += "VMware memory optimization incomplete"
        Write-Log "7. VMware Memory Optimization: INCOMPLETE" "WARN"
    }
    
    # 8. Password Age Registry
    if ($PasswordAgeResult) {
        $ReadinessScore += 1
        Write-Log "8. Password Age Registry: CLEANED" "SUCCESS"
    } else {
        $ReadinessIssues += "Password age registry cleanup incomplete"
        Write-Log "8. Password Age Registry: INCOMPLETE" "WARN"
    }
    
    # 9. RDS Grace Period Reset
    if ($RDSGraceResult -and $RDSGraceResult.Success) {
        $ReadinessScore += 1
        Write-Log "9. RDS Grace Period Reset: COMPLETED" "SUCCESS"
    } else {
        $ReadinessIssues += "RDS grace period reset incomplete"
        Write-Log "9. RDS Grace Period Reset: INCOMPLETE" "WARN"
    }
    
    # 10. Network Optimizations
    if ($NetworkOptResults -and $NetworkOptResults.Success) {
        $ReadinessScore += 1
        Write-Log "10. Network Optimizations: COMPLETED" "SUCCESS"
    } else {
        $ReadinessIssues += "Network optimizations incomplete"
        Write-Log "10. Network Optimizations: INCOMPLETE" "WARN"
    }
    
    # 11. Storage Optimizations
    if ($StorageOptResults -and $StorageOptResults.Success) {
        $ReadinessScore += 1
        Write-Log "11. Storage Optimizations: COMPLETED" "SUCCESS"
    } else {
        $ReadinessIssues += "Storage optimizations incomplete"
        Write-Log "11. Storage Optimizations: INCOMPLETE" "WARN"
    }
    
    # 12. Ghost Device Removal
    if ($GhostDeviceResults -and $GhostDeviceResults.Success) {
        $ReadinessScore += 1
        Write-Log "12. Ghost Device Removal: COMPLETED" "SUCCESS"
    } else {
        $ReadinessIssues += "Ghost device removal incomplete"
        Write-Log "12. Ghost Device Removal: INCOMPLETE" "WARN"
    }
    
    # 13. System Defragmentation
    if ($DefragResults -and ($DefragResults.Success -or $DefragResults.Skipped)) {
        $ReadinessScore += 1
        Write-Log "13. System Defragmentation: COMPLETED" "SUCCESS"
    } else {
        $ReadinessIssues += "System defragmentation incomplete"
        Write-Log "13. System Defragmentation: INCOMPLETE" "WARN"
    }
    
    # 14. Event Logs Cleanup
    if ($EventLogCleanupResults -and $EventLogCleanupResults.Success) {
        $ReadinessScore += 1
        Write-Log "14. Event Logs Cleanup: COMPLETED" "SUCCESS"
    } else {
        $ReadinessIssues += "Event logs cleanup incomplete"
        Write-Log "14. Event Logs Cleanup: INCOMPLETE" "WARN"
    }
    
    # 15. .NET Framework Optimization
    if ($DotNetResults -and $DotNetResults.Success) {
        $ReadinessScore += 1
        Write-Log "15. .NET Framework Optimization: COMPLETED" "SUCCESS"
    } else {
        $ReadinessIssues += ".NET Framework optimization incomplete"
        Write-Log "15. .NET Framework Optimization: INCOMPLETE" "WARN"
    }
    
    # 16. Automatic Maintenance
    if ($MaintenanceStatus -and $MaintenanceStatus.Optimized) {
        $ReadinessScore += 1
        Write-Log "16. Automatic Maintenance: OPTIMIZED" "SUCCESS"
    } else {
        $ReadinessIssues += "Automatic maintenance not optimized"
        Write-Log "16. Automatic Maintenance: NOT OPTIMIZED" "WARN"
    }
    
    # 17. Recycle Bin Disable
    if ($RecycleBinResult) {
        $ReadinessScore += 1
        Write-Log "17. Recycle Bin Disable: COMPLETED" "SUCCESS"
    } else {
        $ReadinessIssues += "Recycle Bin disable incomplete"
        Write-Log "17. Recycle Bin Disable: INCOMPLETE" "WARN"
    }
    
    # 18. Quick Access Disable
    if ($QuickAccessResult) {
        $ReadinessScore += 1
        Write-Log "18. Quick Access Disable: COMPLETED" "SUCCESS"
    } else {
        $ReadinessIssues += "Quick Access disable incomplete"
        Write-Log "18. Quick Access Disable: INCOMPLETE" "WARN"
    }
    
    # 19. Event Log Redirection
    if ($EventLogResult) {
        $ReadinessScore += 1
        Write-Log "19. Event Log Redirection: COMPLETED" "SUCCESS"
    } else {
        $ReadinessIssues += "Event log redirection incomplete"
        Write-Log "19. Event Log Redirection: INCOMPLETE" "WARN"
    }
    
    # 20. User Profile Redirection
    if ($UserProfileResult) {
        $ReadinessScore += 1
        Write-Log "20. User Profile Redirection: COMPLETED" "SUCCESS"
    } else {
        $ReadinessIssues += "User profile redirection incomplete"
        Write-Log "20. User Profile Redirection: INCOMPLETE" "WARN"
    }
    
    # 21. Pagefile Configuration
    if ($PagefileResult -and ($PagefileResult.Success -or $PagefileResult.Skipped)) {
        $ReadinessScore += 1
        Write-Log "21. Pagefile Configuration: COMPLETED" "SUCCESS"
    } else {
        $ReadinessIssues += "Pagefile configuration incomplete"
        Write-Log "21. Pagefile Configuration: INCOMPLETE" "WARN"
    }
    
    # 22. Virtual Cache Drive Removal
    if ($VirtualCacheRemovalResult -and ($VirtualCacheRemovalResult.Success -or $VirtualCacheRemovalResult.Skipped)) {
        $ReadinessScore += 1
        Write-Log "22. Virtual Cache Drive Removal: COMPLETED" "SUCCESS"
    } else {
        $ReadinessIssues += "Virtual cache drive removal incomplete"
        Write-Log "22. Virtual Cache Drive Removal: INCOMPLETE" "WARN"
    }
    
    # 23. Active Setup Components Cleanup
    if ($ActiveSetupResult -and $ActiveSetupResult.Success) {
        $ReadinessScore += 1
        Write-Log "23. Active Setup Components Cleanup: COMPLETED" "SUCCESS"
    } else {
        $ReadinessIssues += "Active Setup components cleanup incomplete"
        Write-Log "23. Active Setup Components Cleanup: INCOMPLETE" "WARN"
    }
    
    # Calculate final results
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
    
    $FinalReport += "READINESS ASSESSMENT:"
    $FinalReport += "Score: $ReadinessScore / $MaxScore ($ReadinessPercentage%)"
    $FinalReport += ""
    
    $FinalReport += "STAGE 2 OPERATIONS COMPLETED:"
    $FinalReport += "- VDA Verification: $(if ($VDAInstalled) { 'PASSED' } else { 'FAILED' })"
    $FinalReport += "- Citrix Services: $TotalFoundServices found"
    $FinalReport += "- System Optimizations: $(if ($OptimizationResults.OverallStatus) { 'COMPLETED' } else { 'INCOMPLETE' })"
    $FinalReport += "- VDI Optimizations: $(if ($VDIOptResults.OverallStatus -or $VDIOptResults.Success) { 'COMPLETED' } else { 'INCOMPLETE' })"
    $FinalReport += "- WEM RSA Cleanup: $(if ($WEMCleanupSuccess) { 'COMPLETED' } else { 'INCOMPLETE' })"
    $FinalReport += "- Domain Profile Cleanup: $(if ($ProfileCleanupResults.Success) { 'COMPLETED' } else { 'INCOMPLETE' })"
    $FinalReport += "- VMware Memory Optimization: $(if ($VMwareMemoryStatus.Success) { 'COMPLETED' } else { 'INCOMPLETE' })"
    $FinalReport += "- Password Age Registry: $(if ($PasswordAgeResult) { 'CLEANED' } else { 'INCOMPLETE' })"
    $FinalReport += "- Active Setup Cleanup: $(if ($ActiveSetupResult.Success) { 'COMPLETED' } else { 'INCOMPLETE' })"
    
    Write-Log ""
    Write-Log "STAGE 2 DEPLOYMENT COMPLETED"
    Write-Log "Total time: $((New-TimeSpan -Start $Global:ScriptStartTime -End (Get-Date)).TotalMinutes.ToString('F2')) minutes"
    
    # Generate HTML report
    try {
        $ReportData = @{
            SystemInfo = $CurrentSystemInfo
            VDAInstalled = $VDAInstalled
            CitrixServices = $CitrixServices
            OptimizationResults = $OptimizationResults
            VDIOptResults = $VDIOptResults
            WEMCleanupSuccess = $WEMCleanupSuccess
            ProfileCleanupResults = $ProfileCleanupResults
            VMwareMemoryStatus = $VMwareMemoryStatus
            PasswordAgeResult = $PasswordAgeResult
            RDSGraceResult = $RDSGraceResult
            NetworkOptResults = $NetworkOptResults
            StorageOptResults = $StorageOptResults
            GhostDeviceResults = $GhostDeviceResults
            DefragResults = $DefragResults
            EventLogCleanupResults = $EventLogCleanupResults
            DotNetResults = $DotNetResults
            MaintenanceStatus = $MaintenanceStatus
            RecycleBinResult = $RecycleBinResult
            QuickAccessResult = $QuickAccessResult
            EventLogResult = $EventLogResult
            UserProfileResult = $UserProfileResult
            PagefileResult = $PagefileResult
            VirtualCacheRemovalResult = $VirtualCacheRemovalResult
            ActiveSetupResult = $ActiveSetupResult
            ReadinessScore = $ReadinessScore
            MaxScore = $MaxScore
            ReadinessPercentage = $ReadinessPercentage
            ReadinessIssues = $ReadinessIssues
            ExecutionTime = (New-TimeSpan -Start $Global:ScriptStartTime -End (Get-Date)).TotalMinutes
        }
        
        $HTMLReportPath = ".\Generate-CitrixReport.ps1"
        if (Test-Path $HTMLReportPath) {
            & $HTMLReportPath -ReportData $ReportData
            Write-Log "HTML report generated successfully" "SUCCESS"
        } else {
            Write-Log "HTML report generator not found" "WARN"
        }
    }
    catch {
        Write-Log "Failed to generate HTML report: $($_.Exception.Message)" "ERROR"
    }
}
catch {
    Write-Log "Critical error in Stage 2 deployment: $($_.Exception.Message)" "ERROR"
    Write-Log "Stack trace: $($_.ScriptStackTrace)" "ERROR"
    exit 1
}
finally {
    Write-Log "Stage 2 deployment script completed at $(Get-Date)" "INFO"
}