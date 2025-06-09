<#
.SYNOPSIS
    Standalone Configuration Validation Script for Citrix Platform Installation
    
.DESCRIPTION
    Comprehensive validation script that verifies all configuration parameters have been
    properly applied to the system. Can be run independently to check system state
    against configuration file specifications.
    
.PARAMETER ConfigFilePath
    Path to the configuration file to validate against
    
.PARAMETER ValidationType
    Type of validation to perform:
    - "Full" - Complete validation of all parameters (default)
    - "Quick" - Essential parameters only  
    - "Report" - Generate detailed validation report
    
.PARAMETER LogPath
    Optional path for validation log output
    
.EXAMPLE
    .\validate_configuration.ps1 -ConfigFilePath "CitrixConfig.txt"
    
.EXAMPLE
    .\validate_configuration.ps1 -ConfigFilePath "CitrixConfig.txt" -ValidationType "Report" -LogPath "validation.log"
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$ConfigFilePath,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Full", "Quick", "Report")]
    [string]$ValidationType = "Full",
    
    [Parameter(Mandatory = $false)]
    [string]$LogPath = ""
)

# Ensure we're running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "ERROR: This script requires Administrator privileges" -ForegroundColor Red
    Write-Host "Please run PowerShell as Administrator and try again" -ForegroundColor Yellow
    Read-Host "Press any key to exit"
    exit 1
}

# Set execution policy for this session
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

Write-Host "Citrix Configuration Validation Tool" -ForegroundColor Cyan
Write-Host "===================================" -ForegroundColor Cyan
Write-Host ""

# Validate configuration file exists
if (-not (Test-Path $ConfigFilePath)) {
    Write-Host "ERROR: Configuration file not found: $ConfigFilePath" -ForegroundColor Red
    Read-Host "Press any key to exit"
    exit 1
}

# Load functions library
$FunctionsLibraryPath = Join-Path $PSScriptRoot "citrix_functions_library.psm1"
if (-not (Test-Path $FunctionsLibraryPath)) {
    Write-Host "ERROR: Functions library not found: $FunctionsLibraryPath" -ForegroundColor Red
    Read-Host "Press any key to exit"
    exit 1
}

try {
    Import-Module $FunctionsLibraryPath -Force
    Write-Host "Functions library loaded successfully" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Failed to load functions library: $($_.Exception.Message)" -ForegroundColor Red
    Read-Host "Press any key to exit"
    exit 1
}

# Set up logging if specified
if ($LogPath) {
    try {
        $LogDir = Split-Path $LogPath -Parent
        if ($LogDir -and -not (Test-Path $LogDir)) {
            New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
        }
        "Validation started at $(Get-Date)" | Out-File -FilePath $LogPath -Force
        Write-Host "Validation log: $LogPath" -ForegroundColor Gray
    } catch {
        Write-Host "WARNING: Could not initialize log file: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "Configuration File: $ConfigFilePath" -ForegroundColor Gray
Write-Host "Validation Type: $ValidationType" -ForegroundColor Gray
Write-Host ""

# Run comprehensive validation
try {
    $ValidationResults = Test-ConfigurationValidation -ConfigFilePath $ConfigFilePath -ValidationType $ValidationType
    
    # Additional summary for standalone execution
    Write-Host ""
    Write-Host "VALIDATION COMPLETE" -ForegroundColor Cyan
    Write-Host "==================" -ForegroundColor Cyan
    
    $SuccessRate = if ($ValidationResults.TotalChecks -gt 0) { 
        [Math]::Round(($ValidationResults.PassedChecks / $ValidationResults.TotalChecks) * 100, 1) 
    } else { 0 }
    
    switch ($SuccessRate) {
        { $_ -ge 95 } { 
            Write-Host "EXCELLENT: System configuration is optimal ($SuccessRate%)" -ForegroundColor Green
            $ExitCode = 0
        }
        { $_ -ge 85 } { 
            Write-Host "GOOD: System configuration is acceptable ($SuccessRate%)" -ForegroundColor Yellow
            $ExitCode = 0
        }
        { $_ -ge 70 } { 
            Write-Host "FAIR: System configuration needs attention ($SuccessRate%)" -ForegroundColor Yellow
            $ExitCode = 1
        }
        default { 
            Write-Host "POOR: System configuration requires immediate attention ($SuccessRate%)" -ForegroundColor Red
            $ExitCode = 2
        }
    }
    
    # Write summary to log if specified
    if ($LogPath) {
        try {
            @"
Validation Summary:
- Total Checks: $($ValidationResults.TotalChecks)
- Passed: $($ValidationResults.PassedChecks)
- Failed: $($ValidationResults.FailedChecks)
- Warnings: $($ValidationResults.WarningChecks)
- Success Rate: $SuccessRate%
- Overall Status: $(if ($SuccessRate -ge 85) { "ACCEPTABLE" } else { "NEEDS ATTENTION" })

Validation completed at $(Get-Date)
"@ | Out-File -FilePath $LogPath -Append
        } catch {
            Write-Host "WARNING: Could not write to log file" -ForegroundColor Yellow
        }
    }
    
    # Provide recommendations based on results
    Write-Host ""
    if ($ValidationResults.FailedChecks -gt 0) {
        Write-Host "RECOMMENDATIONS:" -ForegroundColor Yellow
        Write-Host "- Review failed validations above" -ForegroundColor Yellow
        Write-Host "- Re-run Stage 1 script if installations are missing" -ForegroundColor Yellow
        Write-Host "- Check network connectivity for path-related failures" -ForegroundColor Yellow
        Write-Host "- Verify configuration file parameter values" -ForegroundColor Yellow
    }
    
    if ($ValidationResults.WarningChecks -gt 0) {
        Write-Host "- Review warning items for potential improvements" -ForegroundColor Yellow
    }
    
    if ($ValidationResults.FailedChecks -eq 0 -and $ValidationResults.WarningChecks -eq 0) {
        Write-Host "✓ No issues detected - System ready for production use" -ForegroundColor Green
    }
    
} catch {
    Write-Host "CRITICAL ERROR: Validation process failed" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    $ExitCode = 3
}

Write-Host ""
Write-Host "Press any key to exit..." -ForegroundColor Gray
$null = Read-Host

exit $ExitCode