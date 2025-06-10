# Citrix Installation Scripts - Analysis and Improvements

## Critical Issues

### 1. Missing Function Exports
The following functions are used but not in the export list:
- `Initialize-LoggingSystem`
- `Set-PageFile`
- `Clear-EventLogs`
- `Set-PowerPlan`
- `Disable-WindowsUpdates`
- `Disable-WindowsDefender`
- `Disable-UAC`
- `Enable-RDP`
- `Set-TimeZone`
- `Join-Domain`
- `Set-LocalUserPassword`
- `Set-Autologon`
- `Install-CitrixVDA`
- `Install-CitrixPVSTarget`
- `Install-CitrixWEMAgent`
- `Install-IBMTADDMAgent`
- `Configure-IBMTADDMSCMPermissions`
- `Install-CitrixOptimizer`
- `Optimize-CitrixVDI`
- `Set-RegistryValue`
- `Get-RegistryValue`
- `Test-RegistryPath`
- `New-RegistryPath`
- `Remove-RegistryValue`
- `Set-VDAMultipleMonitorHookKeys`
- `Test-VirtualCacheDrive`

### 2. Undefined Functions Called
Functions called but not defined anywhere:
- `Set-StartupShutdownScripts` (called with wrong parameters in Stage 1)
- `Test-DriveConfiguration` (returns boolean, not object)

### 3. Get-CimInstance Compatibility Issues
The scripts use `Get-CimInstance` which may not be available in all environments. Need fallback to `Get-WmiObject` for older systems.

### 4. Path Handling Issues
- Inconsistent path sanitization (some use `.Replace('\\\\', '\')` but not all)
- Missing validation for UNC paths vs local paths
- No handling for paths with spaces

### 5. Error Handling Gaps
- Many try-catch blocks don't properly clean up resources on failure
- Some functions return different types on success vs failure
- Missing validation for null/empty parameters in several functions

## Recommended Fixes

### Fix 1: Complete the Export List
Add all missing functions to the export list at the end of `citrix_functions_library.psm1`.

### Fix 2: Add Missing Function Definitions
Here are the missing core functions that need to be added:

```powershell
function Set-PageFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [int]$SizeGB = 8,
        
        [Parameter(Mandatory=$false)]
        [string]$DriveLetter = "C"
    )
    
    try {
        Write-Log "Configuring pagefile on ${DriveLetter}: drive with ${SizeGB}GB..."
        
        # Disable automatic pagefile management
        $ComputerSystem = Get-WmiObject -Class Win32_ComputerSystem -EnableAllPrivileges
        $ComputerSystem.AutomaticManagedPagefile = $false
        $ComputerSystem.Put() | Out-Null
        
        # Remove existing pagefiles
        $PageFiles = Get-WmiObject -Class Win32_PageFileSetting
        foreach ($PageFile in $PageFiles) {
            $PageFile.Delete()
        }
        
        # Create new pagefile
        $PageFileSizeMB = $SizeGB * 1024
        Set-WmiInstance -Class Win32_PageFileSetting -Arguments @{
            Name = "${DriveLetter}:\pagefile.sys"
            InitialSize = $PageFileSizeMB
            MaximumSize = $PageFileSizeMB
        } | Out-Null
        
        Write-Log "Pagefile configured successfully: ${DriveLetter}:\pagefile.sys (${SizeGB}GB)" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to configure pagefile: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Test-DriveConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$ConfigFilePath = ".\CitrixConfig.txt"
    )
    
    try {
        Write-Log "Testing drive configuration..."
        
        $Result = @{
            Success = $true
            SystemDriveAccessible = $false
            CacheDriveAccessible = $false
            Issues = @()
        }
        
        # Test system drive
        $SystemDrive = $env:SystemDrive
        if (Test-Path $SystemDrive) {
            $Result.SystemDriveAccessible = $true
            Write-Log "System drive ($SystemDrive) is accessible" "SUCCESS"
        } else {
            $Result.Success = $false
            $Result.Issues += "System drive not accessible"
        }
        
        # Test cache drive if required
        $RequireCacheDrive = [bool](Get-ConfigValue -Key "RequireCacheDrive" -DefaultValue "true" -ConfigFile $ConfigFilePath)
        if ($RequireCacheDrive) {
            if (Test-Path "D:\") {
                $Result.CacheDriveAccessible = $true
                Write-Log "Cache drive (D:) is accessible" "SUCCESS"
            } else {
                $Result.Success = $false
                $Result.Issues += "Cache drive (D:) not accessible"
            }
        }
        
        return $Result
    }
    catch {
        Write-Log "Drive configuration test failed: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            SystemDriveAccessible = $false
            CacheDriveAccessible = $false
            Issues = @("Test failed: $($_.Exception.Message)")
        }
    }
}

function Initialize-LoggingSystem {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$LogPath
    )
    
    try {
        # Ensure log directory exists
        $LogDir = Split-Path $LogPath -Parent
        if (-not (Test-Path $LogDir)) {
            New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
        }
        
        # Initialize global log path
        $Global:LogPath = $LogPath
        
        # Write initial entry
        $InitMessage = "=== Logging System Initialized at $(Get-Date) ==="
        $InitMessage | Out-File -FilePath $LogPath -Force
        
        Write-Host "Logging initialized: $LogPath" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "Failed to initialize logging: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}
```

### Fix 3: Correct Function Calls
Fix the incorrect function calls in Stage 1:

```powershell
# In citrix_stage1_script.ps1, replace:
$ScriptConfigResult = Set-StartupShutdownScripts -ScriptCopyResults $ScriptCopyResult -StartupDestination $StartupDestination -ShutdownDestination $ShutdownDestination

# With:
$ScriptConfigResult = Add-StartupShutdownScripts -StartupScriptPath $StartupDestination -ShutdownScriptPath $ShutdownDestination
```

### Fix 4: Add CIM/WMI Compatibility Layer
Add this helper function to handle compatibility:

```powershell
function Get-WmiOrCimInstance {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ClassName,
        
        [Parameter(Mandatory=$false)]
        [string]$Filter = "",
        
        [Parameter(Mandatory=$false)]
        [string]$Property = ""
    )
    
    try {
        # Try CIM first (newer, preferred)
        if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
            if ($Filter) {
                return Get-CimInstance -ClassName $ClassName -Filter $Filter
            } else {
                return Get-CimInstance -ClassName $ClassName
            }
        }
    }
    catch {
        # Fall back to WMI
    }
    
    # Use WMI as fallback
    if ($Filter) {
        return Get-WmiObject -Class $ClassName -Filter $Filter
    } else {
        return Get-WmiObject -Class $ClassName
    }
}
```

### Fix 5: Path Validation Function
Add a comprehensive path validation function:

```powershell
function Test-SafePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [string]$Path,
        
        [Parameter(Mandatory=$false)]
        [switch]$CreateIfMissing
    )
    
    try {
        # Handle null or empty
        if ([string]::IsNullOrWhiteSpace($Path)) {
            return $false
        }
        
        # Sanitize path
        $CleanPath = $Path.Trim()
        
        # Handle UNC paths
        if ($CleanPath.StartsWith("\\")) {
            # Validate UNC path format
            if ($CleanPath -match '^\\\\[^\\]+\\[^\\]+') {
                # Test UNC path accessibility
                try {
                    $null = Get-Item -Path $CleanPath -ErrorAction Stop
                    return $true
                }
                catch {
                    return $false
                }
            }
            return $false
        }
        
        # Handle local paths
        $CleanPath = $CleanPath.Replace('\\\\', '\')
        
        # Test path
        if (Test-Path -Path $CleanPath) {
            return $true
        }
        elseif ($CreateIfMissing) {
            try {
                New-Item -Path $CleanPath -ItemType Directory -Force | Out-Null
                return $true
            }
            catch {
                return $false
            }
        }
        
        return $false
    }
    catch {
        return $false
    }
}
```

### Fix 6: Enhanced Error Handling Template
Use this pattern for better error handling:

```powershell
function Template-Function {
    [CmdletBinding()]
    param()
    
    # Initialize result object
    $Result = @{
        Success = $false
        Data = $null
        Errors = @()
        Warnings = @()
    }
    
    # Resource tracking
    $ResourcesToCleanup = @()
    
    try {
        # Main logic here
        
        $Result.Success = $true
    }
    catch {
        $Result.Errors += $_.Exception.Message
        Write-Log "Function failed: $($_.Exception.Message)" "ERROR"
    }
    finally {
        # Always cleanup resources
        foreach ($Resource in $ResourcesToCleanup) {
            try {
                # Cleanup logic
            }
            catch {
                Write-Log "Cleanup failed for resource: $($_.Exception.Message)" "WARN"
            }
        }
    }
    
    return $Result
}
```

## Additional Improvements

### 1. Configuration Validation
Add a configuration validation function:

```powershell
function Test-Configuration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ConfigFilePath
    )
    
    $ValidationResults = @{
        Valid = $true
        Issues = @()
        Warnings = @()
    }
    
    # Check required keys
    $RequiredKeys = @(
        "NetworkSourcePath",
        "LocalInstallPath",
        "VDAISOSourcePath"
    )
    
    foreach ($Key in $RequiredKeys) {
        $Value = Get-ConfigValue -Key $Key -ConfigFile $ConfigFilePath
        if ([string]::IsNullOrWhiteSpace($Value)) {
            $ValidationResults.Valid = $false
            $ValidationResults.Issues += "Missing required configuration: $Key"
        }
    }
    
    # Validate paths
    $PathKeys = @(
        "NetworkSourcePath",
        "VDAISOSourcePath",
        "PVSISOSourcePath"
    )
    
    foreach ($Key in $PathKeys) {
        $Path = Get-ConfigValue -Key $Key -ConfigFile $ConfigFilePath
        if (![string]::IsNullOrWhiteSpace($Path) -and !(Test-SafePath -Path $Path)) {
            $ValidationResults.Warnings += "Path not accessible: $Key = $Path"
        }
    }
    
    return $ValidationResults
}
```

### 2. Progress Tracking
Add progress tracking for long operations:

```powershell
function Write-ProgressHelper {
    [CmdletBinding()]
    param(
        [string]$Activity,
        [string]$Status,
        [int]$PercentComplete,
        [int]$Id = 1
    )
    
    Write-Progress -Activity $Activity -Status $Status -PercentComplete $PercentComplete -Id $Id
    Write-Log "$Activity - $Status ($PercentComplete%)" "INFO"
}
```

### 3. Retry Logic Helper
Add a generic retry helper:

```powershell
function Invoke-WithRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [scriptblock]$ScriptBlock,
        
        [int]$MaxAttempts = 3,
        [int]$DelaySeconds = 2
    )
    
    $Attempt = 0
    $LastError = $null
    
    while ($Attempt -lt $MaxAttempts) {
        $Attempt++
        try {
            return & $ScriptBlock
        }
        catch {
            $LastError = $_
            if ($Attempt -lt $MaxAttempts) {
                Write-Log "Attempt $Attempt failed, retrying in $DelaySeconds seconds..." "WARN"
                Start-Sleep -Seconds $DelaySeconds
            }
        }
    }
    
    throw $LastError
}
```

## Security Improvements

### 1. Credential Handling
Never store credentials in plain text. Use secure methods:

```powershell
function Get-SecureCredential {
    [CmdletBinding()]
    param(
        [string]$Username,
        [string]$Message = "Enter credentials"
    )
    
    if ($Username) {
        return Get-Credential -UserName $Username -Message $Message
    } else {
        return Get-Credential -Message $Message
    }
}
```

### 2. Input Validation
Add input validation for all user inputs:

```powershell
function Test-ValidInput {
    [CmdletBinding()]
    param(
        [string]$Input,
        [string]$Pattern,
        [string[]]$AllowedValues
    )
    
    if ($AllowedValues) {
        return $Input -in $AllowedValues
    }
    
    if ($Pattern) {
        return $Input -match $Pattern
    }
    
    return ![string]::IsNullOrWhiteSpace($Input)
}
```

## Performance Optimizations

### 1. Parallel Processing
For multiple file copies:

```powershell
function Copy-FilesInParallel {
    [CmdletBinding()]
    param(
        [hashtable]$FilesToCopy,
        [int]$ThrottleLimit = 4
    )
    
    $Jobs = @()
    
    foreach ($File in $FilesToCopy.GetEnumerator()) {
        $Job = Start-Job -ScriptBlock {
            param($Source, $Destination)
            Copy-Item -Path $Source -Destination $Destination -Force
        } -ArgumentList $File.Value.Source, $File.Value.Destination
        
        $Jobs += $Job
        
        # Throttle concurrent jobs
        while ((Get-Job -State Running).Count -ge $ThrottleLimit) {
            Start-Sleep -Milliseconds 100
        }
    }
    
    # Wait for all jobs
    $Jobs | Wait-Job | Receive-Job
    $Jobs | Remove-Job
}
```

### 2. Lazy Loading
Load heavy modules only when needed:

```powershell
function Get-RequiredModule {
    [CmdletBinding()]
    param(
        [string]$ModuleName
    )
    
    if (!(Get-Module -Name $ModuleName)) {
        try {
            Import-Module $ModuleName -ErrorAction Stop
            return $true
        }
        catch {
            Write-Log "Failed to load module: $ModuleName" "ERROR"
            return $false
        }
    }
    return $true
}
```

## Testing Recommendations

1. **Add Pester Tests**: Create unit tests for critical functions
2. **Validation Mode**: Add a -WhatIf parameter to test without making changes
3. **Rollback Capability**: Implement rollback for failed installations
4. **Logging Levels**: Add verbose/debug logging levels

## Summary

The scripts are well-structured but need these fixes:
1. Complete function exports
2. Add missing function definitions
3. Fix function call mismatches
4. Improve error handling
5. Add compatibility layers
6. Enhance path validation
7. Implement security best practices

These improvements will make the scripts more robust, maintainable, and reliable across different Windows environments.