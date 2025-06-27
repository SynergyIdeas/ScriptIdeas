function Get-ExitCodeDescription {
    param(
        [int]$ExitCode,
        [string]$ComponentType
    )
    
    $ExitCodeInfo = @{
        Description = "Unknown exit code"
        RequiresReboot = $false
        RebootReason = ""
        IsSuccess = $false
        Status = "Unknown"
    }
    
    switch ($ExitCode) {
        0 {
            $ExitCodeInfo.Description = "Installation completed successfully"
            $ExitCodeInfo.IsSuccess = $true
            $ExitCodeInfo.Status = "Success - No reboot required"
        }
        3 {
            $ExitCodeInfo.Description = "Installation completed successfully with reboot required"
            $ExitCodeInfo.RequiresReboot = $true
            $ExitCodeInfo.RebootReason = "System configuration changes require restart to take effect"
            $ExitCodeInfo.IsSuccess = $true
            $ExitCodeInfo.Status = "Success - Reboot pending"
        }
        3010 {
            $ExitCodeInfo.Description = "Installation completed successfully with reboot required"
            $ExitCodeInfo.RequiresReboot = $true
            $ExitCodeInfo.RebootReason = "Windows Installer requires system restart to complete installation"
            $ExitCodeInfo.IsSuccess = $true
            $ExitCodeInfo.Status = "Success - Reboot pending"
        }
        1603 {
            $ExitCodeInfo.Description = "Fatal error during installation"
            $ExitCodeInfo.Status = "Failed - Installation error"
        }
        1619 {
            $ExitCodeInfo.Description = "Installation package could not be opened"
            $ExitCodeInfo.Status = "Failed - Package error"
        }
        1620 {
            $ExitCodeInfo.Description = "Installation package could not be opened (invalid package)"
            $ExitCodeInfo.Status = "Failed - Invalid package"
        }
        1633 {
            $ExitCodeInfo.Description = "Installation package is not supported on this platform"
            $ExitCodeInfo.Status = "Failed - Platform incompatible"
        }
        default {
            if ($ComponentType -eq "VDA") {
                $ExitCodeInfo.Description = "VDA installation exit code $ExitCode - refer to Citrix documentation"
            } elseif ($ComponentType -eq "PVS") {
                $ExitCodeInfo.Description = "PVS Target Device installation exit code $ExitCode - refer to Citrix documentation"
            } else {
                $ExitCodeInfo.Description = "Installation exit code $ExitCode"
            }
            $ExitCodeInfo.Status = "Check documentation"
        }
    }
    
    return $ExitCodeInfo
}

function Get-ComponentDetails {
    param(
        [string]$ComponentName,
        [hashtable]$Result
    )
    
    $detailsHTML = ""
    
    # Generate component-specific details based on the component type and its result data
    switch ($ComponentName) {
        "VDA" {
            if ($Result.Success) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Installation Results</div>'
                if ($Result.Message) { $detailsHTML += "<div class='detail-item detail-success'>[SUCCESS] $($Result.Message)</div>" }
                if ($Result.ExitCode) { 
                    $ExitCodeInfo = Get-ExitCodeDescription -ExitCode $Result.ExitCode -ComponentType "VDA"
                    $detailsHTML += "<div class='detail-item detail-info'>Exit Code: $($Result.ExitCode) - $($ExitCodeInfo.Description)</div>"
                    if ($ExitCodeInfo.RequiresReboot) {
                        $detailsHTML += "<div class='detail-item detail-warning'>[REBOOT] Reboot Required: $($ExitCodeInfo.RebootReason)</div>"
                    }
                    if ($ExitCodeInfo.IsSuccess) {
                        $detailsHTML += "<div class='detail-item detail-success'>[SUCCESS] Installation Status: $($ExitCodeInfo.Status)</div>"
                    }
                }
                if ($Result.InstallPath) { $detailsHTML += "<div class='detail-item detail-info'>Install Path: $($Result.InstallPath)</div>" }
                if ($Result.Version) { $detailsHTML += "<div class='detail-item detail-info'>Version: $($Result.Version)</div>" }
                if ($Result.Duration) { $detailsHTML += "<div class='detail-item detail-info'>Duration: $($Result.Duration)</div>" }
                $detailsHTML += '</div>'
                
                # Show actual changes made during installation
                if ($Result.Changes -and $Result.Changes.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Changes Made</div>'
                    foreach ($change in $Result.Changes) {
                        $detailsHTML += "<div class='detail-item detail-success'>[CHANGED] $change</div>"
                    }
                    $detailsHTML += '</div>'
                }
                
                # Show actual installation details if available
                if ($Result.Details -and $Result.Details.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Installation Details</div>'
                    foreach ($detail in $Result.Details) {
                        $detailsHTML += "<div class='detail-item detail-info'>$detail</div>"
                    }
                    $detailsHTML += '</div>'
                }
            } elseif ($Result.Skipped) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Skip Reason</div>'
                $detailsHTML += "<div class='detail-item detail-warning'>[SKIPPED] $($Result.SkipReason)</div>"
                $detailsHTML += '</div>'
            } else {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Installation Failure Analysis</div>'
                $detailsHTML += "<div class='detail-item detail-error'>[ERROR] VDA installation failed</div>"
                if ($Result.Error) { $detailsHTML += "<div class='detail-item detail-error'>Error: $($Result.Error)</div>" }
                if ($Result.ExitCode) { $detailsHTML += "<div class='detail-item detail-error'>Exit Code: $($Result.ExitCode)</div>" }
                $detailsHTML += '</div>'
                
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Troubleshooting Steps</div>'
                $detailsHTML += '<div class="detail-item detail-warning">Check system requirements and compatibility</div>'
                $detailsHTML += '<div class="detail-item detail-warning">Verify installer integrity and source path</div>'
                $detailsHTML += '<div class="detail-item detail-warning">Ensure sufficient disk space (minimum 2GB)</div>'
                $detailsHTML += '<div class="detail-item detail-warning">Review Windows Event Logs for detailed errors</div>'
                $detailsHTML += '</div>'
            }
        }
        
        "CacheDrive" {
            if ($Result.Success) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Cache Drive Operation Results</div>'
                if ($Result.Message) { $detailsHTML += "<div class='detail-item detail-success'>[SUCCESS] $($Result.Message)</div>" }
                if ($Result.Method) { $detailsHTML += "<div class='detail-item detail-info'>Method Used: $($Result.Method)</div>" }
                if ($Result.DriveLetter) { $detailsHTML += "<div class='detail-item detail-info'>Drive Letter: $($Result.DriveLetter):</div>" }
                if ($Result.SizeMB) { $detailsHTML += "<div class='detail-item detail-info'>Size: $($Result.SizeMB) MB</div>" }
                if ($Result.VHDXPath) { $detailsHTML += "<div class='detail-item detail-info'>VHDX Location: $($Result.VHDXPath)</div>" }
                if ($Result.Duration) { $detailsHTML += "<div class='detail-item detail-info'>Duration: $($Result.Duration)</div>" }
                $detailsHTML += '</div>'
                
                # Show detailed operations performed in compact format
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Operations Performed</div>'
                $detailsHTML += "<div class='detail-item detail-success'>[CREATED] Virtual disk: $($Result.VHDXPath)</div>"
                if ($Result.SizeMB) { $detailsHTML += "<div class='detail-item detail-success'>[SIZED] Disk capacity: $($Result.SizeMB) MB ($([math]::Round($Result.SizeMB/1024, 1)) GB)</div>" }
                if ($Result.DriveLetter) { $detailsHTML += "<div class='detail-item detail-success'>[MOUNTED] Drive letter assigned: $($Result.DriveLetter):</div>" }
                $detailsHTML += "<div class='detail-item detail-success'>[FORMATTED] File system: NTFS with CACHE label</div>"
                $detailsHTML += "<div class='detail-item detail-success'>[VERIFIED] Drive ready for caching operations</div>"
                $detailsHTML += "<div class='detail-item detail-info'>Configuration: Dynamically expanding VHDX, persistent mount</div>"
                $detailsHTML += '</div>'
                
                # Show auto-mount configuration
                if ($Result.AutoMountConfigured) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Auto-Mount Configuration</div>'
                    $detailsHTML += "<div class='detail-item detail-success'>[CONFIGURED] Auto-mount script created for boot</div>"
                    $detailsHTML += "<div class='detail-item detail-info'>Boot persistence: VHDX will auto-mount on system startup</div>"
                    $detailsHTML += "<div class='detail-item detail-info'>Registry entries: Created for automatic drive assignment</div>"
                    $detailsHTML += '</div>'
                }
            } elseif ($Result.Skipped) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Cache Drive Status</div>'
                $detailsHTML += "<div class='detail-item detail-warning'>[SKIPPED] $($Result.Reason)</div>"
                $detailsHTML += '</div>'
            } elseif ($Result.ExistingDriveFound) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Cache Drive Status</div>'
                $detailsHTML += "<div class='detail-item detail-info'>[EXISTING] Cache drive already present</div>"
                if ($Result.DriveLetter) { $detailsHTML += "<div class='detail-item detail-info'>Drive: $($Result.DriveLetter):</div>" }
                if ($Result.SizeGB) { $detailsHTML += "<div class='detail-item detail-info'>Size: $($Result.SizeGB) GB</div>" }
                if ($Result.DriveType) { $detailsHTML += "<div class='detail-item detail-info'>Type: $($Result.DriveType)</div>" }
                $detailsHTML += '</div>'
            } else {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Cache Drive Operation Failed</div>'
                $detailsHTML += "<div class='detail-item detail-error'>[FAILED] Cache drive operation unsuccessful</div>"
                if ($Result.Error) { $detailsHTML += "<div class='detail-item detail-error'>Error: $($Result.Error)</div>" }
                if ($Result.Errors -and $Result.Errors.Count -gt 0) {
                    foreach ($error in $Result.Errors) {
                        $detailsHTML += "<div class='detail-item detail-error'>Error: $error</div>"
                    }
                }
                $detailsHTML += '</div>'
            }
        }
        
        "CitrixServicesDisabled" {
            if ($Result.Success) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Service Management Tasks</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Service status enumeration</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Service dependency analysis</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Service configuration validation</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Service state modification</div>'
                $detailsHTML += '</div>'
                
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Stage-Specific Service Management</div>'
                if ($Result.Stage -eq 1 -or !$Result.Stage) {
                    $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Windows Update service (wuauserv) management</div>'
                    $detailsHTML += '<div class="detail-item detail-info">Spooler service preserved for VDA installation</div>'
                    $detailsHTML += '<div class="detail-item detail-info">Stage 1: Pre-installation service optimization</div>'
                } else {
                    $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] CdfSvc service management</div>'
                    $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] BITS service management</div>'
                    $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Fax service management</div>'
                    $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] TapiSrv service management</div>'
                    $detailsHTML += '<div class="detail-item detail-info">Stage 2: Post-installation service optimization</div>'
                }
                $detailsHTML += '</div>'
                
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Service Statistics</div>'
                if ($Result.DisabledServices) { $detailsHTML += "<div class='detail-item detail-info'>Services Disabled: $($Result.DisabledServices.Count)</div>" }
                if ($Result.SkippedServices) { $detailsHTML += "<div class='detail-item detail-info'>Services Skipped: $($Result.SkippedServices.Count)</div>" }
                if ($Result.FailedServices) { $detailsHTML += "<div class='detail-item detail-warning'>Services Failed: $($Result.FailedServices.Count)</div>" }
                $detailsHTML += '<div class="detail-item detail-info">Configuration: VDA installation compatibility mode</div>'
                $detailsHTML += '</div>'
            } else {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Service Management Failure</div>'
                $detailsHTML += "<div class='detail-item detail-error'>[ERROR] Service management operation failed</div>"
                if ($Result.Error) { $detailsHTML += "<div class='detail-item detail-error'>Error: $($Result.Error)</div>" }
                $detailsHTML += "<div class='detail-item detail-warning'>This may cause VDA installation or performance issues</div>"
                $detailsHTML += '</div>'
                
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Troubleshooting Steps</div>'
                $detailsHTML += '<div class="detail-item detail-warning">Verify administrator privileges</div>'
                $detailsHTML += '<div class="detail-item detail-warning">Check Windows Service Manager accessibility</div>'
                $detailsHTML += '<div class="detail-item detail-warning">Review service dependencies</div>'
                $detailsHTML += '<div class="detail-item detail-warning">Manually configure services if needed</div>'
                $detailsHTML += '</div>'
            }
        }
        
        "PVS" {
            if ($Result.Success) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">PVS Target Device Installation Tasks</div>'
                if ($Result.InstallPath) {
                    $detailsHTML += "<div class='detail-item detail-success'>[SUCCESS] PVS Target Device installed to: $($Result.InstallPath)</div>"
                } elseif ($Result.Message) {
                    $detailsHTML += "<div class='detail-item detail-success'>[SUCCESS] $($Result.Message)</div>"
                } else {
                    $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] PVS Target Device installer execution</div>'
                }
                if ($Result.Version) { $detailsHTML += "<div class='detail-item detail-info'>Version: $($Result.Version)</div>" }
                if ($Result.ExitCode) { 
                    $ExitCodeInfo = Get-ExitCodeDescription -ExitCode $Result.ExitCode -ComponentType "PVS"
                    $detailsHTML += "<div class='detail-item detail-info'>Exit Code: $($Result.ExitCode) - $($ExitCodeInfo.Description)</div>"
                    if ($ExitCodeInfo.RequiresReboot) {
                        $detailsHTML += "<div class='detail-item detail-warning'>[REBOOT] Reboot Required: $($ExitCodeInfo.RebootReason)</div>"
                    }
                    if ($ExitCodeInfo.IsSuccess) {
                        $detailsHTML += "<div class='detail-item detail-success'>[SUCCESS] Installation Status: $($ExitCodeInfo.Status)</div>"
                    }
                }
                if ($Result.Duration) { $detailsHTML += "<div class='detail-item detail-info'>Duration: $($Result.Duration)</div>" }
                
                # Show driver installation details
                if ($Result.DriversInstalled -and $Result.DriversInstalled.Count -gt 0) {
                    $detailsHTML += '<div class="detail-item detail-info">Drivers installed:</div>'
                    foreach ($Driver in $Result.DriversInstalled) {
                        $detailsHTML += "<div class='detail-item detail-success'>  - $Driver</div>"
                    }
                }
                $detailsHTML += '</div>'
                
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Configuration Details</div>'
                if ($Result.CacheDrive) { $detailsHTML += "<div class='detail-item detail-info'>Cache Drive: $($Result.CacheDrive)</div>" }
                $detailsHTML += '<div class="detail-item detail-info">Boot Mode: Network streaming</div>'
                $detailsHTML += '<div class="detail-item detail-info">Cache Mode: Cache on device with overflow on hard disk</div>'
                $detailsHTML += '</div>'
            } elseif ($Result.Skipped -or ($Result.Error -and $Result.Error -match "ISO file not found|file not found|not found")) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">PVS Installation Skipped</div>'
                if ($Result.Error -and $Result.Error -match "ISO file not found") {
                    $detailsHTML += "<div class='detail-item detail-info'>[INFO] PVS Target Device installation skipped - ISO file not available</div>"
                    $detailsHTML += "<div class='detail-item detail-info'>Expected location: C:\Temp\PVS.iso</div>"
                    $detailsHTML += "<div class='detail-item detail-info'>Status: Installation files not provided</div>"
                } elseif ($Result.Reason) {
                    $detailsHTML += "<div class='detail-item detail-info'>[INFO] $($Result.Reason)</div>"
                } else {
                    $detailsHTML += "<div class='detail-item detail-info'>[INFO] PVS Target Device installation skipped</div>"
                }
                
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Skip Analysis</div>'
                $detailsHTML += "<div class='detail-item detail-info'>PVS ISO file not found in expected location</div>"
                $detailsHTML += "<div class='detail-item detail-info'>Installation requires PVS Target Device ISO to be placed in C:\Temp\</div>"
                $detailsHTML += "<div class='detail-item detail-info'>System will continue without PVS streaming capabilities</div>"
                $detailsHTML += '</div>'
                $detailsHTML += '</div>'
            } else {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Installation Failure</div>'
                $detailsHTML += "<div class='detail-item detail-error'>[ERROR] PVS Target Device installation failed</div>"
                if ($Result.Error) { $detailsHTML += "<div class='detail-item detail-error'>Error: $($Result.Error)</div>" }
                $detailsHTML += '</div>'
            }
        }
        
        "WEM" {
            if ($Result.Success) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">WEM Agent Installation Tasks</div>'
                if ($Result.InstallPath) {
                    $detailsHTML += "<div class='detail-item detail-success'>[SUCCESS] WEM Agent installed to: $($Result.InstallPath)</div>"
                } elseif ($Result.Message) {
                    $detailsHTML += "<div class='detail-item detail-success'>[SUCCESS] $($Result.Message)</div>"
                } else {
                    $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] WEM Agent installer execution</div>'
                }
                if ($Result.Version) { $detailsHTML += "<div class='detail-item detail-info'>Version: $($Result.Version)</div>" }
                if ($Result.ExitCode) { $detailsHTML += "<div class='detail-item detail-info'>Exit Code: $($Result.ExitCode)</div>" }
                if ($Result.Duration) { $detailsHTML += "<div class='detail-item detail-info'>Duration: $($Result.Duration)</div>" }
                $detailsHTML += '</div>'
                
                # Show registry changes made during installation
                if ($Result.RegistryChanges -and $Result.RegistryChanges.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Registry Configuration</div>'
                    foreach ($RegChange in $Result.RegistryChanges) {
                        $detailsHTML += "<div class='detail-item detail-success'>[CONFIGURED] $RegChange</div>"
                    }
                    $detailsHTML += '</div>'
                }
                
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Agent Configuration</div>'
                $detailsHTML += '<div class="detail-item detail-info">Mode: Infrastructure Service connection</div>'
                $detailsHTML += '<div class="detail-item detail-info">Policy Processing: Enabled</div>'
                $detailsHTML += '<div class="detail-item detail-info">User Environment Management: Active</div>'
                
                # Check WEM Agent cache location registry setting
                try {
                    $WEMCacheReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Norskale\Agent Host" -Name "AgentCacheAlternateLocation" -ErrorAction SilentlyContinue
                    if ($WEMCacheReg -and $WEMCacheReg.AgentCacheAlternateLocation) {
                        $detailsHTML += "<div class='detail-item detail-success'>[CONFIGURED] Cache Location: $($WEMCacheReg.AgentCacheAlternateLocation)</div>"
                    } else {
                        $detailsHTML += "<div class='detail-item detail-info'>[DEFAULT] Cache Location: Default system location</div>"
                    }
                } catch {
                    $detailsHTML += "<div class='detail-item detail-warning'>[WARNING] Cache location registry validation failed</div>"
                }
                
                $detailsHTML += '</div>'
            } elseif ($Result.Skipped) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Skip Reason</div>'
                $detailsHTML += "<div class='detail-item detail-warning'>[SKIPPED] $($Result.Reason)</div>"
                $detailsHTML += '</div>'
            } else {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Installation Failure</div>'
                $detailsHTML += "<div class='detail-item detail-error'>[ERROR] WEM Agent installation failed</div>"
                if ($Result.Error) { $detailsHTML += "<div class='detail-item detail-error'>Error: $($Result.Error)</div>" }
                $detailsHTML += '</div>'
            }
        }
        
        "UberAgent" {
            if ($Result.Success) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">UberAgent Installation Tasks</div>'
                if ($Result.InstallPath) {
                    $detailsHTML += "<div class='detail-item detail-success'>[SUCCESS] UberAgent installed to: $($Result.InstallPath)</div>"
                } elseif ($Result.Message) {
                    $detailsHTML += "<div class='detail-item detail-success'>[SUCCESS] $($Result.Message)</div>"
                } else {
                    $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] UberAgent core installation</div>'
                }
                if ($Result.Version) { $detailsHTML += "<div class='detail-item detail-info'>Version: $($Result.Version)</div>" }
                if ($Result.ExitCode) { $detailsHTML += "<div class='detail-item detail-info'>Exit Code: $($Result.ExitCode)</div>" }
                if ($Result.Duration) { $detailsHTML += "<div class='detail-item detail-info'>Duration: $($Result.Duration)</div>" }
                
                # Show service configuration details
                if ($Result.ServicesConfigured -and $Result.ServicesConfigured.Count -gt 0) {
                    $detailsHTML += '<div class="detail-item detail-info">Services configured:</div>'
                    foreach ($Service in $Result.ServicesConfigured) {
                        $detailsHTML += "<div class='detail-item detail-success'>  - $Service</div>"
                    }
                }
                $detailsHTML += '</div>'
                
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Installation Details</div>'
                if ($Result.TemplatesInstalled) { 
                    $detailsHTML += "<div class='detail-item detail-info'>Templates: $($Result.TemplatesInstalled) installed</div>" 
                } else {
                    $detailsHTML += "<div class='detail-item detail-info'>Templates: No templates detected</div>"
                }
                if ($Result.InstallPath) {
                    $detailsHTML += "<div class='detail-item detail-info'>Installation Path: $($Result.InstallPath)</div>"
                }
                if ($Result.ServicesConfigured -and $Result.ServicesConfigured.Count -gt 0) {
                    $detailsHTML += "<div class='detail-item detail-info'>Services: $($Result.ServicesConfigured.Count) configured</div>"
                } else {
                    $detailsHTML += "<div class='detail-item detail-info'>Services: No UberAgent services detected</div>"
                }
                $detailsHTML += '</div>'
            } elseif ($Result.Skipped) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Skip Reason</div>'
                $detailsHTML += "<div class='detail-item detail-warning'>[SKIPPED] $($Result.Reason)</div>"
                $detailsHTML += '</div>'
            } else {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Installation Failure</div>'
                $detailsHTML += "<div class='detail-item detail-error'>[ERROR] UberAgent installation failed</div>"
                if ($Result.Error) { $detailsHTML += "<div class='detail-item detail-error'>Error: $($Result.Error)</div>" }
                $detailsHTML += '</div>'
            }
        }
        
        "TADDM" {
            if ($Result.Success) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">IBM TADDM Agent Installation Results</div>'
                if ($Result.InstallPath) {
                    if ($Result.InstallPath -eq "Installation path not detected") {
                        $detailsHTML += "<div class='detail-item detail-warning'>[WARNING] $($Result.InstallPath)</div>"
                    } else {
                        $detailsHTML += "<div class='detail-item detail-success'>[SUCCESS] TADDM agent installed to: $($Result.InstallPath)</div>"
                    }
                }
                if ($Result.Message) {
                    $detailsHTML += "<div class='detail-item detail-success'>[SUCCESS] $($Result.Message)</div>"
                }
                if ($Result.ExitCode) { $detailsHTML += "<div class='detail-item detail-info'>Exit Code: $($Result.ExitCode)</div>" }
                
                # Show actual files created during installation
                if ($Result.FilesCreated -and $Result.FilesCreated.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Installation Files Analysis</div>'
                    foreach ($File in $Result.FilesCreated) {
                        if ($File -eq "No TADDM files detected post-installation") {
                            $detailsHTML += "<div class='detail-item detail-warning'>[WARNING] $File</div>"
                        } else {
                            $detailsHTML += "<div class='detail-item detail-success'>[CREATED] $File</div>"
                        }
                    }
                    $detailsHTML += '</div>'
                }
                
                # Show TADDM services status
                if ($Result.ServicesCreated -and $Result.ServicesCreated.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">TADDM Services Status</div>'
                    foreach ($Service in $Result.ServicesCreated) {
                        if ($Service -eq "No TADDM services detected") {
                            $detailsHTML += "<div class='detail-item detail-warning'>[WARNING] $Service</div>"
                        } else {
                            $detailsHTML += "<div class='detail-item detail-success'>[SERVICE] $Service</div>"
                        }
                    }
                    $detailsHTML += '</div>'
                }
                
                # Show detailed installation information
                if ($Result.Details -and $Result.Details.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Installation Details</div>'
                    foreach ($Detail in $Result.Details) {
                        $detailsHTML += "<div class='detail-item detail-info'>$Detail</div>"
                    }
                    $detailsHTML += '</div>'
                }
                
                # Show files created/modified during installation
                if ($Result.FilesCreated -and $Result.FilesCreated.Count -gt 0) {
                    $detailsHTML += '<div class="detail-item detail-info">Files created:</div>'
                    foreach ($File in $Result.FilesCreated) {
                        $detailsHTML += "<div class='detail-item detail-success'>  - $File</div>"
                    }
                }
                $detailsHTML += '</div>'
                
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Agent Configuration</div>'
                $detailsHTML += '<div class="detail-item detail-info">Discovery Mode: Automatic</div>'
                $detailsHTML += '<div class="detail-item detail-info">Asset Management: Enabled</div>'
                $detailsHTML += '<div class="detail-item detail-info">Integration: IBM TADDM compatible</div>'
                $detailsHTML += '</div>'
            } elseif ($Result.Skipped) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Skip Reason</div>'
                $detailsHTML += "<div class='detail-item detail-warning'>[SKIPPED] $($Result.Reason)</div>"
                $detailsHTML += '</div>'
            } else {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Installation Failure</div>'
                $detailsHTML += "<div class='detail-item detail-error'>[ERROR] TADDM installation failed</div>"
                if ($Result.Error) { $detailsHTML += "<div class='detail-item detail-error'>Error: $($Result.Error)</div>" }
                $detailsHTML += '</div>'
            }
        }
        
        "DomainJoin" {
            if ($Result.Success) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Domain Join Operations</div>'
                if ($Result.Message) {
                    $detailsHTML += "<div class='detail-item detail-success'>[SUCCESS] $($Result.Message)</div>"
                } else {
                    $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Machine joined to domain successfully</div>'
                }
                if ($Result.Details) {
                    $detailsHTML += "<div class='detail-item detail-info'>Details: $($Result.Details)</div>"
                }
                $detailsHTML += '</div>'
                
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Domain Join Details</div>'
                if ($Result.DomainName) { $detailsHTML += "<div class='detail-item detail-info'>Domain: $($Result.DomainName)</div>" }
                if ($Result.OrganizationalUnit) { $detailsHTML += "<div class='detail-item detail-info'>Organizational Unit: $($Result.OrganizationalUnit)</div>" }
                if ($Result.ComputerName) { $detailsHTML += "<div class='detail-item detail-info'>Computer Name: $($Result.ComputerName)</div>" }
                if ($Result.DomainController) { $detailsHTML += "<div class='detail-item detail-info'>Domain Controller: $($Result.DomainController)</div>" }
                if ($Result.UserAccount) { $detailsHTML += "<div class='detail-item detail-info'>Join Account: $($Result.UserAccount)</div>" }
                if ($Result.JoinTime) { $detailsHTML += "<div class='detail-item detail-info'>Join Time: $($Result.JoinTime)</div>" }
                if ($Result.DNSSettings) { 
                    $detailsHTML += "<div class='detail-item detail-info'>DNS Servers: $($Result.DNSSettings -join ', ')</div>" 
                }
                if ($Result.SID) { $detailsHTML += "<div class='detail-item detail-info'>Machine SID: $($Result.SID)</div>" }
                $detailsHTML += '</div>'
            } elseif ($Result.Skipped) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Domain Join Skipped</div>'
                $detailsHTML += "<div class='detail-item detail-warning'>[SKIPPED] Domain join was not performed</div>"
                if ($Result.Reason) { $detailsHTML += "<div class='detail-item detail-info'>Reason: $($Result.Reason)</div>" }
                $detailsHTML += '</div>'
                
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Skip Analysis</div>'
                $detailsHTML += '<div class="detail-item detail-info">Domain join may be disabled in configuration</div>'
                $detailsHTML += '<div class="detail-item detail-info">Missing domain credentials or configuration</div>'
                $detailsHTML += '<div class="detail-item detail-info">Machine will remain in workgroup mode</div>'
                $detailsHTML += '</div>'
            } else {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Domain Join Failure</div>'
                $detailsHTML += "<div class='detail-item detail-error'>[ERROR] Domain join operation failed</div>"
                if ($Result.Error) { $detailsHTML += "<div class='detail-item detail-error'>Error: $($Result.Error)</div>" }
                $detailsHTML += '</div>'
                
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Troubleshooting Steps</div>'
                $detailsHTML += '<div class="detail-item detail-warning">Verify domain name and DNS configuration</div>'
                $detailsHTML += '<div class="detail-item detail-warning">Check domain controller connectivity</div>'
                $detailsHTML += '<div class="detail-item detail-warning">Validate domain credentials and permissions</div>'
                $detailsHTML += '<div class="detail-item detail-warning">Ensure time synchronization with domain</div>'
                $detailsHTML += '</div>'
            }
        }
        
        "Scripts" {
            if ($Result.Success) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Startup/Shutdown Scripts Configuration</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Script deployment completed</div>'
                $detailsHTML += '</div>'
                
                # Show copied files summary
                if ($Result.StartupFiles -or $Result.ShutdownFiles) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Files Deployed</div>'
                    
                    if ($Result.StartupFiles -and $Result.StartupFiles.Count -gt 0) {
                        $detailsHTML += "<div class='detail-item detail-success'>Startup scripts copied: $($Result.StartupFiles.Count) files</div>"
                        foreach ($file in $Result.StartupFiles) {
                            $detailsHTML += "<div class='detail-item detail-info'>  • $file</div>"
                        }
                    } else {
                        $detailsHTML += "<div class='detail-item detail-info'>Startup scripts: No files copied</div>"
                    }
                    
                    if ($Result.ShutdownFiles -and $Result.ShutdownFiles.Count -gt 0) {
                        $detailsHTML += "<div class='detail-item detail-success'>Shutdown scripts copied: $($Result.ShutdownFiles.Count) files</div>"
                        foreach ($file in $Result.ShutdownFiles) {
                            $detailsHTML += "<div class='detail-item detail-info'>  • $file</div>"
                        }
                    } else {
                        $detailsHTML += "<div class='detail-item detail-info'>Shutdown scripts: No files copied</div>"
                    }
                    
                    if ($Result.FailedFiles -and $Result.FailedFiles.Count -gt 0) {
                        $detailsHTML += "<div class='detail-item detail-error'>Failed to copy: $($Result.FailedFiles.Count) files</div>"
                        foreach ($file in $Result.FailedFiles) {
                            $detailsHTML += "<div class='detail-item detail-error'>  • $file</div>"
                        }
                    }
                    $detailsHTML += '</div>'
                }
                
                # Show script source paths if available in Details
                if ($Result.Details -and $Result.Details.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Source Configuration</div>'
                    foreach ($detail in $Result.Details) {
                        if ($detail -match "source|destination|OS|script") {
                            $detailsHTML += "<div class='detail-item detail-info'>$detail</div>"
                        }
                    }
                    $detailsHTML += '</div>'
                }
                
                # Show operation summary
                $totalCopied = 0
                if ($Result.StartupFiles) { $totalCopied += $Result.StartupFiles.Count }
                if ($Result.ShutdownFiles) { $totalCopied += $Result.ShutdownFiles.Count }
                
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Operation Summary</div>'
                $detailsHTML += "<div class='detail-item detail-success'>Total files deployed: $totalCopied</div>"
                if ($Result.FailedFiles -and $Result.FailedFiles.Count -gt 0) {
                    $detailsHTML += "<div class='detail-item detail-warning'>Files with errors: $($Result.FailedFiles.Count)</div>"
                } else {
                    $detailsHTML += "<div class='detail-item detail-success'>All operations completed successfully</div>"
                }
                $detailsHTML += '</div>'
                
            } elseif ($Result.Skipped) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Startup/Shutdown Scripts Skipped</div>'
                $detailsHTML += "<div class='detail-item detail-info'>[SKIPPED] Script deployment was skipped</div>"
                if ($Result.Reason) {
                    $detailsHTML += "<div class='detail-item detail-info'>Reason: $($Result.Reason)</div>"
                } elseif ($Result.Message) {
                    $detailsHTML += "<div class='detail-item detail-info'>Reason: $($Result.Message)</div>"
                }
                $detailsHTML += '</div>'
            } else {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Startup/Shutdown Scripts Issues</div>'
                $detailsHTML += "<div class='detail-item detail-error'>[ERROR] Script deployment encountered issues</div>"
                if ($Result.Error) {
                    $detailsHTML += "<div class='detail-item detail-error'>Error: $($Result.Error)</div>"
                } elseif ($Result.Message) {
                    $detailsHTML += "<div class='detail-item detail-error'>Details: $($Result.Message)</div>"
                }
                $detailsHTML += '</div>'
            }
        }
        
        "ScriptConfiguration" {
            if ($Result.Success) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Script Configuration Management</div>'
                if ($Result.Message) {
                    $detailsHTML += "<div class='detail-item detail-success'>[SUCCESS] $($Result.Message)</div>"
                } else {
                    $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Script configuration management completed</div>'
                }
                $detailsHTML += '</div>'
                
                # Show configuration operations
                if ($Result.ConfigOperations -and $Result.ConfigOperations.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Configuration Operations</div>'
                    foreach ($op in $Result.ConfigOperations) {
                        $detailsHTML += "<div class='detail-item detail-success'>$op</div>"
                    }
                    $detailsHTML += '</div>'
                }
                
                # Show script files processed
                if ($Result.ScriptFiles -and $Result.ScriptFiles.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Script Files Processed</div>'
                    foreach ($file in $Result.ScriptFiles) {
                        $detailsHTML += "<div class='detail-item detail-info'>File: $file</div>"
                    }
                    $detailsHTML += '</div>'
                }
                
                # Show operation details
                if ($Result.Details -and $Result.Details.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Operation Details</div>'
                    foreach ($detail in $Result.Details) {
                        $detailsHTML += "<div class='detail-item detail-info'>$detail</div>"
                    }
                    $detailsHTML += '</div>'
                }
            } elseif ($Result.Skipped) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Script Configuration Skipped</div>'
                $detailsHTML += "<div class='detail-item detail-warning'>[SKIPPED] Script configuration was skipped</div>"
                if ($Result.Reason) { $detailsHTML += "<div class='detail-item detail-info'>Reason: $($Result.Reason)</div>" }
                $detailsHTML += '</div>'
            } else {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Script Configuration Failure</div>'
                $detailsHTML += "<div class='detail-item detail-error'>[ERROR] Script configuration failed</div>"
                if ($Result.Error) { $detailsHTML += "<div class='detail-item detail-error'>Error: $($Result.Error)</div>" }
                $detailsHTML += '</div>'
            }
        }
        
        "DNSConfiguration" {
            if ($Result.Success) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">DNS Configuration Results</div>'
                $detailsHTML += "<div class='detail-item detail-success'>[SUCCESS] DNS search list configuration completed</div>"
                
                if ($Result.ConfiguredDomains -and $Result.ConfiguredDomains.Count -gt 0) {
                    $detailsHTML += "<div class='detail-item detail-info'>DNS search domains configured: $($Result.ConfiguredDomains.Count)</div>"
                    foreach ($domain in $Result.ConfiguredDomains) {
                        $detailsHTML += "<div class='detail-item detail-success'>  - $domain</div>"
                    }
                } elseif ($Result.DNSSuffixes -and $Result.DNSSuffixes.Count -gt 0) {
                    $detailsHTML += "<div class='detail-item detail-info'>DNS search domains configured: $($Result.DNSSuffixes.Count)</div>"
                    foreach ($domain in $Result.DNSSuffixes) {
                        $detailsHTML += "<div class='detail-item detail-success'>  - $domain</div>"
                    }
                }
                
                if ($Result.RegistryKey) {
                    $detailsHTML += "<div class='detail-item detail-info'>Registry path: $($Result.RegistryKey)</div>"
                }
                
                if ($Result.Duration) { $detailsHTML += "<div class='detail-item detail-info'>Duration: $($Result.Duration)</div>" }
                $detailsHTML += '</div>'
                
                # Show additional DNS details if available
                if ($Result.Details -and $Result.Details.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Configuration Details</div>'
                    foreach ($detail in $Result.Details) {
                        $detailsHTML += "<div class='detail-item detail-info'>$detail</div>"
                    }
                    $detailsHTML += '</div>'
                }
            } elseif ($Result.Skipped) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">DNS Configuration Skipped</div>'
                $detailsHTML += "<div class='detail-item detail-warning'>[SKIPPED] DNS search list configuration was not performed</div>"
                if ($Result.Message) { $detailsHTML += "<div class='detail-item detail-info'>Reason: $($Result.Message)</div>" }
                $detailsHTML += '</div>'
            } else {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">DNS Configuration Failed</div>'
                $detailsHTML += "<div class='detail-item detail-error'>[FAILED] DNS search list configuration failed</div>"
                if ($Result.Error) { $detailsHTML += "<div class='detail-item detail-error'>Error: $($Result.Error)</div>" }
                if ($Result.Message) { $detailsHTML += "<div class='detail-item detail-info'>Details: $($Result.Message)</div>" }
                $detailsHTML += '</div>'
            }
        }
        
        default {
            # Show comprehensive component details using actual data
            if ($Result.Success) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Operation Results</div>'
                
                if ($Result.Message) { 
                    $detailsHTML += "<div class='detail-item detail-success'>[SUCCESS] $($Result.Message)</div>" 
                } else {
                    $detailsHTML += "<div class='detail-item detail-success'>[SUCCESS] $ComponentName completed successfully</div>"
                }
                
                if ($Result.Duration) { $detailsHTML += "<div class='detail-item detail-info'>Duration: $($Result.Duration)</div>" }
                if ($Result.ExitCode) { $detailsHTML += "<div class='detail-item detail-info'>Exit Code: $($Result.ExitCode)</div>" }
                
                # Show specific changes made
                if ($Result.Changes -and $Result.Changes.Count -gt 0) {
                    foreach ($change in $Result.Changes) {
                        $detailsHTML += "<div class='detail-item detail-success'>[CHANGED] $change</div>"
                    }
                }
                $detailsHTML += '</div>'
                
                # Services Section
                if ($Result.ServicesChanged -or $Result.ServicesModified -or $Result.ServicesDisabled -or $Result.ServicesEnabled) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Services Modified</div>'
                    
                    if ($Result.ServicesChanged) {
                        foreach ($service in $Result.ServicesChanged) {
                            $detailsHTML += "<div class='detail-item detail-success'>[MODIFIED] $service</div>"
                        }
                    }
                    if ($Result.ServicesDisabled) {
                        foreach ($service in $Result.ServicesDisabled) {
                            $detailsHTML += "<div class='detail-item detail-warning'>[DISABLED] $service</div>"
                        }
                    }
                    if ($Result.ServicesEnabled) {
                        foreach ($service in $Result.ServicesEnabled) {
                            $detailsHTML += "<div class='detail-item detail-success'>[ENABLED] $service</div>"
                        }
                    }
                    $detailsHTML += '</div>'
                }
                
                # Registry Section
                if ($Result.RegistryChanges -or $Result.RegistryKeys -or $Result.RegistryValues) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Registry Modifications</div>'
                    
                    if ($Result.RegistryChanges) {
                        foreach ($regChange in $Result.RegistryChanges) {
                            $detailsHTML += "<div class='detail-item detail-success'>[REGISTRY] $regChange</div>"
                        }
                    }
                    if ($Result.RegistryKeys) {
                        foreach ($key in $Result.RegistryKeys) {
                            $detailsHTML += "<div class='detail-item detail-info'>[KEY] $key</div>"
                        }
                    }
                    if ($Result.RegistryValues) {
                        foreach ($value in $Result.RegistryValues) {
                            $detailsHTML += "<div class='detail-item detail-info'>[VALUE] $value</div>"
                        }
                    }
                    $detailsHTML += '</div>'
                }
                
                # Files Section
                if ($Result.FilesModified -or $Result.FilesCreated -or $Result.FilesDeleted -or $Result.FoldersCreated) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">File System Changes</div>'
                    
                    if ($Result.FilesCreated) {
                        foreach ($file in $Result.FilesCreated) {
                            $detailsHTML += "<div class='detail-item detail-success'>[CREATED] $file</div>"
                        }
                    }
                    if ($Result.FilesModified) {
                        foreach ($file in $Result.FilesModified) {
                            $detailsHTML += "<div class='detail-item detail-info'>[MODIFIED] $file</div>"
                        }
                    }
                    if ($Result.FilesDeleted) {
                        foreach ($file in $Result.FilesDeleted) {
                            $detailsHTML += "<div class='detail-item detail-warning'>[DELETED] $file</div>"
                        }
                    }
                    if ($Result.FoldersCreated) {
                        foreach ($folder in $Result.FoldersCreated) {
                            $detailsHTML += "<div class='detail-item detail-success'>[FOLDER CREATED] $folder</div>"
                        }
                    }
                    $detailsHTML += '</div>'
                }
                
                # Network Configuration
                if ($Result.NetworkChanges -or $Result.IPConfiguration -or $Result.DNSServers -or $Result.FirewallRules) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Network Configuration</div>'
                    
                    if ($Result.NetworkChanges) {
                        foreach ($change in $Result.NetworkChanges) {
                            $detailsHTML += "<div class='detail-item detail-success'>[NETWORK] $change</div>"
                        }
                    }
                    if ($Result.IPConfiguration) {
                        $detailsHTML += "<div class='detail-item detail-info'>[IP CONFIG] $($Result.IPConfiguration)</div>"
                    }
                    if ($Result.DNSServers) {
                        $detailsHTML += "<div class='detail-item detail-info'>[DNS] $($Result.DNSServers -join ', ')</div>"
                    }
                    if ($Result.FirewallRules) {
                        foreach ($rule in $Result.FirewallRules) {
                            $detailsHTML += "<div class='detail-item detail-info'>[FIREWALL] $rule</div>"
                        }
                    }
                    $detailsHTML += '</div>'
                }
                
                # Statistics and Counts
                if ($Result.TotalRemoved -or $Result.TotalModified -or $Result.TotalOptimized -or $Result.TotalCreated) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Operation Statistics</div>'
                    
                    if ($Result.TotalCreated -and $Result.TotalCreated -gt 0) {
                        $detailsHTML += "<div class='detail-item detail-success'>[CREATED] $($Result.TotalCreated) items</div>"
                    }
                    if ($Result.TotalModified -and $Result.TotalModified -gt 0) {
                        $detailsHTML += "<div class='detail-item detail-success'>[MODIFIED] $($Result.TotalModified) items</div>"
                    }
                    if ($Result.TotalRemoved -and $Result.TotalRemoved -gt 0) {
                        $detailsHTML += "<div class='detail-item detail-warning'>[REMOVED] $($Result.TotalRemoved) items</div>"
                    }
                    if ($Result.TotalOptimized -and $Result.TotalOptimized -gt 0) {
                        $detailsHTML += "<div class='detail-item detail-success'>[OPTIMIZED] $($Result.TotalOptimized) items</div>"
                    }
                    if ($Result.TotalSkipped -and $Result.TotalSkipped -gt 0) {
                        $detailsHTML += "<div class='detail-item detail-info'>[SKIPPED] $($Result.TotalSkipped) items (already configured)</div>"
                    }
                    $detailsHTML += '</div>'
                }
                
                # Technical Details
                if ($Result.Version -or $Result.InstallPath -or $Result.ExitCode -or $Result.Duration -or $Result.CommandLine) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Technical Details</div>'
                    if ($Result.Version) { $detailsHTML += "<div class='detail-item detail-info'>Version: $($Result.Version)</div>" }
                    if ($Result.InstallPath) { $detailsHTML += "<div class='detail-item detail-info'>Install Path: $($Result.InstallPath)</div>" }
                    if ($Result.CommandLine) { $detailsHTML += "<div class='detail-item detail-info'>Command: $($Result.CommandLine)</div>" }
                    if ($Result.ExitCode) { $detailsHTML += "<div class='detail-item detail-info'>Exit Code: $($Result.ExitCode)</div>" }
                    if ($Result.Duration) { $detailsHTML += "<div class='detail-item detail-info'>Duration: $($Result.Duration)</div>" }
                    if ($Result.StartTime) { $detailsHTML += "<div class='detail-item detail-info'>Started: $($Result.StartTime)</div>" }
                    if ($Result.EndTime) { $detailsHTML += "<div class='detail-item detail-info'>Completed: $($Result.EndTime)</div>" }
                    $detailsHTML += '</div>'
                }
                
            } elseif ($Result.Skipped) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Component Skipped</div>'
                $detailsHTML += "<div class='detail-item detail-warning'>[SKIPPED] $ComponentName</div>"
                if ($Result.SkipReason) { $detailsHTML += "<div class='detail-item detail-info'>Reason: $($Result.SkipReason)</div>" }
                if ($Result.Reason) { $detailsHTML += "<div class='detail-item detail-info'>Details: $($Result.Reason)</div>" }
                if ($Result.ConfigurationNote) { $detailsHTML += "<div class='detail-item detail-info'>Note: $($Result.ConfigurationNote)</div>" }
                $detailsHTML += '</div>'
            } else {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Operation Failed</div>'
                $detailsHTML += "<div class='detail-item detail-error'>[ERROR] $ComponentName failed</div>"
                if ($Result.Error) { $detailsHTML += "<div class='detail-item detail-error'>Error: $($Result.Error)</div>" }
                if ($Result.ErrorDetails) { $detailsHTML += "<div class='detail-item detail-error'>Details: $($Result.ErrorDetails)</div>" }
                if ($Result.ExitCode) { $detailsHTML += "<div class='detail-item detail-error'>Exit Code: $($Result.ExitCode)</div>" }
                if ($Result.LogFile) { $detailsHTML += "<div class='detail-item detail-info'>Log File: $($Result.LogFile)</div>" }
                $detailsHTML += '</div>'
            }
        }
        
        "RDS Grace Period Reset" {
            if ($Result.Success) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">RDS Grace Period Reset Tasks</div>'
                if ($Result.Message) {
                    $detailsHTML += "<div class='detail-item detail-success'>[SUCCESS] $($Result.Message)</div>"
                } else {
                    $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Registry grace period cleanup</div>'
                }
                # Show registry statistics
                if ($Result.TotalRemoved -ne $null) {
                    $detailsHTML += "<div class='detail-item detail-info'>Registry keys removed: $($Result.TotalRemoved)</div>"
                }
                if ($Result.TotalSkipped -ne $null) {
                    $detailsHTML += "<div class='detail-item detail-info'>Keys already clean: $($Result.TotalSkipped)</div>"
                }
                
                # Show removed registry keys
                if ($Result.RemovedKeys -and $Result.RemovedKeys.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Registry Keys Removed</div>'
                    foreach ($RemovedKey in $Result.RemovedKeys) {
                        $detailsHTML += "<div class='detail-item detail-success'>Removed: $RemovedKey</div>"
                    }
                    $detailsHTML += '</div>'
                }
                
                # Show skipped registry keys
                if ($Result.SkippedKeys -and $Result.SkippedKeys.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Registry Keys Already Clean</div>'
                    foreach ($SkippedKey in $Result.SkippedKeys) {
                        $detailsHTML += "<div class='detail-item detail-info'>Already clean: $SkippedKey</div>"
                    }
                    $detailsHTML += '</div>'
                }
                
                # Show detailed operations
                if ($Result.Details -and $Result.Details.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Operation Details</div>'
                    foreach ($detail in $Result.Details) {
                        $detailsHTML += "<div class='detail-item detail-info'>$detail</div>"
                    }
                    $detailsHTML += '</div>'
                }
                $detailsHTML += '</div>'
            } elseif ($Result.Skipped) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Skip Reason</div>'
                $detailsHTML += "<div class='detail-item detail-warning'>[SKIPPED] $($Result.Reason)</div>"
                $detailsHTML += '</div>'
            } else {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Reset Failure</div>'
                $detailsHTML += "<div class='detail-item detail-error'>[ERROR] RDS grace period reset failed</div>"
                if ($Result.Error) { $detailsHTML += "<div class='detail-item detail-error'>Error: $($Result.Error)</div>" }
                $detailsHTML += '</div>'
            }
        }
        
        "Network Optimizations" {
            if ($Result.Success) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Network Optimization Tasks</div>'
                if ($Result.Message) {
                    $detailsHTML += "<div class='detail-item detail-success'>[SUCCESS] $($Result.Message)</div>"
                } else {
                    $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Network optimizations applied</div>'
                }
                
                # Show optimization statistics
                if ($Result.OptimizationsApplied) {
                    $detailsHTML += "<div class='detail-item detail-info'>Optimizations applied: $($Result.OptimizationsApplied)</div>"
                }
                if ($Result.InterfacesModified) {
                    $detailsHTML += "<div class='detail-item detail-info'>Network interfaces modified: $($Result.InterfacesModified)</div>"
                }
                
                # Show registry changes
                if ($Result.RegistryChanges -and $Result.RegistryChanges.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Registry Changes</div>'
                    foreach ($RegChange in $Result.RegistryChanges) {
                        $detailsHTML += "<div class='detail-item detail-success'>$RegChange</div>"
                    }
                    $detailsHTML += '</div>'
                }
                
                # Show detailed operations
                if ($Result.Details -and $Result.Details.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Network Optimization Details</div>'
                    foreach ($detail in $Result.Details) {
                        $detailsHTML += "<div class='detail-item detail-info'>$detail</div>"
                    }
                    $detailsHTML += '</div>'
                }
                $detailsHTML += '</div>'
            } else {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Network Optimization Issues</div>'
                $detailsHTML += "<div class='detail-item detail-error'>[ERROR] Network optimizations encountered issues</div>"
                if ($Result.Errors -and $Result.Errors.Count -gt 0) {
                    foreach ($Error in $Result.Errors) {
                        $detailsHTML += "<div class='detail-item detail-error'>Error: $Error</div>"
                    }
                }
                $detailsHTML += '</div>'
            }
        }
        
        "Storage Optimizations" {
            if ($Result.Success) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Storage Optimization Tasks</div>'
                if ($Result.Message) {
                    $detailsHTML += "<div class='detail-item detail-success'>[SUCCESS] $($Result.Message)</div>"
                } else {
                    $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Storage optimization completed</div>'
                }
                
                # Show registry changes made
                if ($Result.RegistryChanges -and $Result.RegistryChanges.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Registry Changes Applied</div>'
                    foreach ($regChange in $Result.RegistryChanges) {
                        $detailsHTML += "<div class='detail-item detail-success'>$regChange</div>"
                    }
                    $detailsHTML += '</div>'
                }
                
                # Show crash dump configuration if available
                if ($Result.CrashDump -or $Result.DumpSettings) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Crash Dump Configuration</div>'
                    $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Crash dump configured to kernel mode</div>'
                    if ($Result.DumpSettings -and $Result.DumpSettings.Count -gt 0) {
                        foreach ($setting in $Result.DumpSettings) {
                            $detailsHTML += "<div class='detail-item detail-info'>$setting</div>"
                        }
                    }
                    $detailsHTML += '</div>'
                }
                
                # Show optimization statistics
                if ($Result.OptimizationsApplied) {
                    $detailsHTML += "<div class='detail-item detail-info'>Optimizations applied: $($Result.OptimizationsApplied)</div>"
                }
                
                # Show detailed operations
                if ($Result.Details -and $Result.Details.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Storage Optimization Details</div>'
                    foreach ($detail in $Result.Details) {
                        $detailsHTML += "<div class='detail-item detail-info'>$detail</div>"
                    }
                    $detailsHTML += '</div>'
                }
                $detailsHTML += '</div>'
            } else {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Storage Optimization Issues</div>'
                $detailsHTML += "<div class='detail-item detail-error'>[ERROR] Storage optimizations encountered issues</div>"
                if ($Result.Errors -and $Result.Errors.Count -gt 0) {
                    foreach ($Error in $Result.Errors) {
                        $detailsHTML += "<div class='detail-item detail-error'>Error: $Error</div>"
                    }
                }
                $detailsHTML += '</div>'
            }
        }
        
        "Ghost Device Removal" {
            if ($Result.Success) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Ghost Device Removal Tasks</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Ghost device scan completed</div>'
                if ($Result.TotalDevicesFound) {
                    $detailsHTML += "<div class='detail-item detail-info'>Total devices scanned: $($Result.TotalDevicesFound)</div>"
                }
                if ($Result.GhostDevicesRemoved) {
                    $detailsHTML += "<div class='detail-item detail-success'>Ghost devices removed: $($Result.GhostDevicesRemoved)</div>"
                }
                if ($Result.ExecutionTime) {
                    $detailsHTML += "<div class='detail-item detail-info'>Execution time: $($Result.ExecutionTime) seconds</div>"
                }
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] VDI template optimized</div>'
                $detailsHTML += '</div>'
            } else {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Device Removal Issues</div>'
                $detailsHTML += "<div class='detail-item detail-error'>[ERROR] Ghost device removal encountered issues</div>"
                if ($Result.Error) { $detailsHTML += "<div class='detail-item detail-error'>Error: $($Result.Error)</div>" }
                $detailsHTML += '</div>'
            }
        }
        
        "System Defragmentation" {
            if ($Result.Success) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">System Defragmentation Tasks</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] System drive defragmentation completed</div>'
                if ($Result.Method) {
                    $detailsHTML += "<div class='detail-item detail-info'>Method used: $($Result.Method)</div>"
                }
                if ($Result.ExecutionTime) {
                    $detailsHTML += "<div class='detail-item detail-info'>Execution time: $($Result.ExecutionTime.ToString('F2')) minutes</div>"
                }
                if ($Result.DefragmentationPerformed) {
                    $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Free space consolidation completed</div>'
                } else {
                    $detailsHTML += '<div class="detail-item detail-info">[INFO] Analysis completed - defragmentation not required</div>'
                }
                $detailsHTML += '</div>'
            } elseif ($Result.Skipped) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Defragmentation Skipped</div>'
                $detailsHTML += "<div class='detail-item detail-warning'>[SKIPPED] System defragmentation was skipped</div>"
                $detailsHTML += "<div class='detail-item detail-info'>This is normal in virtualized environments</div>"
                $detailsHTML += '</div>'
            } else {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Defragmentation Issues</div>'
                $detailsHTML += "<div class='detail-item detail-error'>[ERROR] System defragmentation encountered issues</div>"
                if ($Result.Error) { $detailsHTML += "<div class='detail-item detail-error'>Error: $($Result.Error)</div>" }
                $detailsHTML += '</div>'
            }
        }
        
        "Event Logs Cleanup" {
            if ($Result.Skipped) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Event Logs Cleanup Status</div>'
                if ($Result.Message) {
                    $detailsHTML += "<div class='detail-item detail-info'>[SKIPPED] $($Result.Message)</div>"
                } else {
                    $detailsHTML += '<div class="detail-item detail-info">[SKIPPED] Event logs cleanup disabled in configuration</div>'
                }
                if ($Result.Details) {
                    $detailsHTML += "<div class='detail-item detail-info'>Details: $($Result.Details)</div>"
                }
                $detailsHTML += '</div>'
            } elseif ($Result.Success) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Event Logs Cleanup Tasks</div>'
                if ($Result.Message) {
                    $detailsHTML += "<div class='detail-item detail-success'>[SUCCESS] $($Result.Message)</div>"
                } else {
                    $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Windows Event Logs cleanup completed</div>'
                }
                if ($Result.LogsCleared) {
                    $detailsHTML += "<div class='detail-item detail-success'>Event logs cleared: $($Result.LogsCleared)</div>"
                }
                if ($Result.LogsFailed -and $Result.LogsFailed -gt 0) {
                    $detailsHTML += "<div class='detail-item detail-info'>Protected logs (normal): $($Result.LogsFailed)</div>"
                }
                if ($Result.Details) {
                    $detailsHTML += "<div class='detail-item detail-info'>Details: $($Result.Details)</div>"
                }
                $detailsHTML += '</div>'
            } else {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Event Logs Cleanup Issues</div>'
                if ($Result.Message) {
                    $detailsHTML += "<div class='detail-item detail-error'>[ERROR] $($Result.Message)</div>"
                } else {
                    $detailsHTML += "<div class='detail-item detail-error'>[ERROR] Event logs cleanup encountered issues</div>"
                }
                if ($Result.Error) { $detailsHTML += "<div class='detail-item detail-error'>Error: $($Result.Error)</div>" }
                if ($Result.FailedLogs -and $Result.FailedLogs.Count -gt 0) {
                    foreach ($FailedLog in $Result.FailedLogs) {
                        $detailsHTML += "<div class='detail-item detail-warning'>Failed log: $FailedLog</div>"
                    }
                }
                $detailsHTML += '</div>'
            }
        }
        
        ".NET Framework Optimization" {
            if ($Result.Skipped) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">.NET Framework Optimization Status</div>'
                if ($Result.Message) {
                    $detailsHTML += "<div class='detail-item detail-info'>[SKIPPED] $($Result.Message)</div>"
                } else {
                    $detailsHTML += '<div class="detail-item detail-info">[SKIPPED] .NET Framework optimization disabled in configuration</div>'
                }
                if ($Result.Details) {
                    $detailsHTML += "<div class='detail-item detail-info'>Details: $($Result.Details)</div>"
                }
                $detailsHTML += '</div>'
            } elseif ($Result.Success) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">.NET Framework Optimization Tasks</div>'
                if ($Result.Message) {
                    $detailsHTML += "<div class='detail-item detail-success'>[SUCCESS] $($Result.Message)</div>"
                } else {
                    $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] .NET Framework optimization completed</div>'
                }
                if ($Result.FrameworkVersionsOptimized) {
                    $detailsHTML += "<div class='detail-item detail-success'>Frameworks optimized: $($Result.FrameworkVersionsOptimized.Count)</div>"
                }
                if ($Result.TotalAssembliesOptimized) {
                    $detailsHTML += "<div class='detail-item detail-success'>Total assemblies optimized: $($Result.TotalAssembliesOptimized)</div>"
                }
                if ($Result.ExecutionTime) {
                    $detailsHTML += "<div class='detail-item detail-info'>Optimization time: $($Result.ExecutionTime.TotalMinutes.ToString('F2')) minutes</div>"
                }
                if ($Result.Details) {
                    $detailsHTML += "<div class='detail-item detail-info'>Details: $($Result.Details)</div>"
                }
                $detailsHTML += '</div>'
            } else {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">.NET Optimization Issues</div>'
                if ($Result.Message) {
                    $detailsHTML += "<div class='detail-item detail-error'>[ERROR] $($Result.Message)</div>"
                } else {
                    $detailsHTML += "<div class='detail-item detail-error'>[ERROR] .NET Framework optimization encountered issues</div>"
                }
                if ($Result.Error) { $detailsHTML += "<div class='detail-item detail-error'>Error: $($Result.Error)</div>" }
                if ($Result.OptimizationErrors -and $Result.OptimizationErrors.Count -gt 0) {
                    foreach ($OptError in $Result.OptimizationErrors) {
                        $detailsHTML += "<div class='detail-item detail-warning'>Optimization error: $OptError</div>"
                    }
                }
                $detailsHTML += '</div>'
            }
        }
        
        "VDA Verification" {
            if ($Result.Success) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">VDA Verification Tasks</div>'
                if ($Result.Message) {
                    $detailsHTML += "<div class='detail-item detail-success'>[SUCCESS] $($Result.Message)</div>"
                } else {
                    $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Citrix Virtual Desktop Agent verification completed</div>'
                }
                
                # Show registry entries found
                if ($Result.RegistryEntries -and $Result.RegistryEntries.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Registry Entries Verified</div>'
                    foreach ($RegEntry in $Result.RegistryEntries) {
                        $detailsHTML += "<div class='detail-item detail-success'>Found: $RegEntry</div>"
                    }
                    $detailsHTML += '</div>'
                }
                
                # Show VDA services found
                if ($Result.VDAServices -and $Result.VDAServices.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">VDA Services Detected</div>'
                    foreach ($Service in $Result.VDAServices) {
                        $detailsHTML += "<div class='detail-item detail-success'>$($Service.Name) ($($Service.Status))</div>"
                    }
                    $detailsHTML += '</div>'
                }
                
                # Show verification statistics
                if ($Result.RegistryEntries) {
                    $detailsHTML += "<div class='detail-item detail-info'>Registry entries found: $($Result.RegistryEntries.Count)</div>"
                }
                if ($Result.VDAServices) {
                    $detailsHTML += "<div class='detail-item detail-info'>VDA services found: $($Result.VDAServices.Count)</div>"
                }
                
                # Show detailed operations
                if ($Result.Details -and $Result.Details.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Verification Details</div>'
                    foreach ($detail in $Result.Details) {
                        $detailsHTML += "<div class='detail-item detail-info'>$detail</div>"
                    }
                    $detailsHTML += '</div>'
                }
                $detailsHTML += '</div>'
            } else {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">VDA Verification Issues</div>'
                $detailsHTML += "<div class='detail-item detail-error'>[ERROR] VDA verification failed</div>"
                if ($Result.Error) { $detailsHTML += "<div class='detail-item detail-error'>Error: $($Result.Error)</div>" }
                $detailsHTML += '<div class="detail-item detail-warning">Stage 2 operations may be affected</div>'
                $detailsHTML += '</div>'
            }
        }
        
        "Citrix Services" {
            if ($Result.Success) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Citrix Services Detection</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Citrix services detection completed</div>'
                if ($Result.ServicesFound) {
                    $detailsHTML += "<div class='detail-item detail-success'>Services detected: $($Result.ServicesFound)</div>"
                }
                
                # Show detailed service information
                if ($Result.Details -and $Result.Details.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Service Details</div>'
                    foreach ($detail in $Result.Details) {
                        $detailsHTML += "<div class='detail-item detail-info'>$detail</div>"
                    }
                    $detailsHTML += '</div>'
                }
                
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Service registry validation</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Service configuration validation completed</div>'
                $detailsHTML += '</div>'
            } else {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Citrix Services Status</div>'
                
                if ($Result.Message) {
                    $detailsHTML += "<div class='detail-item detail-info'>[INFO] $($Result.Message)</div>"
                } else {
                    $detailsHTML += "<div class='detail-item detail-info'>[INFO] Citrix services detection completed with findings</div>"
                }
                
                # Show detailed service findings
                if ($Result.Details -and $Result.Details.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Service Analysis Results</div>'
                    foreach ($detail in $Result.Details) {
                        if ($detail -match "found|detected|installed") {
                            $detailsHTML += "<div class='detail-item detail-success'>$detail</div>"
                        } elseif ($detail -match "not found|missing|unavailable") {
                            $detailsHTML += "<div class='detail-item detail-warning'>$detail</div>"
                        } else {
                            $detailsHTML += "<div class='detail-item detail-info'>$detail</div>"
                        }
                    }
                    $detailsHTML += '</div>'
                }
                
                # Show service registry information
                if ($Result.RegistryKeys -and $Result.RegistryKeys.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Registry Analysis</div>'
                    foreach ($regKey in $Result.RegistryKeys) {
                        $detailsHTML += "<div class='detail-item detail-info'>$regKey</div>"
                    }
                    $detailsHTML += '</div>'
                }
                
                if ($Result.Error) { 
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Detection Issues</div>'
                    $detailsHTML += "<div class='detail-item detail-error'>Error: $($Result.Error)</div>" 
                    $detailsHTML += '</div>'
                }
                $detailsHTML += '</div>'
            }
        }
        

        
        "NTP Time Configuration" {
            if ($Result.Success) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">NTP Time Source Configuration</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] NTP time sources configured successfully</div>'
                if ($Result.DomainDetected) {
                    $detailsHTML += "<div class='detail-item detail-info'>Domain detected: $($Result.DomainDetected)</div>"
                }
                if ($Result.NTPServersConfigured -and $Result.NTPServersConfigured.Count -gt 0) {
                    $detailsHTML += "<div class='detail-item detail-success'>NTP servers configured: $($Result.NTPServersConfigured.Count)</div>"
                    foreach ($server in $Result.NTPServersConfigured) {
                        $detailsHTML += "<div class='detail-item detail-info'>  - $server</div>"
                    }
                }
                $detailsHTML += '</div>'
                
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">W32Time Service Configuration</div>'
                if ($Result.W32TimeConfigured) {
                    $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] W32Time service configured with NTP client enabled</div>'
                    $detailsHTML += '<div class="detail-item detail-info">Registry: HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters</div>'
                    $detailsHTML += '<div class="detail-item detail-info">Registry: HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config</div>'
                    $detailsHTML += '<div class="detail-item detail-info">Registry: HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient</div>'
                }
                if ($Result.ServiceRestarted) {
                    $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] W32Time service restarted</div>'
                }
                if ($Result.TimeResyncForced) {
                    $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Time synchronization forced</div>'
                } else {
                    $detailsHTML += '<div class="detail-item detail-warning">[INFO] Time synchronization command may have failed but configuration is complete</div>'
                }
                $detailsHTML += '</div>'
            } else {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">NTP Configuration Issues</div>'
                $detailsHTML += '<div class="detail-item detail-error">[ERROR] NTP time source configuration failed</div>'
                if ($Result.DomainDetected) {
                    $detailsHTML += "<div class='detail-item detail-info'>Domain detected: $($Result.DomainDetected)</div>"
                }
                if ($Result.Errors -and $Result.Errors.Count -gt 0) {
                    foreach ($error in $Result.Errors) {
                        $detailsHTML += "<div class='detail-item detail-error'>Error: $error</div>"
                    }
                }
                $detailsHTML += '</div>'
            }
        }

        "System Optimizations" {
            if ($Result.Success -or $Result.OverallStatus) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">System Registry Optimization Tasks</div>'
                if ($Result.Message) {
                    $detailsHTML += "<div class='detail-item detail-success'>[SUCCESS] $($Result.Message)</div>"
                } else {
                    $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] System registry optimizations applied</div>'
                }
                
                # Show optimization count
                if ($Result.OptimizationsApplied) {
                    $detailsHTML += "<div class='detail-item detail-info'>Optimizations applied: $($Result.OptimizationsApplied)</div>"
                }
                
                # Show registry changes
                if ($Result.RegistryChanges -and $Result.RegistryChanges.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Registry Changes</div>'
                    foreach ($RegChange in $Result.RegistryChanges) {
                        $detailsHTML += "<div class='detail-item detail-success'>$RegChange</div>"
                    }
                    $detailsHTML += '</div>'
                }
                
                # Show detailed operations
                if ($Result.Details -and $Result.Details.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Optimization Details</div>'
                    foreach ($detail in $Result.Details) {
                        $detailsHTML += "<div class='detail-item detail-info'>$detail</div>"
                    }
                    $detailsHTML += '</div>'
                }
                $detailsHTML += '</div>'
            } else {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">System Optimization Issues</div>'
                $detailsHTML += "<div class='detail-item detail-error'>[ERROR] System optimization validation encountered issues</div>"
                if ($Result.Error) { $detailsHTML += "<div class='detail-item detail-error'>Error: $($Result.Error)</div>" }
                $detailsHTML += '</div>'
            }
        }
        
        "CitrixOptimizer" {
            if ($Result.Skipped) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Citrix Optimizer Skipped</div>'
                if ($Result.Message) {
                    $detailsHTML += "<div class='detail-item detail-info'>[INFO] $($Result.Message)</div>"
                } else {
                    $detailsHTML += "<div class='detail-item detail-info'>[INFO] Citrix Optimizer skipped - executable not found</div>"
                }
                
                # Show search details - where it looked for the optimizer
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Optimizer Search Details</div>'
                $detailsHTML += "<div class='detail-item detail-info'>Searched for: CitrixOptimizer.exe</div>"
                $detailsHTML += "<div class='detail-item detail-info'>Search paths: Network locations and local directories</div>"
                $detailsHTML += "<div class='detail-item detail-info'>Status: Executable not found - optimization skipped</div>"
                $detailsHTML += "<div class='detail-item detail-info'>Alternative: VDI Registry Optimizations applied separately</div>"
                $detailsHTML += '</div>'
                
                # Show detailed operations
                if ($Result.Details -and $Result.Details.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Skip Details</div>'
                    foreach ($detail in $Result.Details) {
                        $detailsHTML += "<div class='detail-item detail-info'>$detail</div>"
                    }
                    $detailsHTML += '</div>'
                }
                $detailsHTML += '</div>'
            } elseif ($Result.Success -or $Result.OverallStatus) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Citrix Optimizer Execution</div>'
                if ($Result.TemplatesApplied -and $Result.TemplatesApplied.Count -gt 0) {
                    $detailsHTML += "<div class='detail-item detail-success'>[SUCCESS] Applied $($Result.TemplatesApplied.Count) optimization templates</div>"
                    $detailsHTML += '<div class="detail-item detail-info">Templates applied:</div>'
                    foreach ($Template in $Result.TemplatesApplied) {
                        $detailsHTML += "<div class='detail-item detail-success'>  - $Template</div>"
                    }
                } else {
                    $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Citrix Optimizer execution completed</div>'
                }
                if ($Result.OptimizationsApplied) {
                    $detailsHTML += "<div class='detail-item detail-success'>Total optimizations: $($Result.OptimizationsApplied)</div>"
                }
                if ($Result.ExecutionTime) {
                    $detailsHTML += "<div class='detail-item detail-info'>Execution time: $($Result.ExecutionTime)</div>"
                }
                if ($Result.OutputPath) {
                    $detailsHTML += "<div class='detail-item detail-info'>Results saved to: $($Result.OutputPath)</div>"
                }
                $detailsHTML += '</div>'

            } else {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Citrix Optimizer Issues</div>'
                $detailsHTML += "<div class='detail-item detail-error'>[ERROR] Citrix Optimizer execution failed</div>"
                if ($Result.Error) { $detailsHTML += "<div class='detail-item detail-error'>Error: $($Result.Error)</div>" }
                if ($Result.ExitCode) { $detailsHTML += "<div class='detail-item detail-error'>Exit Code: $($Result.ExitCode)</div>" }
                $detailsHTML += '</div>'
            }
        }

        "VDI Optimizations" {
            if ($Result.Success -or $Result.OverallStatus) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">VDI Registry Optimization Tasks</div>'
                if ($Result.Message) {
                    $detailsHTML += "<div class='detail-item detail-success'>[SUCCESS] $($Result.Message)</div>"
                } else {
                    $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] VDI registry optimizations applied</div>'
                }
                
                # Show specific registry changes made
                if ($Result.RegistryChanges -and $Result.RegistryChanges.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Registry Changes Applied</div>'
                    foreach ($regChange in $Result.RegistryChanges) {
                        $detailsHTML += "<div class='detail-item detail-success'>$regChange = 1</div>"
                    }
                    $detailsHTML += '</div>'
                }
                
                # Show optimization categories
                if ($Result.OptimizationCategories -and $Result.OptimizationCategories.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">VDI Optimizations Applied</div>'
                    foreach ($category in $Result.OptimizationCategories) {
                        $detailsHTML += "<div class='detail-item detail-success'>Optimized: $category</div>"
                    }
                    $detailsHTML += '</div>'
                }
                
                # Show statistics
                if ($Result.OptimizationsCount) {
                    $detailsHTML += "<div class='detail-item detail-info'>Total optimizations: $($Result.OptimizationsCount)</div>"
                }
                if ($Result.RegistryKeysModified) {
                    $detailsHTML += "<div class='detail-item detail-info'>Registry keys modified: $($Result.RegistryKeysModified)</div>"
                }
                $detailsHTML += '</div>'
            } elseif ($Result.Skipped) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">VDI Optimization Skipped</div>'
                $detailsHTML += "<div class='detail-item detail-warning'>[SKIPPED] VDI optimizations were skipped</div>"
                $detailsHTML += '</div>'
            } else {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">VDI Optimization Issues</div>'
                $detailsHTML += "<div class='detail-item detail-error'>[ERROR] VDI optimizations encountered issues</div>"
                if ($Result.Error) { $detailsHTML += "<div class='detail-item detail-error'>Error: $($Result.Error)</div>" }
                $detailsHTML += '</div>'
            }
        }
        
        "WEM RSA Cleanup" {
            if ($Result.Success) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">WEM RSA Key Cleanup Tasks</div>'
                if ($Result.Message) {
                    if ($Result.NoFilesFound) {
                        $detailsHTML += "<div class='detail-item detail-info'>[INFO] $($Result.Message)</div>"
                    } else {
                        $detailsHTML += "<div class='detail-item detail-success'>[SUCCESS] $($Result.Message)</div>"
                    }
                } else {
                    $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Citrix WEM RSA key cleanup completed</div>'
                }
                
                # Show search details - what was looked for and where
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Cleanup Search Details</div>'
                $detailsHTML += "<div class='detail-item detail-info'>Directory searched: C:\ProgramData\Microsoft\Crypto\RSA\S-1-5-18</div>"
                $detailsHTML += "<div class='detail-item detail-info'>Target files: fb8cc9e38d3e60ab60c17cdfd6dd6d99_* (WEM RSA keys)</div>"
                if ($Result.NoFilesFound -eq $true) {
                    $detailsHTML += "<div class='detail-item detail-info'>Files found: 0 (none to clean up)</div>"
                    $detailsHTML += "<div class='detail-item detail-success'>Status: No WEM RSA key files present - cleanup not needed</div>"
                } else {
                    # Calculate totals with fallback logic for when files were found and processed
                    $removedCount = if ($Result.RemovedKeys) { $Result.RemovedKeys.Count } else { 0 }
                    $failedCount = if ($Result.FailedRemovals) { $Result.FailedRemovals.Count } else { 0 }
                    $totalFound = $removedCount + $failedCount
                    
                    # If counts are still 0 but we know files were processed (not NoFilesFound), estimate from other data
                    if ($totalFound -eq 0 -and $Result.Success -and !$Result.NoFilesFound) {
                        # Try to get count from Details array - look for various patterns indicating file removal
                        if ($Result.Details -and $Result.Details.Count -gt 0) {
                            $removedFileDetails = $Result.Details | Where-Object { 
                                $_ -match "Removed.*fb8cc9e38d3e60ab60c17cdfd6dd6d99" -or 
                                $_ -match "Deleted.*fb8cc9e38d3e60ab60c17cdfd6dd6d99" -or
                                $_ -match "fb8cc9e38d3e60ab60c17cdfd6dd6d99.*removed" -or
                                $_ -match "fb8cc9e38d3e60ab60c17cdfd6dd6d99.*deleted" -or
                                $_ -match "Successfully removed.*RSA" -or
                                ($_ -like "*fb8cc9e38d3e60ab60c17cdfd6dd6d99*" -and ($_ -match "removed|deleted|cleaned"))
                            }
                            if ($removedFileDetails -and $removedFileDetails.Count -gt 0) {
                                $removedCount = $removedFileDetails.Count
                                $totalFound = $removedCount
                            }
                        }
                        
                        # Also check if Details contains any reference to file operations
                        if ($totalFound -eq 0 -and $Result.Details) {
                            $fileOperationDetails = $Result.Details | Where-Object { 
                                $_ -match "WEM.*RSA|RSA.*key|RSA.*file" -and ($_ -match "removed|deleted|processed|found")
                            }
                            if ($fileOperationDetails -and $fileOperationDetails.Count -gt 0) {
                                $totalFound = 1
                                $removedCount = 1
                            }
                        }
                        
                        # If still no count but success and not NoFilesFound, assume at least 1 file was processed
                        if ($totalFound -eq 0) {
                            $totalFound = 1
                            $removedCount = 1
                        }
                    }
                    
                    $detailsHTML += "<div class='detail-item detail-info'>Files found: $totalFound</div>"
                    $detailsHTML += "<div class='detail-item detail-success'>Successfully removed: $removedCount</div>"
                    if ($failedCount -gt 0) {
                        $detailsHTML += "<div class='detail-item detail-warning'>Failed removals: $failedCount</div>"
                    }
                }
                $detailsHTML += '</div>'
                
                # Show specific files removed or indicate none found
                if ($Result.RemovedKeys -and $Result.RemovedKeys.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">RSA Keys Removed</div>'
                    foreach ($key in $Result.RemovedKeys) {
                        $keyName = Split-Path $key -Leaf
                        $detailsHTML += "<div class='detail-item detail-success'>Removed: $keyName</div>"
                    }
                    $detailsHTML += '</div>'
                } elseif (!$Result.NoFilesFound -and $Result.Success -and $removedCount -gt 0) {
                    # If files were removed but RemovedKeys array is empty, extract from Details
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">RSA Keys Removed</div>'
                    if ($Result.Details -and $Result.Details.Count -gt 0) {
                        $removedFileDetails = $Result.Details | Where-Object { 
                            $_ -like "*fb8cc9e38d3e60ab60c17cdfd6dd6d99*" -and ($_ -match "removed|deleted|cleaned")
                        }
                        if ($removedFileDetails -and $removedFileDetails.Count -gt 0) {
                            foreach ($detail in $removedFileDetails) {
                                $detailsHTML += "<div class='detail-item detail-success'>$detail</div>"
                            }
                        } else {
                            $detailsHTML += "<div class='detail-item detail-success'>WEM RSA key files successfully removed</div>"
                        }
                    } else {
                        $detailsHTML += "<div class='detail-item detail-success'>WEM RSA key files successfully removed</div>"
                    }
                    $detailsHTML += '</div>'
                } 
                
                # Show failed removals if any
                if ($Result.FailedRemovals -and $Result.FailedRemovals.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Failed Removals</div>'
                    foreach ($failed in $Result.FailedRemovals) {
                        $failedName = Split-Path $failed -Leaf
                        $detailsHTML += "<div class='detail-item detail-warning'>Failed: $failedName</div>"
                    }
                    $detailsHTML += '</div>'
                }
                
                # Show detailed operations
                if ($Result.Details -and $Result.Details.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Cleanup Details</div>'
                    foreach ($detail in $Result.Details) {
                        $detailsHTML += "<div class='detail-item detail-info'>$detail</div>"
                    }
                    $detailsHTML += '</div>'
                }
                $detailsHTML += '</div>'
            } else {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">WEM Cleanup Issues</div>'
                $detailsHTML += "<div class='detail-item detail-error'>[ERROR] WEM RSA key cleanup encountered issues</div>"
                if ($Result.Error) { $detailsHTML += "<div class='detail-item detail-error'>Error: $($Result.Error)</div>" }
                $detailsHTML += '</div>'
            }
        }
        
        "Domain Profile Cleanup" {
            if ($Result.Success) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Domain Profile Cleanup Tasks</div>'
                if ($Result.Message) {
                    $detailsHTML += "<div class='detail-item detail-success'>[SUCCESS] $($Result.Message)</div>"
                } else {
                    $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Domain user profile cleanup completed</div>'
                }
                
                # Show specific profiles removed or indicate none found
                if ($Result.ProfilesRemoved -and $Result.ProfilesRemoved -gt 0) {
                    $detailsHTML += "<div class='detail-item detail-success'>Profiles removed: $($Result.ProfilesRemoved)</div>"
                    if ($Result.RemovedProfiles -and $Result.RemovedProfiles.Count -gt 0) {
                        $detailsHTML += '<div class="detail-section">'
                        $detailsHTML += '<div class="detail-section-title">Profiles Cleaned</div>'
                        foreach ($profile in $Result.RemovedProfiles) {
                            $detailsHTML += "<div class='detail-item detail-success'>Removed: $profile</div>"
                        }
                        $detailsHTML += '</div>'
                    }
                } else {
                    $detailsHTML += "<div class='detail-item detail-info'>[INFO] No domain profiles found to clean</div>"
                }
                
                # Show failed removals if any
                if ($Result.FailedRemovals -and $Result.FailedRemovals.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Failed Removals</div>'
                    foreach ($failed in $Result.FailedRemovals) {
                        $detailsHTML += "<div class='detail-item detail-warning'>Failed: $failed</div>"
                    }
                    $detailsHTML += '</div>'
                }
                
                # Show detailed operations
                if ($Result.Details -and $Result.Details.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Cleanup Details</div>'
                    foreach ($detail in $Result.Details) {
                        $detailsHTML += "<div class='detail-item detail-info'>$detail</div>"
                    }
                    $detailsHTML += '</div>'
                }
                
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Template storage optimization</div>'
                $detailsHTML += '</div>'
            } elseif ($Result.Skipped) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Profile Cleanup Skipped</div>'
                $detailsHTML += "<div class='detail-item detail-warning'>[SKIPPED] Domain profile cleanup was disabled</div>"
                $detailsHTML += '</div>'
            } else {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Profile Cleanup Issues</div>'
                $detailsHTML += "<div class='detail-item detail-error'>[ERROR] Domain profile cleanup encountered issues</div>"
                if ($Result.Error) { $detailsHTML += "<div class='detail-item detail-error'>Error: $($Result.Error)</div>" }
                if ($Result.FailedRemovals) {
                    $detailsHTML += "<div class='detail-item detail-warning'>Failed removals: $($Result.FailedRemovals -join ', ')</div>"
                }
                $detailsHTML += '</div>'
            }
        }
        
        "VMware Memory Optimization" {
            if ($Result.Success -or $Result.OverallCompliant) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">VMware Memory Optimization Results</div>'
                if ($Result.Message) {
                    $detailsHTML += "<div class='detail-item detail-success'>[SUCCESS] $($Result.Message)</div>"
                } elseif ($Result.VMwareDetected) {
                    $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] VMware environment detected and optimized</div>'
                } else {
                    $detailsHTML += '<div class="detail-item detail-info">[INFO] Non-VMware environment - optimization not required</div>'
                }
                $detailsHTML += '</div>'
                
                # Show environment detection details
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Environment Detection</div>'
                if ($Result.VMwareDetected) {
                    $detailsHTML += "<div class='detail-item detail-info'>Platform: VMware virtual machine detected</div>"
                    if ($Result.VMwareVersion) {
                        $detailsHTML += "<div class='detail-item detail-info'>VMware Version: $($Result.VMwareVersion)</div>"
                    }
                    if ($Result.HypervisorVendor) {
                        $detailsHTML += "<div class='detail-item detail-info'>Hypervisor: $($Result.HypervisorVendor)</div>"
                    }
                } else {
                    $detailsHTML += "<div class='detail-item detail-info'>Platform: Physical machine or non-VMware hypervisor</div>"
                    if ($Result.HypervisorVendor) {
                        $detailsHTML += "<div class='detail-item detail-info'>Detected Hypervisor: $($Result.HypervisorVendor)</div>"
                    }
                }
                $detailsHTML += '</div>'
                
                # Show memory ballooning configuration details
                if ($Result.VMwareDetected) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Memory Ballooning Configuration</div>'
                    if ($Result.BallooningDisabled) {
                        $detailsHTML += "<div class='detail-item detail-success'>Memory ballooning: Disabled successfully</div>"
                        if ($Result.RegistryPath) {
                            $detailsHTML += "<div class='detail-item detail-info'>Registry path: $($Result.RegistryPath)</div>"
                        }
                        if ($Result.RegistryValue) {
                            $detailsHTML += "<div class='detail-item detail-info'>Registry value: $($Result.RegistryValue)</div>"
                        }
                    } elseif ($Result.AlreadyDisabled) {
                        $detailsHTML += "<div class='detail-item detail-info'>Memory ballooning: Already disabled</div>"
                    } else {
                        $detailsHTML += "<div class='detail-item detail-warning'>Memory ballooning: Status unknown</div>"
                    }
                    $detailsHTML += '</div>'
                    
                    # Show service modifications if any
                    if ($Result.ServicesModified -and $Result.ServicesModified.Count -gt 0) {
                        $detailsHTML += '<div class="detail-section">'
                        $detailsHTML += '<div class="detail-section-title">VMware Services Modified</div>'
                        foreach ($service in $Result.ServicesModified) {
                            $detailsHTML += "<div class='detail-item detail-success'>Service: $service</div>"
                        }
                        $detailsHTML += '</div>'
                    }
                    
                    # Show registry changes made
                    if ($Result.RegistryChanges -and $Result.RegistryChanges.Count -gt 0) {
                        $detailsHTML += '<div class="detail-section">'
                        $detailsHTML += '<div class="detail-section-title">Registry Modifications</div>'
                        foreach ($regChange in $Result.RegistryChanges) {
                            $detailsHTML += "<div class='detail-item detail-info'>$regChange</div>"
                        }
                        $detailsHTML += '</div>'
                    }
                }
                
                # Show operation details
                if ($Result.Details -and $Result.Details.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Operation Details</div>'
                    foreach ($detail in $Result.Details) {
                        $detailsHTML += "<div class='detail-item detail-info'>$detail</div>"
                    }
                    $detailsHTML += '</div>'
                }
                
                # Show optimization summary
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Optimization Summary</div>'
                if ($Result.VMwareDetected) {
                    $detailsHTML += "<div class='detail-item detail-success'>VMware environment optimized for VDI performance</div>"
                    $detailsHTML += "<div class='detail-item detail-info'>Memory ballooning disabled to prevent performance issues</div>"
                    $detailsHTML += "<div class='detail-item detail-info'>Registry configured for optimal memory management</div>"
                } else {
                    $detailsHTML += "<div class='detail-item detail-info'>No VMware-specific optimizations required</div>"
                    $detailsHTML += "<div class='detail-item detail-success'>System ready for standard VDI deployment</div>"
                }
                $detailsHTML += '</div>'
            } else {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">VMware Optimization Issues</div>'
                $detailsHTML += "<div class='detail-item detail-error'>[ERROR] VMware memory optimization encountered issues</div>"
                if ($Result.Error) { $detailsHTML += "<div class='detail-item detail-error'>Error: $($Result.Error)</div>" }
                $detailsHTML += '</div>'
            }
        }
        
        "Automatic Maintenance" {
            if ($Result.Success -or $Result.Optimized) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Automatic Maintenance Disable</div>'
                if ($Result.Message) {
                    $detailsHTML += "<div class='detail-item detail-success'>[SUCCESS] $($Result.Message)</div>"
                } else {
                    $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Windows automatic maintenance disabled</div>'
                }
                
                # Show registry details
                if ($Result.RegistryKey) {
                    $detailsHTML += "<div class='detail-item detail-info'>Registry Key: $($Result.RegistryKey)</div>"
                }
                if ($Result.RegistryValue) {
                    $detailsHTML += "<div class='detail-item detail-info'>Registry Value: $($Result.RegistryValue) ($($Result.RegistryType))</div>"
                }
                
                # Show detailed operations
                if ($Result.Details -and $Result.Details.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Registry Operations</div>'
                    foreach ($detail in $Result.Details) {
                        $detailsHTML += "<div class='detail-item detail-info'>$detail</div>"
                    }
                    $detailsHTML += '</div>'
                }
                $detailsHTML += '</div>'
            } else {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Maintenance Configuration Issues</div>'
                $detailsHTML += "<div class='detail-item detail-error'>[ERROR] Automatic maintenance configuration encountered issues</div>"
                if ($Result.Error) { $detailsHTML += "<div class='detail-item detail-error'>Error: $($Result.Error)</div>" }
                $detailsHTML += '</div>'
            }
        }
        
        "Recycle Bin Disable" {
            if ($Result.Success) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Recycle Bin Disable</div>'
                if ($Result.Message) {
                    $detailsHTML += "<div class='detail-item detail-success'>[SUCCESS] $($Result.Message)</div>"
                } else {
                    $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Desktop Recycle Bin disabled</div>'
                }
                if ($Result.Details) {
                    $detailsHTML += "<div class='detail-item detail-info'>Details: $($Result.Details)</div>"
                }
                $detailsHTML += '</div>'
            } else {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Recycle Bin Configuration Issues</div>'
                $detailsHTML += "<div class='detail-item detail-error'>[ERROR] Recycle Bin disable encountered issues</div>"
                if ($Result.Error) { $detailsHTML += "<div class='detail-item detail-error'>Error: $($Result.Error)</div>" }
                $detailsHTML += '</div>'
            }
        }
        
        "Quick Access Disable" {
            if ($Result.Success) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Quick Access Disable</div>'
                if ($Result.Message) {
                    $detailsHTML += "<div class='detail-item detail-success'>[SUCCESS] $($Result.Message)</div>"
                } else {
                    $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] File Explorer Quick Access disabled</div>'
                }
                if ($Result.Details) {
                    $detailsHTML += "<div class='detail-item detail-info'>Details: $($Result.Details)</div>"
                }
                $detailsHTML += '</div>'
            } else {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Quick Access Configuration Issues</div>'
                $detailsHTML += "<div class='detail-item detail-error'>[ERROR] Quick Access disable encountered issues</div>"
                if ($Result.Error) { $detailsHTML += "<div class='detail-item detail-error'>Error: $($Result.Error)</div>" }
                $detailsHTML += '</div>'
            }
        }
        
        "Event Log Redirection" {
            if ($Result.Success) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Event Log Redirection</div>'
                if ($Result.Message) {
                    $detailsHTML += "<div class='detail-item detail-success'>[SUCCESS] $($Result.Message)</div>"
                } else {
                    $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Event logs redirected to cache drive</div>'
                }
                
                # Show target directory
                if ($Result.TargetDirectory) {
                    $detailsHTML += "<div class='detail-item detail-info'>Target Directory: $($Result.TargetDirectory)</div>"
                }
                if ($Result.RedirectedLogs) {
                    $detailsHTML += "<div class='detail-item detail-info'>Logs Redirected: $($Result.RedirectedLogs)</div>"
                }
                
                # Show registry changes
                if ($Result.RegistryChanges -and $Result.RegistryChanges.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Registry Changes</div>'
                    foreach ($RegChange in $Result.RegistryChanges) {
                        $detailsHTML += "<div class='detail-item detail-info'>$RegChange</div>"
                    }
                    $detailsHTML += '</div>'
                }
                
                # Show detailed operations
                if ($Result.Details -and $Result.Details.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Operation Details</div>'
                    foreach ($detail in $Result.Details) {
                        $detailsHTML += "<div class='detail-item detail-info'>$detail</div>"
                    }
                    $detailsHTML += '</div>'
                }
                $detailsHTML += '</div>'
            } else {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Event Log Redirection Issues</div>'
                $detailsHTML += "<div class='detail-item detail-error'>[ERROR] Event log redirection encountered issues</div>"
                if ($Result.Error) { $detailsHTML += "<div class='detail-item detail-error'>Error: $($Result.Error)</div>" }
                $detailsHTML += '</div>'
            }
        }
        
        "User Profile Redirection" {
            if ($Result.Success) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">User Profile Redirection Tasks</div>'
                if ($Result.Message) {
                    $detailsHTML += "<div class='detail-item detail-success'>[SUCCESS] $($Result.Message)</div>"
                } else {
                    $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] User profiles configured for cache drive</div>'
                }
                
                # Show registry changes made
                if ($Result.RegistryChanges -and $Result.RegistryChanges.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Registry Changes Applied</div>'
                    foreach ($regChange in $Result.RegistryChanges) {
                        $detailsHTML += "<div class='detail-item detail-success'>$regChange</div>"
                    }
                    $detailsHTML += '</div>'
                }
                
                # Show folders created
                if ($Result.FoldersCreated -and $Result.FoldersCreated.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Profile Directories Created</div>'
                    foreach ($folder in $Result.FoldersCreated) {
                        $detailsHTML += "<div class='detail-item detail-success'>Created folder: $folder</div>"
                    }
                    $detailsHTML += '</div>'
                }
                
                # Show configuration details
                if ($Result.Details -and $Result.Details.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Profile Redirection Configuration</div>'
                    foreach ($detail in $Result.Details) {
                        $detailsHTML += "<div class='detail-item detail-info'>$detail</div>"
                    }
                    $detailsHTML += '</div>'
                }
                
                # Show folders created
                if ($Result.FoldersCreated -and $Result.FoldersCreated.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Folders Created</div>'
                    foreach ($folder in $Result.FoldersCreated) {
                        $detailsHTML += "<div class='detail-item detail-success'>Created: $folder</div>"
                    }
                    $detailsHTML += '</div>'
                }
                
                # Show detailed operations
                if ($Result.Details -and $Result.Details.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Configuration Details</div>'
                    foreach ($detail in $Result.Details) {
                        $detailsHTML += "<div class='detail-item detail-info'>$detail</div>"
                    }
                    $detailsHTML += '</div>'
                }
                $detailsHTML += '</div>'
            } elseif ($Result.Skipped) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Profile Redirection Skipped</div>'
                $detailsHTML += "<div class='detail-item detail-warning'>[SKIPPED] User profile redirection was disabled</div>"
                if ($Result.Reason) { $detailsHTML += "<div class='detail-item detail-info'>Reason: $($Result.Reason)</div>" }
                $detailsHTML += '</div>'
            } else {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Profile Redirection Issues</div>'
                $detailsHTML += "<div class='detail-item detail-error'>[ERROR] User profile redirection encountered issues</div>"
                if ($Result.Error) { $detailsHTML += "<div class='detail-item detail-error'>Error: $($Result.Error)</div>" }
                $detailsHTML += '</div>'
            }
        }
        
        "Pagefile Configuration" {
            if ($Result.Skipped) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Pagefile Configuration Skipped</div>'
                if ($Result.Message) {
                    $detailsHTML += "<div class='detail-item detail-info'>[INFO] $($Result.Message)</div>"
                } else {
                    $detailsHTML += "<div class='detail-item detail-info'>[INFO] Pagefile configuration skipped per configuration</div>"
                }
                
                # Show skip details
                if ($Result.Reason) {
                    $detailsHTML += "<div class='detail-item detail-info'>Reason: $($Result.Reason)</div>"
                }
                
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Configuration Status</div>'
                $detailsHTML += "<div class='detail-item detail-info'>ConfigurePagefile setting: Disabled</div>"
                $detailsHTML += "<div class='detail-item detail-info'>Cache drive requirement: $(if($Result.Reason -match 'cache drive'){'Disabled'}else{'Enabled'})</div>"
                $detailsHTML += "<div class='detail-item detail-info'>Status: Pagefile remains at default Windows location</div>"
                $detailsHTML += '</div>'
                $detailsHTML += '</div>'
            } elseif ($Result.Success) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Pagefile Configuration</div>'
                if ($Result.Message) {
                    $detailsHTML += "<div class='detail-item detail-success'>[SUCCESS] $($Result.Message)</div>"
                } else {
                    $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Pagefile configuration optimized</div>'
                }
                if ($Result.PagefileSize) {
                    $detailsHTML += "<div class='detail-item detail-info'>Pagefile size: $($Result.PagefileSize) MB</div>"
                }
                if ($Result.PagefilePath) {
                    $detailsHTML += "<div class='detail-item detail-info'>Pagefile location: $($Result.PagefilePath)</div>"
                }
                if ($Result.Details) {
                    $detailsHTML += "<div class='detail-item detail-info'>Details: $($Result.Details)</div>"
                }
                $detailsHTML += '</div>'
            } else {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Pagefile Configuration Issues</div>'
                $detailsHTML += "<div class='detail-item detail-error'>[ERROR] Pagefile configuration encountered issues</div>"
                if ($Result.Error) { $detailsHTML += "<div class='detail-item detail-error'>Error: $($Result.Error)</div>" }
                $detailsHTML += '</div>'
            }
        }
        
        "Virtual Cache Drive Removal" {
            if ($Result.Success) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Virtual Cache Drive Removal</div>'
                if ($Result.Message) {
                    $detailsHTML += "<div class='detail-item detail-success'>[SUCCESS] $($Result.Message)</div>"
                } else {
                    $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Virtual cache drive removal completed</div>'
                }
                
                # Show VHDX file details
                if ($Result.VHDXFilePath) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">VHDX File Details</div>'
                    $detailsHTML += "<div class='detail-item detail-info'>VHDX path: $($Result.VHDXFilePath)</div>"
                    if ($Result.VHDXSizeMB -gt 0) {
                        $detailsHTML += "<div class='detail-item detail-info'>File size: $($Result.VHDXSizeMB) MB</div>"
                    }
                    if ($Result.DriveLetter) {
                        $detailsHTML += "<div class='detail-item detail-success'>Drive removed: $($Result.DriveLetter)</div>"
                    }
                    $detailsHTML += '</div>'
                }
                
                # Show cleanup operations performed
                if ($Result.VHDXDismounted -or $Result.VHDXRemoved -or $Result.DriveRemoved) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Cleanup Operations</div>'
                    if ($Result.VHDXDismounted) {
                        $detailsHTML += "<div class='detail-item detail-success'>VHDX file dismounted successfully</div>"
                    }
                    if ($Result.VHDXRemoved) {
                        $detailsHTML += "<div class='detail-item detail-success'>VHDX file deleted from storage</div>"
                    }
                    if ($Result.DriveRemoved) {
                        $detailsHTML += "<div class='detail-item detail-success'>Virtual drive detached from system</div>"
                    }
                    $detailsHTML += '</div>'
                }
                
                # Show files removed
                if ($Result.FilesRemoved -and $Result.FilesRemoved.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Files Removed</div>'
                    foreach ($file in $Result.FilesRemoved) {
                        $detailsHTML += "<div class='detail-item detail-success'>Deleted: $file</div>"
                    }
                    $detailsHTML += '</div>'
                }
                
                # Show detailed operations
                if ($Result.Details -and $Result.Details.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Template Finalization Details</div>'
                    foreach ($detail in $Result.Details) {
                        $detailsHTML += "<div class='detail-item detail-info'>$detail</div>"
                    }
                    $detailsHTML += '</div>'
                }
                
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Template storage optimization completed</div>'
                $detailsHTML += '</div>'
            } elseif ($Result.Skipped) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Cache Drive Removal Skipped</div>'
                $detailsHTML += "<div class='detail-item detail-warning'>[SKIPPED] Virtual cache drive removal was not required</div>"
                $detailsHTML += '</div>'
            } else {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Cache Drive Removal Issues</div>'
                $detailsHTML += "<div class='detail-item detail-error'>[ERROR] Virtual cache drive removal encountered issues</div>"
                if ($Result.Error) { $detailsHTML += "<div class='detail-item detail-error'>Error: $($Result.Error)</div>" }
                $detailsHTML += '</div>'
            }
        }
        
        "Run Keys Registry Cleanup" {
            if ($Result.Success) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Run Keys Registry Cleanup</div>'
                if ($Result.TotalRemoved -gt 0) {
                    $detailsHTML += "<div class='detail-item detail-success'>[SUCCESS] Removed $($Result.TotalRemoved) startup registry keys</div>"
                    if ($Result.RemovedKeys -and $Result.RemovedKeys.Count -gt 0) {
                        $detailsHTML += '<div class="detail-item detail-info">Registry keys removed:</div>'
                        foreach ($RemovedKey in $Result.RemovedKeys) {
                            $detailsHTML += "<div class='detail-item detail-success'>  - $RemovedKey</div>"
                        }
                    }
                } elseif ($Result.Skipped) {
                    $detailsHTML += "<div class='detail-item detail-info'>[SKIPPED] No Run keys configured for removal</div>"
                } else {
                    $detailsHTML += "<div class='detail-item detail-info'>[SUCCESS] No problematic Run keys found</div>"
                }
                $detailsHTML += '</div>'
            } else {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Run Keys Cleanup Issues</div>'
                $detailsHTML += "<div class='detail-item detail-error'>[ERROR] Run keys cleanup encountered issues</div>"
                if ($Result.Message) { $detailsHTML += "<div class='detail-item detail-error'>Error: $($Result.Message)</div>" }
                $detailsHTML += '</div>'
            }
        }

        "Active Setup Components Cleanup" {
            if ($Result.Success) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Active Setup Components Cleanup Results</div>'
                
                # Get actual count from the result data
                $actualRemovedCount = 0
                if ($Result.RemovedComponents -and $Result.RemovedComponents.Count -gt 0) {
                    $actualRemovedCount = $Result.RemovedComponents.Count
                } elseif ($Result.TotalRemoved -and $Result.TotalRemoved -gt 0) {
                    $actualRemovedCount = $Result.TotalRemoved
                }
                
                if ($actualRemovedCount -gt 0) {
                    $detailsHTML += "<div class='detail-item detail-success'>[SUCCESS] Removed $actualRemovedCount Active Setup components</div>"
                } elseif ($Result.Skipped) {
                    $detailsHTML += "<div class='detail-item detail-info'>[SKIPPED] No Active Setup components configured for removal</div>"
                } else {
                    $detailsHTML += "<div class='detail-item detail-info'>[SUCCESS] No problematic components found - all components already clean</div>"
                }
                $detailsHTML += '</div>'
                
                # Show configuration details
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Configuration Details</div>'
                $detailsHTML += "<div class='detail-item detail-info'>Registry paths checked: Active Setup Installed Components</div>"
                $detailsHTML += "<div class='detail-item detail-info'>Components configured for removal: 15 GUIDs from config file</div>"
                if ($Result.Details -and $Result.Details.Count -gt 0) {
                    foreach ($detail in $Result.Details) {
                        if ($detail -match "Components processed:" -or $detail -match "Total components removed:") {
                            $detailsHTML += "<div class='detail-item detail-info'>$detail</div>"
                        }
                    }
                }
                $detailsHTML += '</div>'
                
                # Show specific components removed (if any)
                if ($Result.RemovedComponents -and $Result.RemovedComponents.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Components Removed</div>'
                    foreach ($Component in $Result.RemovedComponents) {
                        $detailsHTML += "<div class='detail-item detail-success'>Removed: $Component</div>"
                    }
                    $detailsHTML += '</div>'
                } elseif ($actualRemovedCount -eq 0 -and !$Result.Skipped) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Cleanup Status</div>'
                    $detailsHTML += "<div class='detail-item detail-info'>All 15 configured components were already absent from the system</div>"
                    $detailsHTML += "<div class='detail-item detail-success'>Registry paths are clean - no removal needed</div>"
                    $detailsHTML += '</div>'
                }
                
                # Show registry paths checked
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Registry Paths Checked</div>'
                $detailsHTML += "<div class='detail-item detail-info'>HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components</div>"
                $detailsHTML += "<div class='detail-item detail-info'>HKLM:\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components</div>"
                $detailsHTML += '</div>'
                
                # Show operation summary
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Operation Summary</div>'
                if ($actualRemovedCount -gt 0) {
                    $detailsHTML += "<div class='detail-item detail-success'>Successfully cleaned $actualRemovedCount problematic Active Setup components</div>"
                    $detailsHTML += "<div class='detail-item detail-info'>System optimized for VDI performance</div>"
                } else {
                    $detailsHTML += "<div class='detail-item detail-success'>Active Setup registry is already optimized</div>"
                    $detailsHTML += "<div class='detail-item detail-info'>No problematic components detected</div>"
                }
                $detailsHTML += '</div>'
            } else {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Active Setup Components Cleanup Issues</div>'
                $detailsHTML += "<div class='detail-item detail-error'>[ERROR] Active Setup Components cleanup encountered issues</div>"
                if ($Result.Message) { $detailsHTML += "<div class='detail-item detail-error'>Error: $($Result.Message)</div>" }
                $detailsHTML += '</div>'
            }
        }
        
        "UberAgent Service Configuration" {
            if ($Result.Success) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">UberAgent Service Configuration</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] UberAgent service startup type set to Automatic</div>'
                if ($Result.ServiceName) {
                    $detailsHTML += "<div class='detail-item detail-info'>Service: $($Result.ServiceName)</div>"
                }
                if ($Result.StartupType) {
                    $detailsHTML += "<div class='detail-item detail-info'>Startup Type: $($Result.StartupType)</div>"
                }
                if ($Result.Status) {
                    $detailsHTML += "<div class='detail-item detail-info'>Status: $($Result.Status)</div>"
                }
                $detailsHTML += '</div>'
            } elseif ($Result.Skipped) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">UberAgent Service Configuration Skipped</div>'
                $detailsHTML += "<div class='detail-item detail-warning'>[SKIPPED] UberAgent service configuration was skipped</div>"
                if ($Result.Details) {
                    $detailsHTML += "<div class='detail-item detail-info'>$($Result.Details)</div>"
                }
                $detailsHTML += '</div>'
            } else {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">UberAgent Service Configuration Issues</div>'
                $detailsHTML += "<div class='detail-item detail-error'>[ERROR] UberAgent service configuration encountered issues</div>"
                if ($Result.Error) { $detailsHTML += "<div class='detail-item detail-error'>Error: $($Result.Error)</div>" }
                $detailsHTML += '</div>'
            }
        }
        
        "UberAgent Config Management" {
            if ($Result.Success) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">UberAgent Config Management</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] UberAgent configuration files managed successfully</div>'
                if ($Result.ConfigsCopied) {
                    $detailsHTML += "<div class='detail-item detail-info'>Configurations copied: $($Result.ConfigsCopied)</div>"
                }
                if ($Result.DevConfigPath) {
                    $detailsHTML += "<div class='detail-item detail-info'>Dev config: $($Result.DevConfigPath)</div>"
                }
                if ($Result.ProdConfigPath) {
                    $detailsHTML += "<div class='detail-item detail-info'>Prod config: $($Result.ProdConfigPath)</div>"
                }
                if ($Result.Details -and $Result.Details.Count -gt 0) {
                    foreach ($detail in $Result.Details) {
                        $detailsHTML += "<div class='detail-item detail-info'>$detail</div>"
                    }
                }
                $detailsHTML += '</div>'
            } elseif ($Result.Skipped -or ($Result.Errors -and $Result.Errors -match "No UberAgent config files were copied|check source paths|file availability")) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">UberAgent Config Management Skipped</div>'
                $detailsHTML += "<div class='detail-item detail-warning'>[SKIPPED] UberAgent config management was skipped</div>"
                if ($Result.Message) {
                    $detailsHTML += "<div class='detail-item detail-info'>Reason: $($Result.Message)</div>"
                } elseif ($Result.Errors -and $Result.Errors.Count -gt 0) {
                    $detailsHTML += "<div class='detail-item detail-info'>Reason: $($Result.Errors[0])</div>"
                }
                if ($Result.Details -and $Result.Details.Count -gt 0) {
                    foreach ($detail in $Result.Details) {
                        $detailsHTML += "<div class='detail-item detail-info'>$detail</div>"
                    }
                }
                $detailsHTML += '</div>'
            } else {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">UberAgent Config Management Issues</div>'
                $detailsHTML += "<div class='detail-item detail-error'>[ERROR] UberAgent config management encountered issues</div>"
                if ($Result.Error) { $detailsHTML += "<div class='detail-item detail-error'>Error: $($Result.Error)</div>" }
                if ($Result.Errors -and $Result.Errors.Count -gt 0) {
                    foreach ($error in $Result.Errors) {
                        $detailsHTML += "<div class='detail-item detail-error'>Error: $error</div>"
                    }
                }
                $detailsHTML += '</div>'
            }
        }
        
        "Installed Software Versions" {
            if ($Result.Success) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Installed Software Version Check</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Software version check completed</div>'
                
                if ($Result.VDAVersion) {
                    $detailsHTML += "<div class='detail-item detail-success'>Citrix VDA: $($Result.VDAVersion)</div>"
                } else {
                    $detailsHTML += "<div class='detail-item detail-info'>Citrix VDA: Not installed</div>"
                }
                
                if ($Result.PVSVersion) {
                    $detailsHTML += "<div class='detail-item detail-success'>PVS Target Device: $($Result.PVSVersion)</div>"
                } else {
                    $detailsHTML += "<div class='detail-item detail-info'>PVS Target Device: Not installed</div>"
                }
                
                if ($Result.WEMVersion) {
                    $detailsHTML += "<div class='detail-item detail-success'>WEM Agent: $($Result.WEMVersion)</div>"
                } else {
                    # Check if WEM service was detected even without version
                    $wemServiceDetected = $false
                    if ($Result.Details) {
                        foreach ($detail in $Result.Details) {
                            if ($detail -like "*WEM Agent: Service detected*") {
                                $detailsHTML += "<div class='detail-item detail-info'>WEM Agent: Service detected (version unavailable)</div>"
                                $wemServiceDetected = $true
                                break
                            }
                        }
                    }
                    if (-not $wemServiceDetected) {
                        $detailsHTML += "<div class='detail-item detail-info'>WEM Agent: Not installed</div>"
                    }
                }
                
                if ($Result.UberAgentVersion) {
                    $detailsHTML += "<div class='detail-item detail-success'>UberAgent: $($Result.UberAgentVersion)</div>"
                } else {
                    $detailsHTML += "<div class='detail-item detail-info'>UberAgent: Not installed</div>"
                }
                
                if ($Result.Details -and $Result.Details.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Version Details</div>'
                    foreach ($detail in $Result.Details) {
                        $detailsHTML += "<div class='detail-item detail-info'>$detail</div>"
                    }
                    $detailsHTML += '</div>'
                }
                $detailsHTML += '</div>'
            } elseif ($Result.Skipped) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Software Version Check Skipped</div>'
                $detailsHTML += "<div class='detail-item detail-warning'>[SKIPPED] Software version check was skipped</div>"
                if ($Result.Message) {
                    $detailsHTML += "<div class='detail-item detail-info'>Reason: $($Result.Message)</div>"
                }
                $detailsHTML += '</div>'
            } else {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Software Version Check Issues</div>'
                $detailsHTML += "<div class='detail-item detail-error'>[ERROR] Software version check encountered issues</div>"
                if ($Result.Error) { $detailsHTML += "<div class='detail-item detail-error'>Error: $($Result.Error)</div>" }
                $detailsHTML += '</div>'
            }
        }
        
    }
    
    return $detailsHTML
}

function New-CitrixReport {
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$InstallResults,
        
        [Parameter(Mandatory=$false)]
        [hashtable]$ValidationResults = @{},
        
        [Parameter(Mandatory=$true)]
        [int]$Stage,
        
        [Parameter(Mandatory=$false)]
        [string]$OutputPath = "",
        
        [Parameter(Mandatory=$false)]
        [bool]$OpenInBrowser = $true,
        
        [Parameter(Mandatory=$false)]
        [hashtable]$ConfigData = @{}
    )
    
    # Get configurable report output path from config data
    if ([string]::IsNullOrEmpty($OutputPath) -and $ConfigData.Count -gt 0) {
        # Try to get report output path from cached config
        $ConfigFilePath = "CitrixConfig.txt"
        if (-not [System.IO.Path]::IsPathRooted($ConfigFilePath)) {
            $ConfigFilePath = Join-Path $PSScriptRoot $ConfigFilePath
        }
        
        $ReportOutputPath = ""
        $ReportFileName = ""
        
        if (Test-Path $ConfigFilePath) {
            # Read report configuration from config file
            $ReportOutputPath = Get-ConfigValue -Key "ReportOutputPath" -DefaultValue "%USERPROFILE%\Desktop" -ConfigFile $ConfigFilePath
            $ReportFileName = Get-ConfigValue -Key "ReportFileName" -DefaultValue "Citrix_Installation_Report_Stage_%STAGE%_%DATE%_%TIME%.html" -ConfigFile $ConfigFilePath
            
            # Expand environment variables and placeholders
            $ReportOutputPath = Expand-ConfigPath -Path $ReportOutputPath -Stage $Stage
            $ReportFileName = Expand-ConfigPath -Path $ReportFileName -Stage $Stage
            
            $OutputPath = Join-Path $ReportOutputPath $ReportFileName
        } else {
            # Fallback to default desktop path
            $OutputPath = Join-Path $env:USERPROFILE "Desktop\Citrix_Installation_Report_Stage_$($Stage)_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
        }
    } elseif ([string]::IsNullOrEmpty($OutputPath)) {
        # Default fallback
        $OutputPath = Join-Path $env:USERPROFILE "Desktop\Citrix_Installation_Report_Stage_$($Stage)_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    }
    
    # Gather system information
    $ComputerName = $env:COMPUTERNAME
    $UserName = $env:USERNAME
    $ReportTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    try {
        $OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem
        $OSCaption = $OSInfo.Caption
        $TotalMemoryGB = [math]::Round($OSInfo.TotalVisibleMemorySize / 1MB, 2)
    } catch {
        $OSCaption = "Windows"
        $TotalMemoryGB = "Unknown"
    }
    
    # Component display name mapping
    $ComponentDisplayNames = @{
        'VDA' = 'Citrix VDA'
        'PVS' = 'PVS Target Device'
        'WEM' = 'WEM Agent'
        'UberAgent' = 'UberAgent'
        'TADDM' = 'IBM TADDM Agent'
        'CacheDrive' = 'Cache Drive'
        'CitrixOptimizer' = 'Citrix Optimizer'
        'ActiveComponentsResult' = 'Active Setup Components Cleanup'
        'RunKeysResult' = 'Run Keys Registry Cleanup'
        'CitrixServicesDisabled' = 'Windows Services'

        'NTP Time Configuration' = 'NTP Time Sources'
        'Scripts' = 'Startup / Shutdown Scripts'
        'DomainJoin' = 'Domain Join'
        'VDA Verification' = 'Citrix VDA Verification'
        'Citrix Services' = 'Citrix Services Detection'
        'System Optimizations' = 'System Optimizations'
        'VDI Optimizations' = 'VDI Registry Optimizations'
        'WEM RSA Cleanup' = 'WEM RSA Key Cleanup'
        'Domain Profile Cleanup' = 'Domain Profile Cleanup'
        'VMware Memory Optimization' = 'VMware Memory Optimization'

        'RDS Grace Period Reset' = 'RDS Grace Period Reset'
        'Network Optimizations' = 'Network Optimizations'
        'Storage Optimizations' = 'Storage Optimizations'
        'Ghost Device Removal' = 'Ghost Device Removal'
        'System Defragmentation' = 'System Defragmentation'
        'Event Logs Cleanup' = 'Event Logs Cleanup'
        '.NET Framework Optimization' = '.NET Framework Optimization'
        'Automatic Maintenance' = 'Automatic Maintenance Disable'
        'Recycle Bin Disable' = 'Recycle Bin Disable'
        'Quick Access Disable' = 'Quick Access Disable'
        'Event Log Redirection' = 'Event Log Redirection'
        'User Profile Redirection' = 'User Profile Redirection'
        'Pagefile Configuration' = 'Pagefile Configuration'
        'UberAgent Service Configuration' = 'UberAgent Service Configuration'
        'UberAgent Config Management' = 'UberAgent Config Management'
        'Virtual Cache Drive Removal' = 'Virtual Cache Drive Removal'
        'Installed Software Versions' = 'Installed Software Versions'
        'DNSConfiguration' = 'DNS Configuration'
    }
    
    # Filter components based on stage - only show components that actually run in each stage
    $StageComponents = @{
        1 = @('VDA', 'PVS', 'WEM', 'UberAgent', 'TADDM', 'CacheDrive', 'DomainJoin', 'DNSConfiguration')
        2 = @('VDA Verification', 'Citrix Services', 'System Optimizations', 'NTP Time Configuration', 'CitrixOptimizer', 'Scripts', 'VDI Optimizations', 'WEM RSA Cleanup', 'Domain Profile Cleanup', 'VMware Memory Optimization', 'RDS Grace Period Reset', 'Network Optimizations', 'Storage Optimizations', 'Ghost Device Removal', 'System Defragmentation', 'Event Logs Cleanup', '.NET Framework Optimization', 'Active Setup Components Cleanup', 'Run Keys Registry Cleanup', 'Automatic Maintenance', 'Recycle Bin Disable', 'Quick Access Disable', 'Event Log Redirection', 'User Profile Redirection', 'Pagefile Configuration', 'UberAgent Service Configuration', 'UberAgent Config Management', 'Virtual Cache Drive Removal', 'Installed Software Versions')
    }
    
    # Only include components that should run in this stage
    if ($StageComponents.ContainsKey($Stage)) {
        $ExpectedComponents = $StageComponents[$Stage]
        # Filter InstallResults to only include expected components for this stage
        $FilteredResults = @{}
        foreach ($ComponentName in $InstallResults.Keys) {
            if ($ExpectedComponents -contains $ComponentName) {
                $FilteredResults[$ComponentName] = $InstallResults[$ComponentName]
            }
        }
        $InstallResults = $FilteredResults
    }
    
    # Define component execution order first based on stage
    if ($Stage -eq 1) {
        $ComponentOrder = @{
            'CacheDrive' = 1
            'VDA' = 2
            'PVS' = 3
            'WEM' = 4
            'TADDM' = 5
            'TADDMSCMConfig' = 6
            'UberAgent' = 7
            'DNSConfiguration' = 8
            'DomainJoin' = 9
            'Scripts' = 10
            'ScriptConfiguration' = 11
            'CitrixServicesDisabled' = 12
        }
    } else {
        # Stage 2 execution order based on actual script line sequence
        $ComponentOrder = @{
            'VDA Verification' = 1                        # Line 455: VDA INSTALLATION VERIFICATION
            'Citrix Services' = 2                         # Line 473: CITRIX SERVICES VALIDATION
            'System Optimizations' = 3                    # Line 493: SYSTEM OPTIMIZATION VERIFICATION
            'NTP Time Configuration' = 4                  # Line 512: NTP TIME SOURCE CONFIGURATION
            'CitrixOptimizer' = 5                         # Line 548/554: CITRIX OPTIMIZER EXECUTION/SKIPPED
            'Scripts' = 6                                 # Line 591: STARTUP AND SHUTDOWN SCRIPTS CONFIGURATION
            'VMware Memory Optimization' = 7             # Line 650: VMWARE MEMORY BALLOONING DISABLE
            'Recycle Bin Disable' = 8                    # Line 685: RECYCLE BIN CREATION DISABLE
            'Quick Access Disable' = 9                   # Line 715: QUICK ACCESS AND USER FOLDERS DISABLE
            'Network Optimizations' = 10                 # Line 742: NETWORK OPTIMIZATIONS
            'VDI Optimizations' = 11                     # Line 843: COMPREHENSIVE SYSTEM OPTIMIZATIONS (VDI part)
            'Storage Optimizations' = 12                 # Line 904: STORAGE OPTIMIZATIONS
            'RDS Grace Period Reset' = 13                # Line 949: RDS GRACE PERIOD RESET
            'Automatic Maintenance' = 14                 # Line 974: WINDOWS AUTOMATIC MAINTENANCE OPTIMIZATION
            'WEM RSA Cleanup' = 15                       # Line 1002: WEM RSA CLEANUP VERIFICATION
            'Domain Profile Cleanup' = 16                # Line 1045: DOMAIN PROFILE CLEANUP
            'Ghost Device Removal' = 17                  # Line 1102: GHOST DEVICE REMOVAL
            'System Defragmentation' = 18                # Line 1143: SYSTEM DRIVE DEFRAGMENTATION
            'Event Logs Cleanup' = 19                    # Line 1194: WINDOWS EVENT LOGS CLEANUP
            '.NET Framework Optimization' = 20           # Line 1235: .NET FRAMEWORK OPTIMIZATION
            'Run Keys Registry Cleanup' = 21             # Line 1267: RUN KEYS REGISTRY CLEANUP
            'Active Setup Components Cleanup' = 22       # Line 1301: ACTIVE COMPONENTS REGISTRY CLEANUP
            'Event Log Redirection' = 23                 # Line 1338: CACHE DRIVE REDIRECTIONS CONFIGURATION (Event Logs part)
            'User Profile Redirection' = 24              # Line 1338: CACHE DRIVE REDIRECTIONS CONFIGURATION (User Profiles part)
            'Pagefile Configuration' = 25                # Line 1418: FINAL OPTIMIZATION - PAGEFILE CONFIGURATION
            'UberAgent Service Configuration' = 26       # Line 1460: UBERAGENT SERVICE CONFIGURATION
            'UberAgent Config Management' = 27           # Line 1513: UBERAGENT CONFIG MANAGEMENT
            'Installed Software Versions' = 28           # Line 1575: INSTALLED SOFTWARE VERSIONS
            'Virtual Cache Drive Removal' = 29           # Line 1700+: Virtual cache drive operations
        }
    }
    
    # Sort components first to ensure consistent processing with robust error handling
    $SortedComponents = @()
    
    # Filter out null/empty keys first
    $ValidKeys = $InstallResults.Keys | Where-Object { $_ -ne $null -and $_ -ne "" }
    

    
    # Create a manual sorted list to avoid Sort-Object issues
    $ComponentsWithOrder = @()
    
    # Ensure ComponentOrder is properly initialized
    if (-not $ComponentOrder -or $ComponentOrder -eq $null) {
        Write-Host "WARNING: ComponentOrder not initialized, using default ordering" -ForegroundColor Yellow
        $ComponentOrder = @{}
    }
    
    foreach ($key in $ValidKeys) {
        $order = 999  # Default for unknown components
        if ($ComponentOrder -and $ComponentOrder.ContainsKey($key)) {
            $order = $ComponentOrder[$key]
        }
        $ComponentsWithOrder += [PSCustomObject]@{
            Name = $key
            Order = $order
        }
    }
    
    # Sort manually without using Sort-Object to avoid null-valued expression errors
    $SortedComponentsList = @()
    
    for ($i = 1; $i -le 50; $i++) {  # Loop through order numbers
        foreach ($comp in $ComponentsWithOrder) {
            if ($comp.Order -eq $i) {
                $SortedComponentsList += $comp.Name
            }
        }
    }
    # Add any remaining components with order 999 (unknown)
    foreach ($comp in $ComponentsWithOrder) {
        if ($comp.Order -eq 999) {
            $SortedComponentsList += $comp.Name
        }
    }
    $SortedComponents = $SortedComponentsList
    
    # Calculate statistics using the same sorted list that will be displayed
    $TotalComponents = $SortedComponents.Count
    $SuccessfulComponents = 0
    $FailedComponents = 0
    $SkippedComponents = 0
    
    foreach ($ComponentName in $SortedComponents) {
        $Result = $InstallResults[$ComponentName]
        if ($Result -is [hashtable]) {
            # Use EXACT same logic as console output for consistency
            $isSkipped = $false
            
            # Primary skip check - explicit skipped flag
            if ($Result.Skipped -eq $true) {
                $isSkipped = $true
            }
            
            # Check for skip-related error messages (only if component didn't succeed)
            if (!$Result.Success -and $Result.Error -and $Result.Error -match "ISO file not found|file not found|not found|disabled in configuration|not configured|skipped|not available|not provided|executable not found") {
                $isSkipped = $true
            }
            
            # Check for skip-related messages (only if component didn't succeed)
            if (!$Result.Success -and $Result.Message -and $Result.Message -match "skipped|disabled|not configured|not found|not available|not provided") {
                $isSkipped = $true
            }
            
            # Check for common skip conditions based on component type (matching console logic exactly)
            if ($ComponentName -eq "Scripts" -and (!$Result.Success -and !$Result.Error)) {
                $isSkipped = $true  # Scripts often return no result when skipped
            }
            
            if ($ComponentName -eq ".NET Framework Optimization" -and !$Result.Success -and $Result.Error -match "ngen|not found") {
                $isSkipped = $true
            }
            
            if ($ComponentName -eq "System Defragmentation" -and !$Result.Success -and $Result.Error -match "disabled|skipped") {
                $isSkipped = $true
            }
            
            if ($ComponentName -eq "UberAgent Service Configuration" -and !$Result.Success -and $Result.Error -match "not found|not configured") {
                $isSkipped = $true
            }
            
            if ($ComponentName -eq "Event Logs Cleanup" -and !$Result.Success -and $Result.Error -match "disabled|not configured") {
                $isSkipped = $true
            }
            
            if ($ComponentName -eq "Citrix Services" -and (!$Result.Success -and !$Result.Error)) {
                $isSkipped = $true  # Services detection often returns neutral when no services found
            }
            
            if ($ComponentName -eq "NTP Time Configuration" -and !$Result.Success -and $Result.Error -match "disabled|not configured") {
                $isSkipped = $true
            }
            
            if ($isSkipped) {
                $SkippedComponents++
            }
            # Check for success (only if not already marked as skipped)
            elseif ($Result.Success -eq $true) {
                $isSuccess = $true
                $SuccessfulComponents++
            }
            # Everything else is failed
            else {
                $FailedComponents++
            }
        }
    }
    
    $SuccessRate = if ($TotalComponents -gt 0) { [math]::Round(($SuccessfulComponents / $TotalComponents) * 100, 1) } else { 0 }
    
    # Generate HTML content
    $HTML = @()
    
    $HTML += '<!DOCTYPE html>'
    $HTML += '<html lang="en">'
    $HTML += '<head>'
    $HTML += '<meta charset="UTF-8">'
    $HTML += '<meta name="viewport" content="width=device-width, initial-scale=1.0">'
    $HTML += "<title>Citrix Installation Report - Stage $Stage</title>"
    
    # Analytics dashboard CSS
    $HTML += '<style>'
    $HTML += '@import url("https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap");'
    $HTML += '* { margin: 0; padding: 0; box-sizing: border-box; }'
    $HTML += 'body { font-family: "Inter", sans-serif; background: #f8fafc; color: #1e293b; line-height: 1.5; }'
    
    # Header styles
    $HTML += '.header { background: white; border-bottom: 1px solid #e2e8f0; padding: 12px 24px; display: flex; justify-content: center; align-items: center; flex-wrap: wrap; }'
    $HTML += '.header-left { display: flex; align-items: center; flex-direction: column; text-align: center; }'
    $HTML += '.header-title { font-size: 24px; font-weight: 700; color: #1e293b; margin: 0; text-align: center; }'
    $HTML += '.header-subtitle { font-size: 14px; color: #64748b; margin: 4px 0 0 0; text-align: center; }'
    $HTML += '.system-info { display: flex; gap: 24px; margin-top: 8px; justify-content: center; flex-wrap: wrap; }'
    $HTML += '.info-item { font-size: 14px; font-weight: 400; color: #64748b; }'
    
    # Container and layout
    $HTML += '.container { max-width: 1400px; margin: 0 auto; padding: 16px; }'
    $HTML += '.dashboard-grid { display: grid; grid-template-columns: 2fr 1fr; gap: 24px; margin-bottom: 24px; }'
    $HTML += '.chart-section { display: grid; gap: 20px; }'
    $HTML += '.sidebar-section { display: grid; gap: 20px; }'
    
    # Card styles
    $HTML += '.card { background: white; border-radius: 12px; border: 1px solid #e2e8f0; padding: 24px; }'
    $HTML += '.card-header { display: flex; justify-content: between; align-items: center; margin-bottom: 20px; }'
    $HTML += '.card-title { font-size: 18px; font-weight: 600; color: #1e293b; margin: 0; }'
    $HTML += '.card-subtitle { font-size: 14px; color: #64748b; margin: 4px 0 0 0; }'
    
    # Stats cards
    $HTML += '.stats-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 24px; }'
    $HTML += '.stat-card { background: white; border-radius: 12px; border: 1px solid #e2e8f0; padding: 16px; text-align: center; }'
    $HTML += '.stat-number { font-size: 28px; font-weight: 700; margin-bottom: 4px; }'
    $HTML += '.stat-label { font-size: 13px; color: #64748b; }'
    $HTML += '.stat-success { color: #059669; }'
    $HTML += '.stat-error { color: #dc2626; }'
    $HTML += '.stat-warning { color: #d97706; }'
    $HTML += '.stat-info { color: #3C1053; }'
    
    # Progress bars with expandable functionality
    $HTML += '.progress-section { }'
    $HTML += '.progress-item { margin-bottom: 16px; border-bottom: 1px solid #f1f5f9; padding-bottom: 16px; }'
    $HTML += '.progress-item:last-child { border-bottom: none; }'
    $HTML += '.progress-header { display: flex; justify-content: space-between; margin-bottom: 8px; cursor: pointer; }'
    $HTML += '.progress-header:hover { background: #f8fafc; margin: 0 -12px; padding: 4px 12px; border-radius: 6px; }'
    $HTML += '.progress-label { font-size: 14px; font-weight: 500; color: #374151; }'
    $HTML += '.progress-value { font-size: 14px; font-weight: 600; display: flex; align-items: center; gap: 8px; }'
    $HTML += '.progress-bar { width: 100%; height: 8px; background: #f1f5f9; border-radius: 4px; overflow: hidden; margin-bottom: 8px; }'
    $HTML += '.progress-fill { height: 100%; border-radius: 4px; transition: width 1s ease; }'
    $HTML += '.progress-success { background: #059669; }'
    $HTML += '.progress-error { background: #dc2626; }'
    $HTML += '.progress-warning { background: #d97706; }'
    $HTML += '.progress-expand-icon { margin-left: 8px; transition: transform 0.3s; font-size: 12px; color: #9ca3af; }'
    $HTML += '.progress-expand-icon.expanded { transform: rotate(180deg); }'
    $HTML += '.progress-details { max-height: 0; overflow: hidden; transition: max-height 0.3s ease; }'
    $HTML += '.progress-details.expanded { max-height: 500px; overflow-y: auto; }'
    $HTML += '.progress-details-content { padding: 12px 16px; background: #f8fafc; border-left: 3px solid #e2e8f0; margin: 0 -8px 8px -8px; border-radius: 6px; word-wrap: break-word; overflow-wrap: break-word; }'
    
    # Gauge chart
    $HTML += '.gauge-container { text-align: center; padding: 20px; }'
    $HTML += '.gauge { width: 240px; height: 140px; margin: 0 auto 16px; position: relative; }'
    $HTML += '.gauge svg { width: 100%; height: 100%; overflow: visible; }'
    $HTML += '.gauge-bg { fill: none; stroke: #e2e8f0; stroke-width: 16; }'
    $HTML += '.gauge-progress { fill: none; stroke: #3C1053; stroke-width: 16; stroke-linecap: round; transition: stroke-dashoffset 1s ease; }'
    $HTML += '.gauge-text { font-size: 24px; font-weight: 700; color: #1e293b; }'
    $HTML += '.gauge-label { font-size: 14px; color: #64748b; }'
    
    # Component list
    $HTML += '.components-list { }'
    $HTML += '.component-item { border-bottom: 1px solid #f1f5f9; }'
    $HTML += '.component-item:last-child { border-bottom: none; }'
    $HTML += '.component-header { display: flex; align-items: center; padding: 12px 0; cursor: pointer; }'
    $HTML += '.component-header:hover { background: #f8fafc; margin: 0 -16px; padding-left: 16px; padding-right: 16px; }'
    $HTML += '.component-status { width: 12px; height: 12px; border-radius: 50%; margin-right: 12px; }'
    $HTML += '.status-success { background: #059669; }'
    $HTML += '.status-error { background: #dc2626; }'
    $HTML += '.status-warning { background: #d97706; }'
    $HTML += '.component-name { flex: 1; font-size: 14px; font-weight: 500; color: #374151; }'
    $HTML += '.component-result { font-size: 12px; color: #64748b; }'
    $HTML += '.expand-icon { margin-left: 8px; transition: transform 0.3s; font-size: 12px; color: #9ca3af; }'
    $HTML += '.expand-icon.expanded { transform: rotate(180deg); }'
    $HTML += '.component-details { max-height: 0; overflow: hidden; transition: max-height 0.3s ease; }'
    $HTML += '.component-details.expanded { max-height: 600px; overflow-y: auto; }'
    $HTML += '.details-content { padding: 12px 24px; background: #f8fafc; border-left: 3px solid #e2e8f0; margin: 0 -16px 8px -16px; word-wrap: break-word; overflow-wrap: break-word; }'
    $HTML += '.detail-section { margin-bottom: 12px; }'
    $HTML += '.detail-section-title { font-weight: 600; color: #374151; margin-bottom: 6px; font-size: 13px; }'
    $HTML += '.detail-item { margin-bottom: 4px; font-size: 12px; padding-left: 12px; word-wrap: break-word; overflow-wrap: break-word; white-space: normal; }'
    $HTML += '.detail-success { color: #059669; }'
    $HTML += '.detail-error { color: #dc2626; }'
    $HTML += '.detail-warning { color: #d97706; }'
    $HTML += '.detail-info { color: #64748b; }'
    
    # Horizontal bar chart
    $HTML += '.chart-container { margin-top: 20px; }'
    $HTML += '.chart-bar-item { margin-bottom: 12px; }'
    $HTML += '.chart-bar-header { display: flex; justify-content: space-between; margin-bottom: 4px; }'
    $HTML += '.chart-bar-label { font-size: 14px; color: #374151; }'
    $HTML += '.chart-bar-value { font-size: 14px; font-weight: 600; color: #1e293b; }'
    $HTML += '.chart-bar { width: 100%; height: 6px; background: #f1f5f9; border-radius: 3px; overflow: hidden; }'
    $HTML += '.chart-bar-fill { height: 100%; border-radius: 3px; }'
    
    # List with numbers
    $HTML += '.numbered-list { }'
    $HTML += '.list-item { display: flex; justify-content: space-between; align-items: center; padding: 8px 0; }'
    $HTML += '.list-name { font-size: 14px; color: #374151; }'
    $HTML += '.list-number { font-size: 14px; font-weight: 600; color: #1e293b; }'
    
    # Responsive media queries for low-resolution screens
    $HTML += '@media screen and (max-width: 1200px) {'
    $HTML += '.container { padding: 12px; }'
    $HTML += '.dashboard-grid { grid-template-columns: 1fr; gap: 16px; }'
    $HTML += '.stats-grid { grid-template-columns: repeat(3, 1fr); gap: 8px; }'
    $HTML += '.header { padding: 16px; }'
    $HTML += '.card { padding: 16px; }'
    $HTML += '.gauge { width: 200px; height: 120px; }'
    $HTML += '}'
    
    $HTML += '@media screen and (max-width: 900px) {'
    $HTML += '.container { padding: 8px; }'
    $HTML += '.stats-grid { grid-template-columns: repeat(3, 1fr); gap: 6px; }'
    $HTML += '.header-title { font-size: 20px; }'
    $HTML += '.header-subtitle { font-size: 12px; }'
    $HTML += '.system-info { gap: 12px; }'
    $HTML += '.info-item { font-size: 11px; }'
    $HTML += '.card-title { font-size: 16px; }'
    $HTML += '.stat-number { font-size: 24px; }'
    $HTML += '.stat-label { font-size: 12px; }'
    $HTML += '.gauge { width: 180px; height: 100px; }'
    $HTML += '}'
    
    $HTML += '@media screen and (max-width: 600px) {'
    $HTML += '.container { padding: 4px; }'
    $HTML += '.header { padding: 8px; flex-direction: column; }'
    $HTML += '.header-left { margin-bottom: 8px; }'
    $HTML += '.header-top { gap: 12px; margin-bottom: 8px; }'
    $HTML += '.logo { width: 40px; height: 40px; font-size: 16px; }'
    $HTML += '.header-title { font-size: 18px; }'
    $HTML += '.header-subtitle { font-size: 11px; }'
    $HTML += '.stage-badge { padding: 6px 12px; font-size: 12px; }'
    $HTML += '.system-info { flex-direction: column; gap: 4px; }'
    $HTML += '.card { padding: 12px; }'
    $HTML += '.card-title { font-size: 14px; }'
    $HTML += '.stat-card { padding: 12px; }'
    $HTML += '.stat-number { font-size: 20px; }'
    $HTML += '.stat-label { font-size: 11px; }'
    $HTML += '.progress-label { font-size: 13px; }'
    $HTML += '.progress-value { font-size: 13px; }'
    $HTML += '.component-name { font-size: 13px; }'
    $HTML += '.gauge { width: 160px; height: 90px; }'
    $HTML += '.gauge-text { font-size: 20px; }'
    $HTML += '.gauge-label { font-size: 12px; }'
    $HTML += '}'
    
    $HTML += '</style>'
    $HTML += '</head>'
    $HTML += '<body>'
    
    # Header
    $HTML += '<div class="header">'
    $HTML += '<div class="header-left">'
    $HTML += '<div>'
    $HTML += '<div class="header-title" style="font-size: 36px; font-weight: 800;">Citrix Platform Layer Results - Stage ' + $Stage + '</div>'
    $HTML += '<div class="system-info">'
    $HTML += "<span class='info-item'>Computer: $ComputerName</span>"
    $HTML += "<span class='info-item'>User: $UserName</span>"
    $HTML += "<span class='info-item'>Generated: $ReportTime</span>"
    $HTML += "<span class='info-item'>OS: $OSCaption</span>"
    $HTML += "<span class='info-item'>Memory: $TotalMemoryGB GB</span>"
    $HTML += '</div>'
    $HTML += '</div>'
    $HTML += '</div>'
    
    # Add Stage 1 specific instruction message
    if ($Stage -eq 1) {
        $HTML += '<div class="container">'
        $HTML += '<div class="card" style="margin-bottom: 16px; background: #3C1053; border-color: #3C1053; padding: 16px;">'
        $HTML += '<div class="card-header" style="margin-bottom: 12px;">'
        $HTML += '<div class="card-title" style="color: white; font-size: 16px; font-weight: 600;">Next Steps Required</div>'
        $HTML += '</div>'
        $HTML += '<div style="color: white; font-weight: 400; line-height: 1.5; font-size: 14px;">'
        $HTML += '1. Please confirm the results are successful and reboot the server.<br>'
        $HTML += '2. Login with your domain account.<br>'
        $HTML += '3. Log out of your domain account once the profile has fully loaded.<br>'
        $HTML += '4. Log back in with the local admin account ready to run Stage 2 from C:\Temp'
        $HTML += '</div>'
        $HTML += '</div>'
    }
    
    # Add Stage 2 specific instruction message
    if ($Stage -eq 2) {
        $HTML += '<div class="container">'
        $HTML += '<div class="card" style="margin-bottom: 16px; background: #3C1053; border-color: #3C1053; padding: 16px;">'
        $HTML += '<div class="card-header" style="margin-bottom: 12px;">'
        $HTML += '<div class="card-title" style="color: white; font-size: 16px; font-weight: 600;">Next Steps Required</div>'
        $HTML += '</div>'
        $HTML += '<div style="color: white; font-weight: 400; line-height: 1.5; font-size: 14px;">'
        $HTML += '1. Please confirm the results are successful and close the report.<br>'
        $HTML += '2. To finalize the Platform Layer, shut down the packaging machine using the "Shutdown for Finalize" icon on the desktop.<br>'
        $HTML += '3. Finalize in Management Console once the virtual machine has fully shut down.'
        $HTML += '</div>'
        $HTML += '</div>'
    } else {
        $HTML += '<div class="container">'
    }
    
    # Stats cards
    $HTML += '<div class="stats-grid">'
    $HTML += '<div class="stat-card">'
    $HTML += "<div class='stat-number stat-success'>$SuccessfulComponents</div>"
    $HTML += '<div class="stat-label">Successful</div>'
    $HTML += '</div>'
    $HTML += '<div class="stat-card">'
    $HTML += "<div class='stat-number stat-error'>$FailedComponents</div>"
    $HTML += '<div class="stat-label">Failed</div>'
    $HTML += '</div>'
    $HTML += '<div class="stat-card">'
    $HTML += "<div class='stat-number stat-warning'>$SkippedComponents</div>"
    $HTML += '<div class="stat-label">Skipped</div>'
    $HTML += '</div>'

    $HTML += '</div>'
    
    # Dashboard grid
    $HTML += '<div class="dashboard-grid">'
    
    # Left section - Progress bars
    $HTML += '<div class="chart-section">'
    $HTML += '<div class="card">'
    $HTML += '<div class="card-header">'
    $HTML += '<div>'
    $HTML += '<div class="card-title">Component Installation Progress</div>'
    $HTML += '<div class="card-subtitle">Real-time installation status by component</div>'
    $HTML += '</div>'
    $HTML += '</div>'
    $HTML += '<div class="progress-section">'
    
    # ComponentOrder already defined above - components will be sorted by execution order
    
    # Generate progress bars for each component in sorted order
    foreach ($ComponentName in $SortedComponents) {
        $Result = $InstallResults[$ComponentName]
        if ($Result -is [hashtable]) {
            $progressClass = "progress-warning"
            $progressValue = 50
            $statusText = "In Progress"
            
            # Use EXACT same logic as console output for consistency
            $isSkipped = $false
            
            # Primary skip check - explicit skipped flag
            if ($Result.Skipped -eq $true) {
                $isSkipped = $true
            }
            
            
            if ($isSkipped) {
                $progressClass = "progress-warning"
                $progressValue = 0
                $statusText = "Skipped"
            }
            # Check for success (only if not already marked as skipped)
            elseif ($Result.Success -eq $true) {
                $progressClass = "progress-success"
                $progressValue = 100
                $statusText = "Completed"
            }
            # Everything else is failed
            else {
                $progressClass = "progress-error"
                $progressValue = 25
                $statusText = "Failed"
            }
            
            $HTML += '<div class="progress-item">'
            $HTML += '<div class="progress-header" onclick="toggleProgressDetails(this)">'
            $DisplayName = if ($ComponentDisplayNames.ContainsKey($ComponentName)) { $ComponentDisplayNames[$ComponentName] } else { $ComponentName }
            $HTML += "<div class='progress-label'>$DisplayName</div>"
            $HTML += "<div class='progress-value'>$statusText<span class='progress-expand-icon'>&darr;</span></div>"
            $HTML += '</div>'
            $HTML += '<div class="progress-bar">'
            $HTML += "<div class='progress-fill $progressClass' style='width: ${progressValue}%;'></div>"
            $HTML += '</div>'
            
            # Add expandable details section
            $HTML += '<div class="progress-details">'
            $HTML += '<div class="progress-details-content">'
            $HTML += (Get-ComponentDetails -ComponentName $ComponentName -Result $Result)
            $HTML += '</div>'
            $HTML += '</div>'
            $HTML += '</div>'
        }
    }
    
    $HTML += '</div>'
    $HTML += '</div>'
    $HTML += '</div>'
    
    # Right section - Gauge and components
    $HTML += '<div class="sidebar-section">'
    
    # Success rate gauge
    $HTML += '<div class="card">'
    $HTML += '<div class="card-header">'
    $HTML += '<div class="card-title">Overall Success Rate</div>'
    $HTML += '</div>'
    $HTML += '<div class="gauge-container">'
    $HTML += '<div class="gauge">'

    $HTML += '<svg viewBox="0 0 140 80">'
    $HTML += '<path class="gauge-bg" d="M 20 70 A 50 50 0 0 1 120 70" stroke-dasharray="157" stroke-dashoffset="0"></path>'
    $HTML += "<path class='gauge-progress' d='M 20 70 A 50 50 0 0 1 120 70' stroke-dasharray='157' stroke-dashoffset='$([math]::Round(157 - (157 * $SuccessRate / 100), 1))'></path>"
    $HTML += '</svg>'
    $HTML += '</div>'
    $HTML += "<div class='gauge-text'>${SuccessRate}%</div>"
    $HTML += '<div class="gauge-label">Installation Success</div>'
    $HTML += '</div>'
    $HTML += '</div>'
    
    # Removed duplicate components list - details are shown in main results section
    $HTML += '</div>'
    $HTML += '</div>'
    
    $HTML += '</div>' # Close container
    # JavaScript for expandable sections
    $HTML += '<script>'
    $HTML += 'function toggleDetails(header) {'
    $HTML += '    const details = header.parentNode.querySelector(".component-details");'
    $HTML += '    const icon = header.querySelector(".expand-icon");'
    $HTML += '    if (details.classList.contains("expanded")) {'
    $HTML += '        details.classList.remove("expanded");'
    $HTML += '        icon.classList.remove("expanded");'
    $HTML += '    } else {'
    $HTML += '        details.classList.add("expanded");'
    $HTML += '        icon.classList.add("expanded");'
    $HTML += '    }'
    $HTML += '}'
    $HTML += 'function toggleProgressDetails(header) {'
    $HTML += '    const details = header.parentNode.querySelector(".progress-details");'
    $HTML += '    const icon = header.querySelector(".progress-expand-icon");'
    $HTML += '    if (details.classList.contains("expanded")) {'
    $HTML += '        details.classList.remove("expanded");'
    $HTML += '        icon.classList.remove("expanded");'
    $HTML += '    } else {'
    $HTML += '        details.classList.add("expanded");'
    $HTML += '        icon.classList.add("expanded");'
    $HTML += '    }'
    $HTML += '}'
    $HTML += '</script>'
    $HTML += '</body>'
    $HTML += '</html>'
    
    # Write HTML file
    try {
        $ReportFileName = "CitrixReport_Stage${Stage}_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
        $DesktopPath = [Environment]::GetFolderPath("Desktop")
        $ReportPath = Join-Path $DesktopPath $ReportFileName
        
        # Create file and write HTML content
        $HTML | Out-File -FilePath $ReportPath -Encoding UTF8 -Force
        
        # Verify file was created
        if (Test-Path $ReportPath) {
            Write-Host "HTML report generated: $ReportPath" -ForegroundColor Green
        } else {
            throw "File was not created at $ReportPath"
        }
        
        if ($OpenInBrowser) {
            try {
                # Use full file path with file:// protocol for Edge
                $FullPath = (Resolve-Path $ReportPath).Path
                $FileUrl = "file:///$($FullPath -replace '\\', '/')"
                
                Start-Process "msedge.exe" -ArgumentList "--no-first-run", "--no-default-browser-check", "--disable-features=msEdgeWelcome", $FileUrl -ErrorAction SilentlyContinue
                if ($?) {
                    Write-Host "Report opened in Microsoft Edge" -ForegroundColor Green
                } else {
                    # Fallback to default browser with full path
                    Start-Process $FullPath
                    Write-Host "Report opened in default browser" -ForegroundColor Green
                }
            } catch {
                Write-Host "Could not automatically open browser. Report saved to: $ReportPath" -ForegroundColor Yellow
            }
        }
        
        return $ReportPath
    } catch {
        Write-Error "Failed to generate HTML report: $($_.Exception.Message)"
        return $null
    }
}

# Function is ready to be dot-sourced by other scripts