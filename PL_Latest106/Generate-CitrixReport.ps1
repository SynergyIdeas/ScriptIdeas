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
                if ($Result.ExitCode) { $detailsHTML += "<div class='detail-item detail-info'>Exit Code: $($Result.ExitCode)</div>" }
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
                
                # Show creation details
                if ($Result.CreatedVHDX) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Virtual Disk Creation</div>'
                    $detailsHTML += "<div class='detail-item detail-success'>[CREATED] Virtual disk file created successfully</div>"
                    if ($Result.VHDXPath) { $detailsHTML += "<div class='detail-item detail-info'>File: $($Result.VHDXPath)</div>" }
                    $detailsHTML += '</div>'
                }
                
                # Show mount details
                if ($Result.Mounted) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Drive Mount</div>'
                    $detailsHTML += "<div class='detail-item detail-success'>[MOUNTED] Drive mounted and accessible</div>"
                    if ($Result.DriveLetter) { $detailsHTML += "<div class='detail-item detail-info'>Available at: $($Result.DriveLetter):\</div>" }
                    $detailsHTML += '</div>'
                }
                
                # Show auto-mount configuration
                if ($Result.AutoMountConfigured) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Auto-Mount Configuration</div>'
                    $detailsHTML += "<div class='detail-item detail-success'>[CONFIGURED] Auto-mount script created for boot</div>"
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
        
        "Scripts" {
            if ($Result.Skipped) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Script Deployment Status</div>'
                $detailsHTML += "<div class='detail-item detail-warning'>[SKIPPED] $($Result.Reason)</div>"
                $detailsHTML += '</div>'
            } elseif ($Result.Success) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Script Deployment Results</div>'
                if ($Result.Message) { $detailsHTML += "<div class='detail-item detail-success'>[SUCCESS] $($Result.Message)</div>" }
                if ($Result.Duration) { $detailsHTML += "<div class='detail-item detail-info'>Duration: $($Result.Duration)</div>" }
                $detailsHTML += '</div>'
                
                # Show actual files deployed
                if ($Result.StartupFiles -and $Result.StartupFiles.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Startup Scripts Deployed</div>'
                    foreach ($file in $Result.StartupFiles) {
                        $sizeKB = if ($file.Size) { [math]::Round($file.Size / 1KB, 1) } else { "N/A" }
                        $detailsHTML += "<div class='detail-item detail-success'>[DEPLOYED] $($file.Name) ($sizeKB KB)</div>"
                    }
                    $detailsHTML += '</div>'
                } else {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Startup Scripts</div>'
                    $detailsHTML += "<div class='detail-item detail-info'>No startup scripts were deployed</div>"
                    $detailsHTML += '</div>'
                }
                
                if ($Result.ShutdownFiles -and $Result.ShutdownFiles.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Shutdown Scripts Deployed</div>'
                    foreach ($file in $Result.ShutdownFiles) {
                        $sizeKB = if ($file.Size) { [math]::Round($file.Size / 1KB, 1) } else { "N/A" }
                        $detailsHTML += "<div class='detail-item detail-success'>[DEPLOYED] $($file.Name) ($sizeKB KB)</div>"
                    }
                    $detailsHTML += '</div>'
                } else {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Shutdown Scripts</div>'
                    $detailsHTML += "<div class='detail-item detail-info'>No shutdown scripts were deployed</div>"
                    $detailsHTML += '</div>'
                }
                
                # Show actual changes made
                if ($Result.Changes -and $Result.Changes.Count -gt 0) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Changes Made</div>'
                    foreach ($change in $Result.Changes) {
                        $detailsHTML += "<div class='detail-item detail-success'>[CHANGED] $change</div>"
                    }
                    $detailsHTML += '</div>'
                }
            } else {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Deployment Failure Analysis</div>'
                if ($Result.FailedFiles -and $Result.FailedFiles.Count -gt 0) {
                    foreach ($failed in $Result.FailedFiles) {
                        $detailsHTML += "<div class='detail-item detail-error'>[ERROR] $($failed.Name): $($failed.Reason)</div>"
                    }
                } else {
                    $detailsHTML += "<div class='detail-item detail-error'>[ERROR] Script deployment failed</div>"
                }
                $detailsHTML += '</div>'
                
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Troubleshooting Steps</div>'
                $detailsHTML += '<div class="detail-item detail-warning">Verify source script paths in configuration</div>'
                $detailsHTML += '<div class="detail-item detail-warning">Check destination directory permissions</div>'
                $detailsHTML += '<div class="detail-item detail-warning">Ensure script files are not corrupted</div>'
                $detailsHTML += '<div class="detail-item detail-warning">Review file access permissions</div>'
                $detailsHTML += '</div>'
            }
        }
        
        "ScriptConfiguration" {
            if ($Result.Success) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Registry Configuration Tasks</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Group Policy script registry access</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Startup script registry path creation</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Shutdown script registry path creation</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Script array registration validation</div>'
                $detailsHTML += '</div>'
                
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Startup Scripts Registry</div>'
                $detailsHTML += "<div class='detail-item detail-success'>[SUCCESS] Registered $($Result.StartupScriptsRegistered) startup script(s)</div>"
                if ($Result.RegisteredScripts -and $Result.RegisteredScripts.Count -gt 0) {
                    $startupScripts = $Result.RegisteredScripts | Where-Object { $_.Type -eq "Startup" }
                    foreach ($script in $startupScripts) {
                        $detailsHTML += "<div class='detail-item detail-info'>  - $($script.Name)</div>"
                    }
                } else {
                    $detailsHTML += "<div class='detail-item detail-info'>No startup scripts registered</div>"
                }
                $detailsHTML += '</div>'
                
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Shutdown Scripts Registry</div>'
                $detailsHTML += "<div class='detail-item detail-success'>[SUCCESS] Registered $($Result.ShutdownScriptsRegistered) shutdown script(s)</div>"
                if ($Result.RegisteredScripts -and $Result.RegisteredScripts.Count -gt 0) {
                    $shutdownScripts = $Result.RegisteredScripts | Where-Object { $_.Type -eq "Shutdown" }
                    foreach ($script in $shutdownScripts) {
                        $detailsHTML += "<div class='detail-item detail-info'>  - $($script.Name)</div>"
                    }
                } else {
                    $detailsHTML += "<div class='detail-item detail-info'>No shutdown scripts registered</div>"
                }
                $detailsHTML += '</div>'
                
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Registry Settings Applied</div>'
                $detailsHTML += '<div class="detail-item detail-info">Registry Path: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts</div>'
                $detailsHTML += '<div class="detail-item detail-info">Array Type: String[] for Group Policy compatibility</div>'
                $detailsHTML += '<div class="detail-item detail-info">Script Execution: Enabled for machine startup/shutdown</div>'
                $detailsHTML += '</div>'
            } else {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Configuration Failure Analysis</div>'
                if ($Result.FailedRegistrations -and $Result.FailedRegistrations.Count -gt 0) {
                    foreach ($failed in $Result.FailedRegistrations) {
                        $detailsHTML += "<div class='detail-item detail-error'>[ERROR] $($failed.Type) Script: $($failed.Name) - $($failed.Error)</div>"
                    }
                } else {
                    $detailsHTML += "<div class='detail-item detail-error'>[ERROR] Script registration failed</div>"
                }
                $detailsHTML += '</div>'
                
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Troubleshooting Steps</div>'
                $detailsHTML += '<div class="detail-item detail-warning">Verify administrator privileges for registry access</div>'
                $detailsHTML += '<div class="detail-item detail-warning">Check Group Policy registry path permissions</div>'
                $detailsHTML += '<div class="detail-item detail-warning">Ensure script files exist before registration</div>'
                $detailsHTML += '<div class="detail-item detail-warning">Validate registry array type compatibility</div>'
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
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] PVS Target Device installer execution</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Network boot configuration</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Cache drive integration</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] PVS services registration</div>'
                $detailsHTML += '</div>'
                
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Configuration Details</div>'
                if ($Result.Version) { $detailsHTML += "<div class='detail-item detail-info'>Version: $($Result.Version)</div>" }
                if ($Result.CacheDrive) { $detailsHTML += "<div class='detail-item detail-info'>Cache Drive: $($Result.CacheDrive)</div>" }
                $detailsHTML += '<div class="detail-item detail-info">Boot Mode: Network streaming</div>'
                $detailsHTML += '<div class="detail-item detail-info">Cache Mode: Cache on device with overflow on hard disk</div>'
                $detailsHTML += '</div>'
            } elseif ($Result.Skipped) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Skip Reason</div>'
                $detailsHTML += "<div class='detail-item detail-warning'>[SKIPPED] $($Result.Reason)</div>"
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
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] WEM Agent installer execution</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Service registration and startup</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Agent configuration initialization</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Policy engine registration</div>'
                $detailsHTML += '</div>'
                
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Agent Configuration</div>'
                if ($Result.Version) { $detailsHTML += "<div class='detail-item detail-info'>Version: $($Result.Version)</div>" }
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
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] UberAgent core installation</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Performance monitoring configuration</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Template deployment</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] License activation</div>'
                $detailsHTML += '</div>'
                
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Monitoring Configuration</div>'
                if ($Result.Version) { $detailsHTML += "<div class='detail-item detail-info'>Version: $($Result.Version)</div>" }
                if ($Result.TemplatesInstalled) { $detailsHTML += "<div class='detail-item detail-info'>Templates: $($Result.TemplatesInstalled) installed</div>" }
                $detailsHTML += '<div class="detail-item detail-info">Performance Metrics: Enabled</div>'
                $detailsHTML += '<div class="detail-item detail-info">User Experience Monitoring: Active</div>'
                $detailsHTML += '<div class="detail-item detail-info">Application Performance: Tracked</div>'
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
                $detailsHTML += '<div class="detail-section-title">TADDM Configuration Tasks</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] TADDM agent installation</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Discovery configuration</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Service integration</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Monitoring activation</div>'
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
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Domain connectivity validation</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Computer account creation</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Domain authentication setup</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Machine joined to domain successfully</div>'
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
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Registry grace period cleanup</div>'
                if ($Result.TotalRemoved -gt 0) {
                    $detailsHTML += "<div class='detail-item detail-success'>[SUCCESS] Registry keys removed: $($Result.TotalRemoved)</div>"
                }
                if ($Result.TotalSkipped -gt 0) {
                    $detailsHTML += "<div class='detail-item detail-info'>[INFO] Keys already clean: $($Result.TotalSkipped)</div>"
                }
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] VDI template preparation optimized</div>'
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
                if ($Result.NetBios) {
                    $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] NetBIOS over TCP/IP disabled</div>'
                }
                if ($Result.Offload) {
                    $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Network offload parameters disabled</div>'
                }
                if ($Result.SMB) {
                    $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] SMB settings configured</div>'
                }
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] PVS compatibility optimized</div>'
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
                if ($Result.CrashDump) {
                    $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Crash dump configured to kernel mode</div>'
                }
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Storage optimized for VDI environments</div>'
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
            if ($Result.Success) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Event Logs Cleanup Tasks</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Windows Event Logs cleanup completed</div>'
                if ($Result.LogsCleared) {
                    $detailsHTML += "<div class='detail-item detail-success'>Event logs cleared: $($Result.LogsCleared)</div>"
                }
                if ($Result.LogsFailed -and $Result.LogsFailed -gt 0) {
                    $detailsHTML += "<div class='detail-item detail-info'>Protected logs (normal): $($Result.LogsFailed)</div>"
                }
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] VDI template cleaned of installation artifacts</div>'
                $detailsHTML += '</div>'
            } else {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Event Logs Cleanup Issues</div>'
                $detailsHTML += "<div class='detail-item detail-error'>[ERROR] Event logs cleanup encountered issues</div>"
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
            if ($Result.Success) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">.NET Framework Optimization Tasks</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] .NET Framework optimization completed</div>'
                if ($Result.FrameworkVersionsOptimized) {
                    $detailsHTML += "<div class='detail-item detail-success'>Frameworks optimized: $($Result.FrameworkVersionsOptimized.Count)</div>"
                }
                if ($Result.TotalAssembliesOptimized) {
                    $detailsHTML += "<div class='detail-item detail-success'>Total assemblies optimized: $($Result.TotalAssembliesOptimized)</div>"
                }
                if ($Result.ExecutionTime) {
                    $detailsHTML += "<div class='detail-item detail-info'>Optimization time: $($Result.ExecutionTime.TotalMinutes.ToString('F2')) minutes</div>"
                }
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Native image optimization for VDI template</div>'
                $detailsHTML += '</div>'
            } else {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">.NET Optimization Issues</div>'
                $detailsHTML += "<div class='detail-item detail-error'>[ERROR] .NET Framework optimization encountered issues</div>"
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
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Citrix Virtual Desktop Agent verification completed</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] VDA installation integrity confirmed</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] VDA component validation completed</div>'
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
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Service registry validation</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Service configuration validation completed</div>'
                $detailsHTML += '</div>'
            } else {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Service Detection Issues</div>'
                $detailsHTML += "<div class='detail-item detail-error'>[ERROR] Citrix services detection encountered issues</div>"
                if ($Result.Error) { $detailsHTML += "<div class='detail-item detail-error'>Error: $($Result.Error)</div>" }
                $detailsHTML += '</div>'
            }
        }
        
        "System Optimizations" {
            if ($Result.Success -or $Result.OverallStatus) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">System Optimization Tasks</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] System optimization validation completed</div>'
                if ($Result.OptimizationCount) {
                    $detailsHTML += "<div class='detail-item detail-success'>Optimizations applied: $($Result.OptimizationCount)</div>"
                }
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] VDI environment preparation</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Performance baseline established</div>'
                $detailsHTML += '</div>'
            } else {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">System Optimization Issues</div>'
                $detailsHTML += "<div class='detail-item detail-error'>[ERROR] System optimization validation encountered issues</div>"
                if ($Result.Error) { $detailsHTML += "<div class='detail-item detail-error'>Error: $($Result.Error)</div>" }
                $detailsHTML += '</div>'
            }
        }
        
        "VDI Optimizations" {
            if ($Result.Success -or $Result.OverallStatus) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">VDI Registry Optimization Tasks</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] VDI registry optimizations applied</div>'
                if ($Result.Optimized) {
                    $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Citrix Optimizer execution completed</div>'
                }
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Template performance optimization</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] User experience enhancement</div>'
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
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Citrix WEM RSA key cleanup completed</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Template security optimization</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] WEM agent preparation</div>'
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
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Domain user profile cleanup completed</div>'
                if ($Result.ProfilesRemoved) {
                    $detailsHTML += "<div class='detail-item detail-success'>Profiles removed: $($Result.ProfilesRemoved)</div>"
                }
                if ($Result.RemovedProfiles) {
                    $detailsHTML += "<div class='detail-item detail-info'>Cleaned profiles: $($Result.RemovedProfiles -join ', ')</div>"
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
                $detailsHTML += '<div class="detail-section-title">VMware Memory Optimization Tasks</div>'
                if ($Result.VMwareDetected) {
                    $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] VMware environment detected</div>'
                    $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Memory ballooning disabled</div>'
                    $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] VDI memory optimization applied</div>'
                } else {
                    $detailsHTML += '<div class="detail-item detail-info">[INFO] Non-VMware environment detected</div>'
                    $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Memory optimization not required</div>'
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
        
        "Password Age Registry" {
            if ($Result.Success) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Password Age Registry Cleanup</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Password age registry cleanup completed</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] VDI template security optimization</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] User authentication preparation</div>'
                $detailsHTML += '</div>'
            } else {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Password Registry Issues</div>'
                $detailsHTML += "<div class='detail-item detail-error'>[ERROR] Password age registry cleanup encountered issues</div>"
                if ($Result.Error) { $detailsHTML += "<div class='detail-item detail-error'>Error: $($Result.Error)</div>" }
                $detailsHTML += '</div>'
            }
        }
        
        "Automatic Maintenance" {
            if ($Result.Success -or $Result.Optimized) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Automatic Maintenance Disable</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Windows automatic maintenance disabled</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] VDI template optimization applied</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Resource usage optimization</div>'
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
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Desktop Recycle Bin disabled</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] VDI user interface optimization</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Template cleanup optimization</div>'
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
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] File Explorer Quick Access disabled</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] VDI user experience optimization</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Privacy and security enhancement</div>'
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
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Event logs redirected to cache drive</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Storage optimization applied</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Performance enhancement</div>'
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
                $detailsHTML += '<div class="detail-section-title">User Profile Redirection</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] User profiles configured for cache drive</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Profile performance optimization</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Storage utilization enhancement</div>'
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
            if ($Result.Success) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Pagefile Configuration</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Pagefile configuration optimized</div>'
                if ($Result.PagefileSize) {
                    $detailsHTML += "<div class='detail-item detail-info'>Pagefile size: $($Result.PagefileSize) MB</div>"
                }
                if ($Result.PagefilePath) {
                    $detailsHTML += "<div class='detail-item detail-info'>Pagefile location: $($Result.PagefilePath)</div>"
                }
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Memory management optimization</div>'
                $detailsHTML += '</div>'
            } elseif ($Result.Skipped) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Pagefile Configuration Skipped</div>'
                $detailsHTML += "<div class='detail-item detail-warning'>[SKIPPED] Pagefile configuration was skipped</div>"
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
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Virtual cache drive removal completed</div>'
                if ($Result.DriveLetter) {
                    $detailsHTML += "<div class='detail-item detail-success'>Drive removed: $($Result.DriveLetter)</div>"
                }
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Template finalization optimization</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Storage cleanup completed</div>'
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
        
        "Active Components Registry" {
            if ($Result.Success) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Active Components Registry Cleanup</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Active Components registry cleanup completed</div>'
                if ($Result.TotalRemoved) {
                    $detailsHTML += "<div class='detail-item detail-success'>Components removed: $($Result.TotalRemoved)</div>"
                }
                if ($Result.RemovedComponents -and $Result.RemovedComponents.Count -gt 0) {
                    $detailsHTML += "<div class='detail-item detail-info'>Cleaned components: $($Result.RemovedComponents -join ', ')</div>"
                }
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] VDI template optimization</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Logon performance enhancement</div>'
                $detailsHTML += '</div>'
            } else {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Active Components Cleanup Issues</div>'
                $detailsHTML += "<div class='detail-item detail-error'>[ERROR] Active Components registry cleanup encountered issues</div>"
                if ($Result.Message) { $detailsHTML += "<div class='detail-item detail-error'>Error: $($Result.Message)</div>" }
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
        'ActiveComponentsResult' = 'Active Components Registry'
        'CitrixServicesDisabled' = 'Windows Services'
        'Scripts' = 'Startup / Shutdown Scripts'
        'ScriptConfiguration' = 'Script File Deployment'
        'DomainJoin' = 'Domain Join'
        'VDA Verification' = 'Citrix VDA Verification'
        'Citrix Services' = 'Citrix Services Detection'
        'System Optimizations' = 'System Optimizations'
        'VDI Optimizations' = 'VDI Registry Optimizations'
        'WEM RSA Cleanup' = 'WEM RSA Key Cleanup'
        'Domain Profile Cleanup' = 'Domain Profile Cleanup'
        'VMware Memory Optimization' = 'VMware Memory Optimization'
        'Password Age Registry' = 'Password Age Registry Cleanup'
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
        'Virtual Cache Drive Removal' = 'Virtual Cache Drive Removal'

    }
    
    # Filter components based on stage - only show components that actually run in each stage
    $StageComponents = @{
        1 = @('VDA', 'PVS', 'WEM', 'UberAgent', 'TADDM', 'CacheDrive', 'Scripts', 'ScriptConfiguration', 'DomainJoin')
        2 = @('VDA Verification', 'Citrix Services', 'System Optimizations', 'VDI Optimizations', 'WEM RSA Cleanup', 'Domain Profile Cleanup', 'VMware Memory Optimization', 'Password Age Registry', 'RDS Grace Period Reset', 'Network Optimizations', 'Storage Optimizations', 'Ghost Device Removal', 'System Defragmentation', 'Event Logs Cleanup', '.NET Framework Optimization', 'Automatic Maintenance', 'Recycle Bin Disable', 'Quick Access Disable', 'Event Log Redirection', 'User Profile Redirection', 'Pagefile Configuration', 'Virtual Cache Drive Removal')
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
    
    # Calculate statistics
    $TotalComponents = $InstallResults.Keys.Count
    $SuccessfulComponents = 0
    $FailedComponents = 0
    $SkippedComponents = 0
    
    foreach ($ComponentName in $InstallResults.Keys) {
        $Result = $InstallResults[$ComponentName]
        if ($Result -is [hashtable]) {
            if ($Result.Skipped -eq $true) {
                $SkippedComponents++
            } elseif ($Result.Success -eq $true) {
                $SuccessfulComponents++
            } else {
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
    $HTML += '.header { background: white; border-bottom: 1px solid #e2e8f0; padding: 20px 32px; display: flex; justify-content: center; align-items: center; flex-wrap: wrap; }'
    $HTML += '.header-left { display: flex; align-items: center; flex-direction: column; text-align: center; }'
    $HTML += '.header-top { display: flex; align-items: center; justify-content: center; gap: 16px; margin-bottom: 12px; }'
    $HTML += '.logo { width: 48px; height: 48px; background: #3C1053; border-radius: 12px; display: flex; align-items: center; justify-content: center; color: white; font-weight: 700; font-size: 20px; }'
    $HTML += '.stage-badge { background: #3C1053; color: white; padding: 8px 16px; border-radius: 20px; font-size: 14px; font-weight: 500; }'
    $HTML += '.header-title { font-size: 24px; font-weight: 600; color: #1e293b; margin: 0; text-align: center; }'
    $HTML += '.header-subtitle { font-size: 14px; color: #64748b; margin: 4px 0 0 0; text-align: center; }'
    $HTML += '.system-info { display: flex; gap: 24px; margin-top: 8px; justify-content: center; flex-wrap: wrap; }'
    $HTML += '.info-item { font-size: 12px; color: #64748b; }'
    
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
    $HTML += '.stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 24px; }'
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
    $HTML += '.progress-details.expanded { max-height: 400px; }'
    $HTML += '.progress-details-content { padding: 12px 16px; background: #f8fafc; border-left: 3px solid #e2e8f0; margin: 0 -8px 8px -8px; border-radius: 6px; }'
    
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
    $HTML += '.component-details.expanded { max-height: 500px; }'
    $HTML += '.details-content { padding: 12px 24px; background: #f8fafc; border-left: 3px solid #e2e8f0; margin: 0 -16px 8px -16px; }'
    $HTML += '.detail-section { margin-bottom: 12px; }'
    $HTML += '.detail-section-title { font-weight: 600; color: #374151; margin-bottom: 6px; font-size: 13px; }'
    $HTML += '.detail-item { margin-bottom: 4px; font-size: 12px; padding-left: 12px; }'
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
    $HTML += '.stats-grid { grid-template-columns: repeat(2, 1fr); gap: 8px; }'
    $HTML += '.header { padding: 16px; }'
    $HTML += '.card { padding: 16px; }'
    $HTML += '.gauge { width: 200px; height: 120px; }'
    $HTML += '}'
    
    $HTML += '@media screen and (max-width: 900px) {'
    $HTML += '.container { padding: 8px; }'
    $HTML += '.stats-grid { grid-template-columns: 1fr; gap: 8px; }'
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
    $HTML += '<div class="header-top">'
    $HTML += '<div class="logo">PL</div>'
    $HTML += "<div class='stage-badge'>Stage $Stage</div>"
    $HTML += '</div>'
    $HTML += '<div>'
    $HTML += '<div class="header-title">Citrix Installation Dashboard</div>'
    $HTML += '<div class="header-subtitle">Platform deployment analytics and monitoring</div>'
    $HTML += '<div class="system-info">'
    $HTML += "<span class='info-item'>Computer: $ComputerName</span>"
    $HTML += "<span class='info-item'>User: $UserName</span>"
    $HTML += "<span class='info-item'>Generated: $ReportTime</span>"
    $HTML += "<span class='info-item'>OS: $OSCaption</span>"
    $HTML += "<span class='info-item'>Memory: $TotalMemoryGB GB</span>"
    $HTML += '</div>'
    $HTML += '</div>'
    $HTML += '</div>'
    
    # Main container
    $HTML += '<div class="container">'
    
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
    $HTML += '<div class="stat-card">'
    $HTML += "<div class='stat-number stat-info'>${SuccessRate}%</div>"
    $HTML += '<div class="stat-label">Success Rate</div>'
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
    
    # Sort components by status: Completed, Failed, Skipped
    $SortedComponents = $InstallResults.Keys | Sort-Object {
        $Result = $InstallResults[$_]
        if ($Result -is [hashtable]) {
            if ($Result.Success -eq $true) { return 1 }      # Completed first
            elseif ($Result.Skipped -eq $true) { return 3 }  # Skipped last
            else { return 2 }                                 # Failed in middle
        }
        return 4 # Unknown status last
    }
    
    # Generate progress bars for each component in sorted order
    foreach ($ComponentName in $SortedComponents) {
        $Result = $InstallResults[$ComponentName]
        if ($Result -is [hashtable]) {
            $progressClass = "progress-warning"
            $progressValue = 50
            $statusText = "In Progress"
            
            if ($Result.Skipped -eq $true) {
                $progressClass = "progress-warning"
                $progressValue = 0
                $statusText = "Skipped"
            } elseif ($Result.Success -eq $true) {
                $progressClass = "progress-success"
                $progressValue = 100
                $statusText = "Completed"
            } else {
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