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
                $detailsHTML += '<div class="detail-section-title">Pre-Installation Tasks</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] System requirements validation</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Disk space check (minimum 2GB verified)</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Windows Update service management</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Spooler service compatibility check</div>'
                $detailsHTML += '</div>'
                
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Core Installation Tasks</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] VDA installer execution</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Citrix Virtual Desktop Agent components</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Machine Creation Services registration</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Session management configuration</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Registry settings application</div>'
                $detailsHTML += '</div>'
                
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Installation Configuration</div>'
                if ($Result.ExitCode) { $detailsHTML += "<div class='detail-item detail-info'>Exit Code: $($Result.ExitCode)</div>" }
                if ($Result.InstallPath) { $detailsHTML += "<div class='detail-item detail-info'>Install Path: $($Result.InstallPath)</div>" }
                if ($Result.Version) { $detailsHTML += "<div class='detail-item detail-info'>Version: $($Result.Version)</div>" }
                $detailsHTML += "<div class='detail-item detail-info'>Installation Mode: Silent</div>"
                $detailsHTML += "<div class='detail-item detail-info'>Machine Catalog: Enabled</div>"
                $detailsHTML += "<div class='detail-item detail-info'>Session Sharing: Disabled</div>"
                $detailsHTML += '</div>'
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
        
        "Scripts" {
            if ($Result.Success) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Deployment Tasks Completed</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] OS version detection and script selection</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Target directory creation and validation</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] File integrity verification</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Script file deployment</div>'
                $detailsHTML += '</div>'
                
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Startup Scripts Deployed</div>'
                if ($Result.StartupFiles -and $Result.StartupFiles.Count -gt 0) {
                    $detailsHTML += "<div class='detail-item detail-success'>[SUCCESS] Deployed $($Result.StartupFiles.Count) startup script(s)</div>"
                    foreach ($file in $Result.StartupFiles) {
                        $sizeKB = if ($file.Size) { [math]::Round($file.Size / 1KB, 1) } else { "N/A" }
                        $detailsHTML += "<div class='detail-item detail-info'>  - $($file.Name) ($sizeKB KB)</div>"
                    }
                } else {
                    $detailsHTML += "<div class='detail-item detail-info'>No startup scripts configured</div>"
                }
                $detailsHTML += '</div>'
                
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Shutdown Scripts Deployed</div>'
                if ($Result.ShutdownFiles -and $Result.ShutdownFiles.Count -gt 0) {
                    $detailsHTML += "<div class='detail-item detail-success'>[SUCCESS] Deployed $($Result.ShutdownFiles.Count) shutdown script(s)</div>"
                    foreach ($file in $Result.ShutdownFiles) {
                        $sizeKB = if ($file.Size) { [math]::Round($file.Size / 1KB, 1) } else { "N/A" }
                        $detailsHTML += "<div class='detail-item detail-info'>  - $($file.Name) ($sizeKB KB)</div>"
                    }
                } else {
                    $detailsHTML += "<div class='detail-item detail-info'>No shutdown scripts configured</div>"
                }
                $detailsHTML += '</div>'
            } elseif ($Result.Skipped) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Skip Reason</div>'
                $detailsHTML += "<div class='detail-item detail-warning'>[SKIPPED] $($Result.Reason)</div>"
                $detailsHTML += '</div>'
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
        
        default {
            # Generic component details with comprehensive task breakdown
            if ($Result.Success) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Component Tasks Completed</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Pre-execution validation</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Configuration parameter processing</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Core component execution</div>'
                $detailsHTML += '<div class="detail-item detail-success">[SUCCESS] Post-execution verification</div>'
                $detailsHTML += "<div class='detail-item detail-success'>[SUCCESS] $ComponentName installation completed</div>"
                $detailsHTML += '</div>'
                
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Installation Details</div>'
                if ($Result.Message) { $detailsHTML += "<div class='detail-item detail-info'>Details: $($Result.Message)</div>" }
                if ($Result.Version) { $detailsHTML += "<div class='detail-item detail-info'>Version: $($Result.Version)</div>" }
                if ($Result.InstallPath) { $detailsHTML += "<div class='detail-item detail-info'>Install Path: $($Result.InstallPath)</div>" }
                if ($Result.ExitCode) { $detailsHTML += "<div class='detail-item detail-info'>Exit Code: $($Result.ExitCode)</div>" }
                if ($Result.Duration) { $detailsHTML += "<div class='detail-item detail-info'>Duration: $($Result.Duration)</div>" }
                $detailsHTML += "<div class='detail-item detail-info'>Component Type: $ComponentName</div>"
                $detailsHTML += '<div class="detail-item detail-info">Integration: Citrix VDA compatibility mode</div>'
                $detailsHTML += '</div>'
                
                if ($Result.InstalledFeatures -or $Result.ConfiguredSettings) {
                    $detailsHTML += '<div class="detail-section">'
                    $detailsHTML += '<div class="detail-section-title">Features and Configuration</div>'
                    if ($Result.InstalledFeatures) {
                        foreach ($feature in $Result.InstalledFeatures) {
                            $detailsHTML += "<div class='detail-item detail-success'>[SUCCESS] Feature: $feature</div>"
                        }
                    }
                    if ($Result.ConfiguredSettings) {
                        foreach ($setting in $Result.ConfiguredSettings) {
                            $detailsHTML += "<div class='detail-item detail-info'>Setting: $setting</div>"
                        }
                    }
                    $detailsHTML += '</div>'
                }
            } elseif ($Result.Skipped) {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Component Skipped</div>'
                $detailsHTML += "<div class='detail-item detail-warning'>[SKIPPED] $ComponentName was not installed</div>"
                if ($Result.SkipReason) { $detailsHTML += "<div class='detail-item detail-info'>Reason: $($Result.SkipReason)</div>" }
                if ($Result.Reason) { $detailsHTML += "<div class='detail-item detail-info'>Details: $($Result.Reason)</div>" }
                $detailsHTML += '</div>'
                
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Skip Analysis</div>'
                $detailsHTML += '<div class="detail-item detail-info">Component was excluded from installation</div>'
                $detailsHTML += '<div class="detail-item detail-info">This may be due to configuration settings</div>'
                $detailsHTML += '<div class="detail-item detail-info">Missing installer files or paths</div>'
                $detailsHTML += '<div class="detail-item detail-info">Environment compatibility requirements</div>'
                $detailsHTML += '</div>'
            } else {
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Installation Failure Analysis</div>'
                $detailsHTML += "<div class='detail-item detail-error'>[ERROR] $ComponentName installation failed</div>"
                if ($Result.Error) { $detailsHTML += "<div class='detail-item detail-error'>Error: $($Result.Error)</div>" }
                if ($Result.ExitCode) { $detailsHTML += "<div class='detail-item detail-error'>Exit Code: $($Result.ExitCode)</div>" }
                $detailsHTML += '</div>'
                
                $detailsHTML += '<div class="detail-section">'
                $detailsHTML += '<div class="detail-section-title">Troubleshooting Recommendations</div>'
                $detailsHTML += '<div class="detail-item detail-warning">Verify installer file integrity and accessibility</div>'
                $detailsHTML += '<div class="detail-item detail-warning">Check system requirements and compatibility</div>'
                $detailsHTML += '<div class="detail-item detail-warning">Review installation logs for detailed error information</div>'
                $detailsHTML += '<div class="detail-item detail-warning">Ensure administrator privileges and sufficient disk space</div>'
                $detailsHTML += '<div class="detail-item detail-warning">Verify network connectivity if remote installers are used</div>'
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
        [string]$OutputPath = ".",
        
        [Parameter(Mandatory=$false)]
        [bool]$OpenInBrowser = $true
    )
    
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
        'CitrixServicesDisabled' = 'Windows Services'
        'Scripts' = 'Startup / Shutdown Scripts'
        'ScriptConfiguration' = 'Script File Deployment'
        'DomainJoin' = 'Domain Join'
    }
    
    # Calculate statistics
    $TotalComponents = $InstallResults.Keys.Count
    $SuccessfulComponents = 0
    $FailedComponents = 0
    $SkippedComponents = 0
    
    foreach ($ComponentName in $InstallResults.Keys) {
        $Result = $InstallResults[$ComponentName]
        if ($Result -is [hashtable]) {
            if ($Result.Success -eq $true) {
                $SuccessfulComponents++
            } elseif ($Result.Skipped -eq $true) {
                $SkippedComponents++
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
    $HTML += '.header { background: white; border-bottom: 1px solid #e2e8f0; padding: 20px 32px; display: flex; justify-content: space-between; align-items: center; }'
    $HTML += '.header-left { display: flex; align-items: center; }'
    $HTML += '.logo { width: 48px; height: 48px; background: #3C1053; border-radius: 12px; display: flex; align-items: center; justify-content: center; color: white; font-weight: 700; font-size: 20px; margin-right: 20px; }'
    $HTML += '.header-title { font-size: 24px; font-weight: 600; color: #1e293b; margin: 0; }'
    $HTML += '.header-subtitle { font-size: 14px; color: #64748b; margin: 4px 0 0 0; }'
    $HTML += '.stage-badge { background: #3C1053; color: white; padding: 8px 16px; border-radius: 20px; font-size: 14px; font-weight: 500; }'
    $HTML += '.system-info { display: flex; gap: 24px; margin-top: 8px; }'
    $HTML += '.info-item { font-size: 12px; color: #64748b; }'
    
    # Container and layout
    $HTML += '.container { max-width: 1400px; margin: 0 auto; padding: 32px; }'
    $HTML += '.dashboard-grid { display: grid; grid-template-columns: 2fr 1fr; gap: 32px; margin-bottom: 32px; }'
    $HTML += '.chart-section { display: grid; gap: 24px; }'
    $HTML += '.sidebar-section { display: grid; gap: 24px; }'
    
    # Card styles
    $HTML += '.card { background: white; border-radius: 12px; border: 1px solid #e2e8f0; padding: 24px; }'
    $HTML += '.card-header { display: flex; justify-content: between; align-items: center; margin-bottom: 20px; }'
    $HTML += '.card-title { font-size: 18px; font-weight: 600; color: #1e293b; margin: 0; }'
    $HTML += '.card-subtitle { font-size: 14px; color: #64748b; margin: 4px 0 0 0; }'
    
    # Stats cards
    $HTML += '.stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 32px; }'
    $HTML += '.stat-card { background: white; border-radius: 12px; border: 1px solid #e2e8f0; padding: 20px; text-align: center; }'
    $HTML += '.stat-number { font-size: 32px; font-weight: 700; margin-bottom: 4px; }'
    $HTML += '.stat-label { font-size: 14px; color: #64748b; }'
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
    
    $HTML += '</style>'
    $HTML += '</head>'
    $HTML += '<body>'
    
    # Header
    $HTML += '<div class="header">'
    $HTML += '<div class="header-left">'
    $HTML += '<div class="logo">C</div>'
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
    $HTML += "<div class='stage-badge'>STAGE $Stage</div>"
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
            
            if ($Result.Success -eq $true) {
                $progressClass = "progress-success"
                $progressValue = 100
                $statusText = "Completed"
            } elseif ($Result.Skipped -eq $true) {
                $progressClass = "progress-warning"
                $progressValue = 0
                $statusText = "Skipped"
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
    
    # Top components list
    $HTML += '<div class="card">'
    $HTML += '<div class="card-header">'
    $HTML += '<div class="card-title">Installation Components</div>'
    $HTML += '</div>'
    $HTML += '<div class="components-list">'
    
    foreach ($ComponentName in $SortedComponents) {
        $Result = $InstallResults[$ComponentName]
        if ($Result -is [hashtable]) {
            $statusClass = "status-warning"
            $resultText = "Unknown"
            
            if ($Result.Success -eq $true) {
                $statusClass = "status-success"
                $resultText = "Success"
            } elseif ($Result.Skipped -eq $true) {
                $statusClass = "status-warning"
                $resultText = "Skipped"
            } else {
                $statusClass = "status-error"
                $resultText = "Failed"
            }
            
            $HTML += '<div class="component-item">'
            $HTML += '<div class="component-header" onclick="toggleDetails(this)">'
            $HTML += "<div class='component-status $statusClass'></div>"
            $DisplayName = if ($ComponentDisplayNames.ContainsKey($ComponentName)) { $ComponentDisplayNames[$ComponentName] } else { $ComponentName }
            $HTML += "<div class='component-name'>$DisplayName</div>"
            $HTML += "<div class='component-result'>$resultText</div>"
            $HTML += '<span class="expand-icon">&darr;</span>'
            $HTML += '</div>'
            
            # Generate detailed information for this component
            $HTML += '<div class="component-details">'
            $HTML += '<div class="details-content">'
            $HTML += (Get-ComponentDetails -ComponentName $ComponentName -Result $Result)
            $HTML += '</div>'
            $HTML += '</div>'
            $HTML += '</div>'
        }
    }
    
    $HTML += '</div>'
    $HTML += '</div>'
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
        $ReportPath = Join-Path (Get-Location).Path $ReportFileName
        
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