# Start-WEMGPOComparison.ps1
# Script to launch the HTML UI and connect it to the PowerShell backend

# Import the WEM GPO comparison module
Import-Module -Name "$PSScriptRoot\Export-CompareWEMGPO.ps1" -Force

# Create a simple HTTP server to serve the HTML UI
function Start-UIServer {
    param (
        [Parameter(Mandatory=$false)]
        [int]$Port = 8080
    )
    
    $Listener = New-Object System.Net.HttpListener
    $Listener.Prefixes.Add("http://localhost:$Port/")
    $Listener.Start()
    
    Write-Host "UI server started at http://localhost:$Port/"
    Write-Host "Press Ctrl+C to stop the server."
    
    # Launch browser
    Start-Process "http://localhost:$Port/"
    
    try {
        while ($Listener.IsListening) {
            $Context = $Listener.GetContext()
            $Request = $Context.Request
            $Response = $Context.Response
            
            # Read the HTML file
            $HTMLPath = "$PSScriptRoot\WEM-GPO-Compare.html"
            $HTMLContent = Get-Content -Path $HTMLPath -Raw
            
            $Buffer = [System.Text.Encoding]::UTF8.GetBytes($HTMLContent)
            $Response.ContentLength64 = $Buffer.Length
            $Response.OutputStream.Write($Buffer, 0, $Buffer.Length)
            $Response.OutputStream.Close()
        }
    }
    finally {
        $Listener.Stop()
    }
}

# Function to handle API endpoints for PowerShell calls
function Start-APIServer {
    param (
        [Parameter(Mandatory=$false)]
        [int]$Port = 8081
    )
    
    $Listener = New-Object System.Net.HttpListener
    $Listener.Prefixes.Add("http://localhost:$Port/")
    $Listener.Start()
    
    Write-Host "API server started at http://localhost:$Port/"
    
    try {
        while ($Listener.IsListening) {
            $Context = $Listener.GetContext()
            $Request = $Context.Request
            $Response = $Context.Response
            
            # Handle different API endpoints
            switch ($Request.Url.LocalPath) {
                "/api/get-policy-templates" {
                    # Get parameters from query string
                    $WEMInfraServer = $Request.QueryString["wemInfraServer"]
                    
                    # Call the function to get policy templates
                    $Policies = Get-WEMPolicyTemplates -WEMInfraServer $WEMInfraServer
                    
                    # Return result as JSON
                    $ResultJson = @{
                        "success" = ($Policies -ne $null)
                        "policies" = $Policies
                        "error" = if ($Policies -eq $null) { $Error[0].ToString() } else { $null }
                    } | ConvertTo-Json -Depth 5
                    
                    $Buffer = [System.Text.Encoding]::UTF8.GetBytes($ResultJson)
                    $Response.ContentType = "application/json"
                    $Response.ContentLength64 = $Buffer.Length
                    $Response.OutputStream.Write($Buffer, 0, $Buffer.Length)
                }
                
                "/api/export-wem" {
                    # Get parameters from query string
                    $WEMInfraServer = $Request.QueryString["wemInfraServer"]
                    $PolicyTemplateId = $Request.QueryString["policyTemplateId"]
                    $OutputPath = $Request.QueryString["outputPath"]
                    
                    # Call the export function
                    $Result = Export-WEMPolicyToXML -WEMInfraServer $WEMInfraServer -PolicyTemplateId $PolicyTemplateId -OutputPath $OutputPath
                    
                    # Return result as JSON
                    $ResultJson = @{
                        "success" = ($Result -ne $null)
                        "path" = $Result
                        "error" = if ($Result -eq $null) { $Error[0].ToString() } else { $null }
                    } | ConvertTo-Json
                    
                    $Buffer = [System.Text.Encoding]::UTF8.GetBytes($ResultJson)
                    $Response.ContentType = "application/json"
                    $Response.ContentLength64 = $Buffer.Length
                    $Response.OutputStream.Write($Buffer, 0, $Buffer.Length)
                }
                
                "/api/compare" {
                    # Get parameters from query string
                    $WEMXmlPath = $Request.QueryString["wemXmlPath"]
                    $GPOXmlPath = $Request.QueryString["gpoXmlPath"]
                    $OutputXmlPath = $Request.QueryString["outputXmlPath"]
                    
                    # Call the compare function
                    $Result = Compare-WEMWithGPO -WEMXmlPath $WEMXmlPath -GPOXmlPath $GPOXmlPath -OutputXmlPath $OutputXmlPath
                    
                    # Return result as JSON
                    $ResultJson = @{
                        "success" = ($Result -ne $null)
                        "result" = $Result
                        "path" = $OutputXmlPath
                        "error" = if ($Result -eq $null) { $Error[0].ToString() } else { $null }
                    } | ConvertTo-Json -Depth 10
                    
                    $Buffer = [System.Text.Encoding]::UTF8.GetBytes($ResultJson)
                    $Response.ContentType = "application/json"
                    $Response.ContentLength64 = $Buffer.Length
                    $Response.OutputStream.Write($Buffer, 0, $Buffer.Length)
                }
                
                default {
                    # Return 404 for unknown endpoints
                    $Response.StatusCode = 404
                    $Buffer = [System.Text.Encoding]::UTF8.GetBytes("Not Found")
                    $Response.ContentLength64 = $Buffer.Length
                    $Response.OutputStream.Write($Buffer, 0, $Buffer.Length)
                }
            }
            
            $Response.OutputStream.Close()
        }
    }
    finally {
        $Listener.Stop()
    }
}

# Start both servers
$UIServerJob = Start-Job -ScriptBlock ${function:Start-UIServer} -ArgumentList 8080
$APIServerJob = Start-Job -ScriptBlock ${function:Start-APIServer} -ArgumentList 8081

try {
    # Wait for jobs to complete (they should run indefinitely until Ctrl+C)
    Wait-Job -Job $UIServerJob, $APIServerJob
}
catch {
    Write-Error "Error in server jobs: $_"
}
finally {
    # Clean up jobs when script is terminated
    Stop-Job -Job $UIServerJob, $APIServerJob
    Remove-Job -Job $UIServerJob, $APIServerJob
}
