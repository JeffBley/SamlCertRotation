param(
    [Parameter(Mandatory = $true)]
    [string]$FunctionAppName,

    [Parameter(Mandatory = $true)]
    [string]$ResourceGroup,

    [string]$RepoRoot = "$HOME/SamlCertRotation"
)

$ErrorActionPreference = 'Stop'

# Build and publish
Set-Location $RepoRoot
$publishDir = Join-Path $RepoRoot "publish"
$publishZip = Join-Path $RepoRoot "publish.zip"

Remove-Item -Recurse -Force $publishDir -ErrorAction SilentlyContinue
Remove-Item -Force $publishZip -ErrorAction SilentlyContinue

dotnet publish src/SamlCertRotation/SamlCertRotation.csproj `
    --configuration Release `
    --output $publishDir

# Create zip (Push-Location ensures hidden .azurefunctions/ directory is included)
Push-Location $publishDir
Get-ChildItem -Force | Compress-Archive -DestinationPath $publishZip -Force
Pop-Location

# Deploy via zip deploy
Write-Host "Deploying to $FunctionAppName..."
az functionapp deployment source config-zip `
    --resource-group $ResourceGroup `
    --name $FunctionAppName `
    --src $publishZip

# Wait for cold start on Consumption plan
Write-Host "Waiting for function host to initialize..."
Start-Sleep -Seconds 30

# List deployed functions
Write-Host "`nVerifying deployed functions..."
$functionList = az functionapp function list `
    --resource-group $ResourceGroup `
    --name $FunctionAppName `
    --query "[].name" -o tsv

if ($functionList) {
    $count = ($functionList -split "`n").Count
    Write-Host "Indexed functions: $count"
    $functionList -split "`n" | ForEach-Object { Write-Host "  $_" }
} else {
    Write-Host "az functionapp function list returned empty (this can happen on Consumption plans)."
    Write-Host "Falling back to route health check..."
}

# Route health check
$functionHost = az functionapp show `
    --resource-group $ResourceGroup `
    --name $FunctionAppName `
    --query defaultHostName -o tsv

$statusCode = $null
try {
    Invoke-WebRequest "https://$functionHost/api/dashboard/stats" -UseBasicParsing | Out-Null
    $statusCode = 200
}
catch {
    $statusCode = $_.Exception.Response.StatusCode.value__
}

Write-Host "Route health status code: $statusCode (401 = expected, 404 = unhealthy)"
if ($statusCode -eq 404) {
    throw "Route health check returned 404 after deployment."
}
