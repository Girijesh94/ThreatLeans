param([switch]$Build)
$ErrorActionPreference = 'Stop'
$projectPath = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location -LiteralPath $projectPath
$pythonPath = Join-Path $projectPath '.venv/Scripts/python.exe'
if (-not (Test-Path -LiteralPath $pythonPath)) {
    throw 'Create the virtual environment and install backend dependencies as described in README.md.'
}
if ($Build -or -not (Test-Path -LiteralPath (Join-Path $projectPath 'frontend/dist/index.html'))) {
    Push-Location -LiteralPath (Join-Path $projectPath 'frontend')
    try { npm ci; if ($LASTEXITCODE -ne 0) { throw 'Frontend installation failed' }; npm run build; if ($LASTEXITCODE -ne 0) { throw 'Frontend build failed' } }
    finally { Pop-Location }
}
& $pythonPath -m threatleans.cli serve
