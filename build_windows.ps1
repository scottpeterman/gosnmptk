Write-Host "Building Go SNMP Tool Kit..." -ForegroundColor Cyan

# Install/update Fyne tools
Write-Host "Updating Fyne tools..." -ForegroundColor Yellow
go install fyne.io/tools/cmd/fyne@latest

# Clean previous builds
if (Test-Path "cmd\snmptk\snmptk.exe") { Remove-Item "cmd\snmptk\snmptk.exe" -Force }
if (Test-Path "cmd\snmptk\snmptk") { Remove-Item "cmd\snmptk\snmptk" -Force }

# Create dist directory
if (!(Test-Path "dist")) { New-Item -ItemType Directory -Path "dist" }

# Build Windows version
Write-Host "`nBuilding Windows version..." -ForegroundColor Yellow
fyne package --target windows --src .\cmd\snmptk

if (Test-Path "cmd\snmptk\snmptk.exe") {
    Move-Item "cmd\snmptk\snmptk.exe" "dist\snmptk-windows.exe" -Force
    $size = (Get-Item "dist\snmptk-windows.exe").Length
    Write-Host "SUCCESS: Windows build ($([math]::Round($size/1MB, 2)) MB)" -ForegroundColor Green
} else {
    Write-Host "FAILED: Windows build" -ForegroundColor Red
}

# Show results
Write-Host "`nBuild Results:" -ForegroundColor Cyan
if (Test-Path "dist") {
    Get-ChildItem "dist" | ForEach-Object {
        $sizeMB = [math]::Round($_.Length / 1MB, 2)
        Write-Host "  $($_.Name) - $sizeMB MB" -ForegroundColor White
    }
} else {
    Write-Host "  No files created" -ForegroundColor Red
}

Write-Host "`nTest your Windows build:" -ForegroundColor Green
Write-Host "  .\dist\snmptk-windows.exe" -ForegroundColor Gray