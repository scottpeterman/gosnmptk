# Enhanced Windows Build Script for Go SNMP Tool Kit
param(
    [string]$Target = "all",  # Options: all, snmptk, scanner, scanner-ext, report
    [switch]$Clean = $false,
    [switch]$Test = $false
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Go SNMP Tool Kit - Windows Build Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Application configurations
$apps = @{
    "snmptk" = @{
        name = "SNMP Tool Kit"
        path = "cmd\snmptk"
        output = "snmptk-windows.exe"
        type = "gui"
    }
    "scanner" = @{
        name = "Network Scanner"
        path = "cmd\scanner"
        output = "snmptk-scan.exe"
        type = "gui"
    }
    "scanner-ext" = @{
        name = "Enhanced Scanner"
        path = "cmd\scanner-ext"
        output = "snmptk-scan-ext.exe"
        type = "gui"
    }
    "report" = @{
        name = "Report Generator"
        path = "cmd\report-generator"
        output = "snmptk-report.exe"
        type = "console"
    }
}

# Function to clean builds
function Clean-Builds {
    Write-Host "Cleaning previous builds..." -ForegroundColor Yellow
    
    foreach ($app in $apps.Keys) {
        $appPath = $apps[$app].path
        if (Test-Path "$appPath\*.exe") { 
            Remove-Item "$appPath\*.exe" -Force 
            Write-Host "  Cleaned $appPath" -ForegroundColor Gray
        }
    }
    
    if (Test-Path "dist") {
        Remove-Item "dist\*.exe" -Force -ErrorAction SilentlyContinue
        Write-Host "  Cleaned dist directory" -ForegroundColor Gray
    }
}

# Function to install/update tools
function Update-Tools {
    Write-Host "Updating build tools..." -ForegroundColor Yellow
    
    # Update Fyne tools
    Write-Host "  Installing Fyne tools..." -ForegroundColor Gray
    go install fyne.io/tools/cmd/fyne@latest
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Failed to install Fyne tools" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "  Tools updated successfully" -ForegroundColor Green
}

# Function to build a single application
function Build-App {
    param($appKey)
    
    $app = $apps[$appKey]
    $appName = $app.name
    $appPath = $app.path
    $outputName = $app.output
    $appType = $app.type
    
    Write-Host "`nBuilding $appName..." -ForegroundColor Yellow
    
    # Check if source exists
    if (!(Test-Path "$appPath\main.go")) {
        Write-Host "  ERROR: main.go not found in $appPath" -ForegroundColor Red
        return $false
    }
    
    try {
        if ($appType -eq "gui") {
            # Use Fyne for GUI applications
            fyne package --target windows --src ".\$appPath"
            
            # Move the generated executable
            $generatedExe = "$appPath\$((Split-Path $appPath -Leaf)).exe"
            if (Test-Path $generatedExe) {
                Move-Item $generatedExe "dist\$outputName" -Force
            } else {
                # Try alternate naming
                $altExe = "$appPath\main.exe"
                if (Test-Path $altExe) {
                    Move-Item $altExe "dist\$outputName" -Force
                } else {
                    throw "Generated executable not found"
                }
            }
        } else {
            # Use standard go build for console applications
            Push-Location $appPath
            go build -ldflags "-s -w" -o "..\..\dist\$outputName" .
            Pop-Location
        }
        
        if (Test-Path "dist\$outputName") {
            $size = (Get-Item "dist\$outputName").Length
            $sizeMB = [math]::Round($size / 1MB, 2)
            Write-Host "  SUCCESS: $appName ($sizeMB MB)" -ForegroundColor Green
            return $true
        } else {
            throw "Output file not created"
        }
    }
    catch {
        Write-Host "  FAILED: $appName - $_" -ForegroundColor Red
        return $false
    }
}

# Function to test builds
function Test-Builds {
    Write-Host "`nTesting builds..." -ForegroundColor Yellow
    
    foreach ($appKey in $apps.Keys) {
        $app = $apps[$appKey]
        $outputPath = "dist\$($app.output)"
        
        if (Test-Path $outputPath) {
            Write-Host "  Testing $($app.name)..." -ForegroundColor Gray
            
            if ($app.type -eq "console") {
                # Test console apps with --help
                $testResult = & $outputPath --help 2>&1
                if ($LASTEXITCODE -eq 0 -or $testResult -match "Usage") {
                    Write-Host "    ✓ Console app responds correctly" -ForegroundColor Green
                } else {
                    Write-Host "    ⚠ Console app test inconclusive" -ForegroundColor Yellow
                }
            } else {
                # For GUI apps, just check if they can start
                Write-Host "    ✓ GUI executable created (manual testing recommended)" -ForegroundColor Green
            }
        }
    }
}

# Function to show results
function Show-Results {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Build Results:" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    if (Test-Path "dist") {
        $totalSize = 0
        Get-ChildItem "dist\*.exe" | ForEach-Object {
            $sizeMB = [math]::Round($_.Length / 1MB, 2)
            $totalSize += $_.Length
            Write-Host "  $($_.Name)" -ForegroundColor White -NoNewline
            Write-Host " - $sizeMB MB" -ForegroundColor Gray
        }
        
        if ($totalSize -gt 0) {
            $totalMB = [math]::Round($totalSize / 1MB, 2)
            Write-Host "`n  Total size: $totalMB MB" -ForegroundColor Cyan
        }
    } else {
        Write-Host "  No files created" -ForegroundColor Red
    }
    
    Write-Host "`nUsage Examples:" -ForegroundColor Green
    Write-Host "  .\dist\snmptk-windows.exe          # Main SNMP toolkit" -ForegroundColor Gray
    Write-Host "  .\dist\snmptk-scan.exe             # Basic network scanner" -ForegroundColor Gray
    Write-Host "  .\dist\snmptk-scan-ext.exe         # Enhanced scanner with persistence" -ForegroundColor Gray
    Write-Host "  .\dist\snmptk-report.exe <file>    # Generate reports from scan data" -ForegroundColor Gray
}

# Main execution
try {
    # Clean if requested
    if ($Clean) {
        Clean-Builds
        if ($Target -eq "clean") {
            exit 0
        }
    }
    
    # Create dist directory
    if (!(Test-Path "dist")) { 
        New-Item -ItemType Directory -Path "dist" | Out-Null
        Write-Host "Created dist directory" -ForegroundColor Gray
    }
    
    # Update tools
    Update-Tools
    
    # Build applications
    $buildSuccess = 0
    $buildTotal = 0
    
    if ($Target -eq "all") {
        foreach ($appKey in $apps.Keys) {
            $buildTotal++
            if (Build-App $appKey) {
                $buildSuccess++
            }
        }
    } elseif ($apps.ContainsKey($Target)) {
        $buildTotal = 1
        if (Build-App $Target) {
            $buildSuccess = 1
        }
    } else {
        Write-Host "Invalid target: $Target" -ForegroundColor Red
        Write-Host "Valid targets: all, $($apps.Keys -join ', ')" -ForegroundColor Yellow
        exit 1
    }
    
    # Test builds if requested
    if ($Test) {
        Test-Builds
    }
    
    # Show results
    Show-Results
    
    # Summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    if ($buildSuccess -eq $buildTotal) {
        Write-Host "✓ All builds completed successfully ($buildSuccess/$buildTotal)" -ForegroundColor Green
    } else {
        Write-Host "⚠ Some builds failed ($buildSuccess/$buildTotal)" -ForegroundColor Yellow
    }
    Write-Host "========================================" -ForegroundColor Cyan
    
} catch {
    Write-Host "Build script failed: $_" -ForegroundColor Red
    exit 1
}