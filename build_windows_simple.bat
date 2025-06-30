go build -ldflags="-H windowsgui" -o dist\snmptk-windows.exe .\cmd\snmptk
go build -ldflags="-H windowsgui" -o dist\snmptk-scan.exe .\cmd\scanner  
go build -ldflags="-H windowsgui" -o dist\snmptk-scan-ext.exe .\cmd\scanner-ext
go build -o dist\snmptk-report.exe .\cmd\report-generator 