@echo off
setlocal

set CGO_ENABLED=0
set GOARCH=arm64

:: Set environment for Windows build
set GOOS=darwin


:: Build for Linux
garble build -trimpath -ldflags "-s -w" -buildvcs=false -o bin/frps .\cmd\frps
garble build -trimpath -ldflags "-s -w" -buildvcs=false -o bin/frpc .\cmd\frpc

endlocal
pause
