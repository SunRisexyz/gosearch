@echo off
setlocal
set GO111MODULE=on
set CGO_ENABLED=0

REM Windows amd64
set GOOS=windows
set GOARCH=amd64
go build -o gosearch.exe

endlocal
