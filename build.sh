#!/usr/bin/env sh
set -e
export GO111MODULE=on
export CGO_ENABLED=0

# Linux amd64
export GOOS=linux
export GOARCH=amd64
go build -o gosearch_linux_amd64

# Linux 386
export GOOS=linux
export GOARCH=386
go build -o gosearch_linux_386
