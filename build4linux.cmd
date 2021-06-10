setlocal
set GOARCH=amd64
set GOOS=linux
set CGO_ENABLED=0
go build -a -installsuffix cgo -ldflags="-w -s" -o ./bin/main
endlocal