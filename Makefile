linux:
	go build

windows:
	GOOS=windows go build -o transfer-windows.exe

clean:
	go clean
	rm transfer-windows.exe 2>/dev/null || true

all: linux windows
