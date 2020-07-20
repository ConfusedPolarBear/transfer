linux:
	go build

windows:
	GOOS=windows go build -o transfer-windows

clean:
	go clean
	rm transfer-windows 2>/dev/null || true

all: linux windows
