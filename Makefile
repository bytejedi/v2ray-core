COMMITHASH=$(shell git rev-parse --short HEAD)
LDFLAGS=-s -w -buildid= -X github.com/v2fly/v2ray-core/v5.build=${COMMITHASH}

build:
	go mod download && go build -o ./build/v2ray -ldflags "${LDFLAGS}" ./main
