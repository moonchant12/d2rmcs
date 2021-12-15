OUT := d2rmcs
VERSION := $(shell git describe --always --long --tags)

all: build

build: check-extra-info
	go build -i -v -o ${OUT}_${VERSION}.exe -buildmode=exe -ldflags "-w -s -X main.version=${VERSION} -X main.info=${INFO}"

check-extra-info:
ifndef INFO
	$(error INFO should be defined as in: make INFO=sometext12345)
endif

.PHONY: build check-extra-info
