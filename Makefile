# ########################################################## #
# Makefile for Golang Project
# Includes cross-compiling, installation, cleanup
# ########################################################## #

# Check for required command tools to build or stop immediately
EXECUTABLES = git go find pwd
K := $(foreach exec,$(EXECUTABLES),\
        $(if $(shell which $(exec)),some string,$(error "No $(exec) in PATH)))

ROOT_DIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

BINARY=netgopha
VERSION=0.1.1
PLATFORMS=darwin linux windows
ARCHITECTURES=386 amd64
OUTPUT=output

# Setup linker flags option for build that interoperate with variable names in src code
LDFLAGS=-ldflags="-s -w -X main.Version=${VERSION}"
LDFLAGS_WIN=-ldflags="-s -w -X main.Version=${VERSION} -H windowsgui"

default: build

all: clean build_all install

build:
	go build ${LDFLAGS} -o $(OUTPUT)/${BINARY}
	# Compress
	#upx -f --brute -o ${BINARY}.upx ${BINARY}

build_all:
	$(foreach GOOS, $(PLATFORMS),\
	$(foreach GOARCH, $(ARCHITECTURES), $(shell export GOOS=$(GOOS); export GOARCH=$(GOARCH); go build -v -o $(OUTPUT)/$(BINARY)-$(GOOS)-$(GOARCH))))
        GOOS=windows GOARCH=386 go build ${LDFLAGS} -o $(OUTPUT)/$(BINARY)-windows.exe

build_win:
	GOOS=windows GOARCH=386 go build ${LDFLAGS} -o $(OUTPUT)/$(BINARY)-windows.exe

install:
	go install ${LDFLAGS}

# Remove only what we've created
clean:
	find ${ROOT_DIR} -name $(OUTPUT)/'${BINARY}[-?][a-zA-Z0-9]*[-?][a-zA-Z0-9]*' -delete

.PHONY: check clean install build_all all
