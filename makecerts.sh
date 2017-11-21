#!/bin/bash

# Also possible to generate tls certificates using go:
# go run $GOROOT/src/crypto/tls/generate_cert.go -host "127.0.0.1"
# will generate: server.sky and cert.pem

if ! [ -x "$(command -v openssl)" ]; then
	echo "openssl is not installed"
	exit 1
else
	openssl ecparam -genkey -name prime256v1 -out server.key
	openssl req -new -x509 -key server.key -out cert.pem -days 3650
fi

