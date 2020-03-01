# Netgopha

A netcat-like clone written in Go.  Supports:

* Unix/OSX only (windows support later)
* Executing commands on listener/client (same as -e in netcat)
* TLS encryption with hardcoded keys or  key files
* TCP protocol
* No-send option
* No-resolve option

Netgopha help menu:

```
netgopha [-l] [-e] [-p listen port ] [-s listen ip address] [ip/hostname] [port]
Usage of ./netgopha:
  -e string
    	Execute command locally
  -l	Listen mode
  -n	Do not resolve domain
  -p string
    	Local port to listen on
  -s string
    	IP address to listen on
  -v	Show current version
  -x	Use TLS encryption.  Either hardcoded or use cert files
  -z	Do not send any data
```

## How to build

Must have Go installed.  Git clone this repository then:

```
go build
```

You could also try with make:
```
make
```

## TLS Encryption support

There are two ways you can do TLS encryption: hardcoded keys or use key files.

To generate key files you need openssl installed:
```
./makecerts.sh
```

If you don't have openssl you can try using Go to generate your cert files (untested):
```
# Replace host with host/ip of your listener
go run $GOROOT/src/crypto/tls/generate_cert.go -host "127.0.0.1"
```

If you wish to use the hardcdoed option then copy and paste the keys into the netgopha.go file 
before you build.

However, if you wish to use a more secure method you would want to keep your server.key private.
A more secure option would be to add the cert.pem to netgopha.go for the "Client" version. Then
on your listener you would use the private server.key with cert.pem file.

## Example usage

TLS Encrypted listener (x for encrypted, l for listener, p for port):

```
./netgopha -x -l -p 9090
```

TLS Encrypted client to connect to local host listener (x for encrypted, connect to ip, connect to port)

```
./netgopha -x 127.0.0.1 9090
```

Reverse shell

```
# your listener
./netgopha -l -p 9090
# your client
./netgopha -e /bin/bash 127.0.0.1 9090
# on your listener
uname -a
```

Send no data to target (only output is enabled)
```
./netgopha -z nyancat.dakko.us 23
```

Assign listener to IP address
```
./netgopha -l -s 10.0.0.1 -p 9090
```

## Other netcat like Go projects

* https://github.com/vfedoroff/go-netcat
* https://github.com/dddpaul/gonc
* https://github.com/codeskyblue/netcat
* https://medium.com/@yanzay/implementing-simple-netcat-using-go-bbab37507635
