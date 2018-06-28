package main

// Change the default hardcoded AES encryption key.
var AESEncryptionKey = "netg0pha"

// If you wish to hardcode TLS server keys into binary then
// you should change the values below.
//
// TLS Server Keys for encrypted communicaton
// http://pascal.bach.ch/2015/12/17/from-tcp-to-tls-in-go/
//
// netgopha will check for a server.key and cert.pem file then use
// that before using the hardcoded keys below.
//
//
// To generate keys:
// openssl ecparam -genkey -name prime256v1 -out server.key
// openssl req -new -x509 -key server.key -out cert.pem -days 3650

// server.key (change this or generate server.key file)
const serverKey = `-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIGb7E70UCFJbOtauKvoMJBKt8duVCSt1iMXF44uETK4XoAoGCCqGSM49
AwEHoUQDQgAEHG/mYyHLPII3AeEjNExn3bx3xOKc3p1lND82XeszXTEf535EtZos
f1GIGj1AxGCmwZIUDzAqLheUmTAsQP5FsA==
-----END EC PRIVATE KEY-----
`

// cert.pem (change this or generate cert.pem file)
const serverCert = `-----BEGIN CERTIFICATE-----
MIICJjCCAc6gAwIBAgIJAIwUhparoU7MMAkGByqGSM49BAEwRTELMAkGA1UEBhMC
QVUxEzARBgNVBAgTClNvbWUtU3RhdGUxITAfBgNVBAoTGEludGVybmV0IFdpZGdp
dHMgUHR5IEx0ZDAeFw0xNzExMTkwNDQyMTVaFw0yNzExMTcwNDQyMTVaMEUxCzAJ
BgNVBAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5l
dCBXaWRnaXRzIFB0eSBMdGQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQcb+Zj
Ics8gjcB4SM0TGfdvHfE4pzenWU0PzZd6zNdMR/nfkS1mix/UYgaPUDEYKbBkhQP
MCouF5SZMCxA/kWwo4GnMIGkMB0GA1UdDgQWBBSiIMId3fHKOW1O3MIlwG9vQP7v
8zB1BgNVHSMEbjBsgBSiIMId3fHKOW1O3MIlwG9vQP7v86FJpEcwRTELMAkGA1UE
BhMCQVUxEzARBgNVBAgTClNvbWUtU3RhdGUxITAfBgNVBAoTGEludGVybmV0IFdp
ZGdpdHMgUHR5IEx0ZIIJAIwUhparoU7MMAwGA1UdEwQFMAMBAf8wCQYHKoZIzj0E
AQNHADBEAiBp1gKDtuMRREyn/Z2/ouOMW0RoD1BwAkR7vkY4f/90nQIgKVJB8ZgQ
FdbP1FZBpEK/FoH79kE2CWbm63UdzTDaRWM=
-----END CERTIFICATE-----
`
