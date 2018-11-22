# esnitool
A cmdline tool in golang to query and display TLS ESNI records from DNS

# Sample Usage

```
$ ./esnitool www.cloudflare.com
domain: _esni.www.cloudflare.com
version : FF 01 (known)
checksum: B7 EF A8 70 (valid)
keys (1):
  0: x25519 [57 51 54 D0 33 EF BF B8 AB 15 26 F5 E9 42 B8 20 F7 1B 9C D4...]
cipher_suites (1):
  0: TLS_AES_128_GCM_SHA256
padded_length: 260
not_before: 2018-11-19 14:00:00 -0500 EST
not_after: 2018-11-25 14:00:00 -0500 EST
extensions: none
```
# Version
Currently it supports the lastest [draft (02)](https://tools.ietf.org/html/draft-ietf-tls-esni-02).  You can be sure there will be changes before it is finalized.

# Building
There are no dependencies other than stdlib, so it's just:
```
cd $GOPATH
go get github.com/mordyovits/esnitool
./bin/esnitool www.cloudflare.com
```
