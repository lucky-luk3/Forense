# Emails
## Dkim signatures
DKIM perform some validations in email communications.
### DKIM headers
Example: 
```
dkim-signature: v=1; a=rsa-sha256; c=relaxed/relaxed;d=domain.com;
s=google;h=mime-version:disposition-notification-to:from:date:message-id:subject:to:cc;
bh=trzSbdc0RPPWhOdZIUT+CSQgON/Fxt76NubsMsvbFnk=;
b=Udrb9tAcsYggrS1W6FjFdHey3bPDUXuTQhy7FehoToOxV4RWXbdvTQXz4eDUTzsd5l
 WCnPF8YWTV25kH539bJGp0XFNxBE0ON5wfgbTNo8vNreBs/GSuc4hhJgMGHqyrANSJCW
 o+Uoe6C/858gaM+ArEIWV5kPTBt5S5seLw59M=
```
* v=  indicates the version of the signature specification. The value should always be set to 1.  
* a= indicates the algorithm used to generate the signature. The value should be rsa-sha256. Senders with reduced CPU capabilities may use rsa-sha1. However, using rsa-sha1 is discouraged due to potential security risks.
* s= indicates the selector record name used with the domain to locate the public key in DNS. The value is a name or number created by the sender.
* b= is the hash data of the headers listed in the h= tag; this hash is also called the DKIM signature and encoded in Base64.
* bh= is the computed hash of the message body. The value is a string of characters representing the hash determined by the hash algorithm.
* d= indicates the domain used with the selector record (s=) to locate the public key. The value is a domain name owned by the sender.
* h= is a list of headers that will be used in the signing algorithm to create the hash found in the b= tag. The order of the headers in the h= tag is the order in which they were presented during DKIM signing, and therefore is also the order in which they should be presented during verification. The value is a list of header fields that won’t change or be removed.
