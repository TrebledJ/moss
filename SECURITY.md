# Security Policy

Security is treated seriously here.

Out of scope issues:

- Denial of Service
- Rate limiting
- Informational HTML header related issues (e.g. missing X-Frame-Options)
- Intended functionality which doesn't classify as a [vulnerability per MITRE's definition][vulndef] (e.g. file upload, file browsing)
- Information disclosure issues which are intended and don't classify as a [vulnerability per MITRE's definition][vulndef] (e.g. plaintext in stealthnet profile)
- Malicious extension file

[vulndef]: https://www.cve.org/ResourcesSupport/Glossary#glossaryVulnerability

If you believe you've found a significant security issue, please contact me at trebledjjj[at]proton[dot]me or through other 1-to-1 private channels.

Examples of bug classes accepted:
- Request smuggling
- Authentication bypass
- XSS
- RCE
- Python format string attack leading to information disclosure

No bounty will be provided. (I am poor.)

But if you would like, I will add your name to this marvelous Hall of Thanks:

## Hall of Thanks

Thanks to the following amazing people for disclosing vulnerabilies:

-  
