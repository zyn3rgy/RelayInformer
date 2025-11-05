<p align="center">
  <img src=".github/img/logo1.png" alt="RelayInformer Logo" width="300"/>
</p>

<p align="center">
Python and BOF utilites to the determine EPA enforcement levels of popular NTLM relay targets from the offensive perspective
<br>
<br>
<a href="https://github.com/specterops#mythic">
    <img src="https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fspecterops%2F.github%2Fmain%2Fconfig%2Fshield.json"
      alt="Sponsored by SpecterOps"/>
</a>
</p>

## Introduction

These tools were written to compliment research summarized in a [blog post](PLACEHOLDER) / [presentation](PLACEHOLDER) by [@tw1sm](https://x.com/Tw1sm) and myself. 

NTLM relay is still a widely abused attack vector during pentests and red teams alike. Depending on your network access perspective, setting up for a relay can be an involved and error-prone process (e.g. over C2). The goal of this toolset is to better inform your NTLM relays, especially in cases where Extended Protection for Authentication (EPA) could be enforced as a mitigation.

## Usage

See the [RelayInformer [Python]](PLACEHOLDER) and [RelayInformer [BOFs]](PLACEHOLDER) documentation for details and example usage.

## Acknowledgements
- **Alex Demine** - initial effort in MSSQL EPA research
- [@Defte_](https://x.com/Defte_) - [“A journey implementation Channel Binding on MSSQLClient.py”](https://sensepost.com/blog/2025/a-journey-implementing-channel-binding-on-mssqlclient.py/)
- [@lowercase_drm](https://x.com/lowercase_drm) - early open-source implementation of LDAP channel binding in LDAP3 library
- **Pierre Milioni** & **Geoffrey Bertoli** - ["A study on Windows HTTP Authentication (Part II)](https://www.synacktiv.com/publications/a-study-on-windows-http-authentication-part-ii)
- [Adam Crosser](https://x.com/UNC1739) - ["Relaying to ADFS Attacks"](https://www.praetorian.com/blog/relaying-to-adfs-attacks/)
- Open-source developers contributing to libraries such as [Impacket](https://github.com/fortra/impacket), [msldap](https://github.com/skelsec/msldap), [LdapSignCheck](https://github.com/cube0x0/LdapSignCheck), and many more
