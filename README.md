# IKEv2-setup

A script to take Ubuntu Server 14.04 from clean install to fully ready IKEv2 VPN with strongSwan. The server is firewalled, updated and set to automatically update in future.

* VPN server identifies itself with a (free) StartSSL web server certificate
* VPN users authenticate with username and password (EAP-MSCHAPv2)

VPN configuration is tested working with iOS 9.1, OS X 10.11.1 and Windows 10.
