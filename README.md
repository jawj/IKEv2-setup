# IKEv2-setup

## What?

A script to take Ubuntu Server 14.04 from clean install to production-ready IKEv2 VPN with strongSwan. The server is appropriately firewalled and configured for unattended upgrades.

* VPN server identifies itself with a (free) StartSSL web server certificate
* VPN users authenticate with username and password (EAP-MSCHAPv2)

VPN configuration is tested working with OS X 10.11.1, Windows 10, iOS 9.1, and the Android strongSwan client.

Comments and pull requests welcomed.

## How?

Run `./setup.sh` as root and you'll be prompted to enter all the necessary details. You *must* use a strong password for the login user, or your server will be compromised. 

The script assumes you're using a free certificate from [StartSSL](http://www.startssl.com/). You can either have StartSSL create your private key, or you can do the right thing and create your own key and certificate signing request like so:

    openssl req -new -newkey rsa:2048 -nodes \
    -out ikev2_example_com.csr \
    -keyout ikev2_example_com.key \
    -subj "/C=GB/ST=/L=Brighton/O=Joe Bloggs/CN=ikev2.example.com"

## Why IKEv2?

* Fair security
* Built-in clients for latest iOS, Mac and Windows
* Robust to connection switching and interruptions via MOBIKE

More at e.g. https://www.bestvpn.com/blog/4147/pptp-vs-l2tp-vs-openvpn-vs-sstp-vs-ikev2/
