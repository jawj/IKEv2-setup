# IKEv2-setup

## What?

A script to take Ubuntu Server 16.10 from clean install to production-ready IKEv2 VPN with strongSwan. The server is appropriately firewalled and configured for unattended upgrades.

* VPN server identifies itself with a Let's Encrypt certificate
* VPN users authenticate with username and password (EAP-MSCHAPv2)

VPN configuration is tested working with OS X 10.12.1, Windows 10, iOS 10.1, and the Android strongSwan client.

Comments and pull requests welcomed.

## How?

Run `./setup.sh` as root and you'll be prompted to enter all the necessary details. You *must* use a strong password for the login user, or your server will be compromised. 

## Why?

We use a similar setup as a corporate VPN at [PSYT](http://psyt.co.uk). And I use this to bounce my personal web browsing via Europe, in the hope of giving Theresa May's [Investigatory Powers Bill](https://www.openrightsgroup.org/blog/2015/investigatory-powers-bill-published-and-now-the-fight-is-on) the finger.

### Why IKEv2?

* Fair security
* Built-in clients for latest iOS, Mac and Windows
* Robust to connection switching and interruptions via MOBIKE

More at https://www.cl.cam.ac.uk/~mas90/resources/strongswan/ and https://www.bestvpn.com/blog/4147/pptp-vs-l2tp-vs-openvpn-vs-sstp-vs-ikev2/
