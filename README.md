# IKEv2-setup

## What?

A script to take Ubuntu Server 17.04 from clean install to production-ready IKEv2 VPN with strongSwan. The server is appropriately firewalled and configured for unattended security upgrades.

* VPN server identifies itself with a Let's Encrypt certificate (no need to install private certs), which is automatically renewed
* VPN users authenticate simply with username and password (EAP-MSCHAPv2)
* A `.mobileconfig` profile is generated for Mac and iOS, to set up secure ciphers and *Connect on demand* support

Comments and pull requests welcomed.

### Compatibility

* The VPN configuration is tested working with OS X 10.12, Windows 10, iOS 10, and the Android strongSwan client.
* The script is tested working on VPSs from OVH and Linode.

### Caveats

* The script will **not** work unmodified on 16.04 LTS because the `certbot` package is outdated (and found under the name `letsencrypt`). 
* It's also not recommended to use this unmodified on a server you use for anything else, as it does as it sees fit with various wider settings that may conflict with what you're doing.


## How?

Run `./setup.sh` as root and you'll be prompted to enter all the necessary details. You *must* use a strong password for the login user, or your server will be compromised. 

## Why?

We use a similar setup as a corporate VPN at [PSYT](http://psyt.co.uk). And I use this to bounce my personal web browsing via Europe, in the hope of giving Theresa May's [Investigatory Powers Bill](https://www.openrightsgroup.org/blog/2015/investigatory-powers-bill-published-and-now-the-fight-is-on) the finger.

### Why IKEv2?

* Fair security
* Built-in clients for latest iOS, Mac and Windows (+ free install on Android)
* *Connect on demand* support on iOS and Mac
* Robust to connection switching and interruptions via MOBIKE

More at https://www.cl.cam.ac.uk/~mas90/resources/strongswan/ and https://www.bestvpn.com/blog/4147/pptp-vs-l2tp-vs-openvpn-vs-sstp-vs-ikev2/
