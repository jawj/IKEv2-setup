# IKEv2-setup

## What?

A script to take Ubuntu Server 17.04 from clean install to production-ready IKEv2 VPN with strongSwan.

* The VPN server identifies itself with a Let's Encrypt certificate, so there's no need for clients to install private certificates — they can simply authenticate with username and password (EAP-MSCHAPv2). The Let's Encrypt certificate is set up to auto-renew.
* The box is firewalled with `iptables` and configured for unattended security upgrades, so it should be safe to forget about until 17.04 reaches end-of-life.
* A `.mobileconfig` profile is generated for Mac and iOS, to set up moderately secure ciphers and *Connect on demand* support, sending all traffic over the VPN.

Comments and pull requests are welcomed.

### Compatibility

* The setup script is tested working on VPSs from OVH and Linode.
* The VPN configuration is tested working with the built-in VPN clients on OS X 10.12, Windows 10, and iOS 10, and the Android strongSwan client.

### Caveats

* The script will **not** work unmodified on 16.04 LTS because the `certbot` package is outdated (and found under the name `letsencrypt`). 
* If you previously set this up on Ubuntu 16.10, you'll need to manually amend the `ike` and `esp` directives in `/etc/ipsec.conf` after the upgrade to 17.04, since the latest version of strongSwan doesn't like different kinds of ciphers mushed together.
* It's not recommended to use this unmodified on a server you use for anything else, as it does as it sees fit with various wider settings that may conflict with what you're doing.
* There's no IPv6 support — and, in fact, IPv6 networking is disabled — because I haven't got to grips with the security implications of that.


## How?

Run `./setup.sh` as root and you'll be prompted to enter all the necessary details. You *must* use a strong password for the login user, or your server will be compromised. 

## Why?

We use a similar setup as a corporate VPN at [PSYT](http://psyt.co.uk). And I use this to bounce my personal web browsing via Europe, in the hope of giving Theresa May's [Investigatory Powers Bill](https://www.openrightsgroup.org/blog/2015/investigatory-powers-bill-published-and-now-the-fight-is-on) the finger.

### Why IKEv2?

* Fair security
* Built-in clients for latest iOS, Mac and Windows (+ free install on Android)
* *Connect on demand* support on iOS and Mac
* Robust to connection switching and interruptions via MOBIKE

More on IKEv2 at https://www.cl.cam.ac.uk/~mas90/resources/strongswan/ and https://www.bestvpn.com/blog/4147/pptp-vs-l2tp-vs-openvpn-vs-sstp-vs-ikev2/
