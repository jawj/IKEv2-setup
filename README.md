# IKEv2-setup

## What?

A script to take Ubuntu Server 17.04 from clean install to production-ready IKEv2 VPN with strongSwan.

* The VPN server identifies itself with a Let's Encrypt certificate, so there's no need for clients to install private certificates — they can simply authenticate with username and password (EAP-MSCHAPv2). The Let's Encrypt certificate is set up to auto-renew.
* The box is firewalled with `iptables` and configured for unattended security upgrades, so it should be safe to forget about until 17.04 reaches end-of-life.
* A `.mobileconfig` profile is generated for Mac and iOS, to set up moderately secure ciphers and *Connect on demand* support, sending all traffic over the VPN. PowerShell commands are provided to configure secure ciphers on Windows 10. These are sent by email.

Comments and pull requests are welcomed.

### Compatibility

* The setup script is tested working on the cheapest VPSs offered by Linode, OVH, Vultr, and on Scaleway's ARM64-2GB (on Scaleway, unblock SMTP ports in the admin panel and *hard* reboot the server first, or your configuration email will not be delivered).
* The VPN configuration is tested working with the built-in VPN clients on OS X 10.12, Windows 10, and iOS 10, and the Android strongSwan client.

### Caveats

* The script will **not** work unmodified on 16.04 LTS because the `certbot` package is outdated (and found under the name `letsencrypt`).
* There's no IPv6 support — and, in fact, IPv6 networking is disabled — because I haven't got to grips with the security implications (e.g. `iptables` rules), and because supporting IPv6 prevents the use of `forceencaps`.
* It's not recommended to use this unmodified on a server you use for anything else, as it does as it sees fit with various wider settings that may conflict with what you're doing.

## How?

* Start with a clean Ubuntu 17.04 Server installation.

* Pick a domain name for the VPN server and ensure that it already resolves to the correct IP. Let's Encrypt needs this in order to create the server certificate.

* Run `./setup.sh` as root and you'll be prompted to enter all the necessary details. You *must* use a strong password or passphrase for the login user, or your server *will* be compromised. 

### Troubleshooting

If things don't work out right away ...

* Make sure you created the client connection using the emailed `.mobileconfig` file or PowerShell commands. Setting it up manually via the OS GUI will not work, since it will default to insecure ciphers which the server has not been configured to support.

* Check the server logs on strongSwan startup and when you try to connect, and the client logs when you try to connect. 

  * __On the server:__  Log in via SSH, then `sudo less +F /var/log/syslog`. To see startup logs, log in to another session and `sudo ipsec restart` there, then switch back. To see the logs during a connection attempt, try to connect from a client. 
  
  * __On the client:__  On a Mac, open Console.app in /Applications/Utilities. If connecting from an iPhone, plug the iPhone into the Mac. Pick the relevant device (in the bar down the left), and filter the output (in the box at top right) to `nesession`, and try to connect. On Windows or Linux I don't know where you find the logs (if _you_ know, feel free to write the explanation and send a pull request).

### Upgrades

If you previously set this up on Ubuntu 16.10, you will need to manually amend the `ike`, `esp`, and `uniqueids` directives in `/etc/ipsec.conf` to reflect the current values in `setup.sh` after upgrading to 17.04. The newer version of strongSwan in 17.04 doesn't like different sorts of ciphers being smooshed together, and `uniqueids=no` now gives me problems trying to connect from two different devices with the same user name.

Alternatively, it may be cleaner to make a record of any changes to `ipsec.secrets`, blow the whole thing away and reinstall.

You will also need to recreate any Windows 10 VPNs using the provided PowerShell commands, since the less secure ciphers supported by GUI-created Windows VPNs are no longer enabled.

### Bonus paranoia

Your traffic is not logged on the server, but if you're feeling especially paranoid there are various things you could do to reduce logging further. A simple and particularly drastic option is:

    sudo rm /var/log/syslog && sudo ln -s /dev/null /var/log/syslog
    sudo rm /var/log/auth.log && sudo ln -s /dev/null /var/log/auth.log

## Why?

We use a similar setup as a corporate VPN at [PSYT](http://psyt.co.uk). And I use this to bounce my personal web browsing via Europe, in the hope of giving Theresa May's [Investigatory Powers Bill](https://www.openrightsgroup.org/blog/2015/investigatory-powers-bill-published-and-now-the-fight-is-on) the finger.

### Why IKEv2?

* Fair security
* Built-in clients for latest iOS, Mac and Windows (+ free install on Android)
* *Connect on demand* support on iOS and Mac
* Robust to connection switching and interruptions via MOBIKE

More on IKEv2 at https://www.cl.cam.ac.uk/~mas90/resources/strongswan/ and https://www.bestvpn.com/blog/4147/pptp-vs-l2tp-vs-openvpn-vs-sstp-vs-ikev2/
