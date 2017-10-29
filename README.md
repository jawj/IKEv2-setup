# IKEv2-setup

## What?

A Bash script that takes Ubuntu Server 17.10 (and probably also 17.04 or 16.10, but these are no longer tested) from clean install to production-ready IKEv2 VPN with strongSwan. Comments and pull requests welcome.

### VPN server

* The VPN server identifies itself with a Let's Encrypt certificate, so there's no need for clients to install private certificates — they can simply authenticate with username and password (EAP-MSCHAPv2).
* The box is firewalled with `iptables` and configured for unattended security upgrades, and the Let's Encrypt certificate is set up to auto-renew, so it should be safe to forget about it all until 17.10 reaches end-of-life.
* The cheapest VPSs offered by Linode, OVH and Vultr, and Scaleway's ARM64-2GB, have all been tested working as VPN servers. On Scaleway, unblock SMTP ports in the admin panel and *hard* reboot the server first, or your configuration email will not be delivered. On Vultr port 25 may also be blocked, but you won't know, and the only way to fix it is to open a support ticket.

### VPN clients

The VPN is tested working with:

*  **macOS 10.12 + 10.13, iOS 10 + 11**  — Built-in clients. A `.mobileconfig` profile is generated for Mac and iOS, to set up secure ciphers and enable *Connect on demand* support.
* **Windows 10 Pro** — Built-in client. PowerShell commands are generated to configure the VPN and secure ciphers.
* **Ubuntu 17.04** — Using strongSwan. A Bash script is generated to set this up.
* **Android** — Using the strongSwan app.

Configuration files, scripts and instructions are sent by email. They are also dropped in the newly-created non-root user's home directory on the server (this point may be important, because VPS providers sometimes block traffic on port 25 by default, and conscientious email providers will sometimes mark a successfully sent email as spam).

### Caveats

* The script **won't** work as-is on 16.04 LTS because the `certbot` package is outdated, found under the name `letsencrypt`, and doesn't renew certificates automatically.
* There's no IPv6 support — and, in fact, IPv6 networking is disabled — because supporting IPv6 prevents the use of `forceencaps`, and honestly also because I haven't got to grips with the security implications (`ip6tables` rules and so on).
* Don't use this unmodified on a server you use for anything else, as it does as it sees fit with various wider settings that may conflict with what you're doing.


## How?

* Start with a clean Ubuntu 17.10 Server installation.

* Pick a domain name for the VPN server and **ensure that it already resolves to the correct IP**. _Let's Encrypt_ needs this in order to create your server certificate.

* Run `./setup.sh` as root and you'll be prompted to enter all the necessary details. **You *must* use a strong password** or passphrase for the login user, or your server *will* be compromised. 

### Troubleshooting

If things don't work out right away ...

* Make sure you created the client connection using the emailed `.mobileconfig` file or PowerShell commands. Setting it up manually via the OS GUI will not work, since it will default to insecure ciphers which the server has not been configured to support.

* Check the server logs on strongSwan startup and when you try to connect, and the client logs when you try to connect. 

  * __On the server:__  Log in via SSH, then `sudo less +F /var/log/syslog`. To see startup logs, log in to another session and `sudo ipsec restart` there, then switch back. To see what's logged during a connection attempt, try to connect from a client. 
  
  * __On the client:__  On a Mac, open Console.app in /Applications/Utilities. If connecting from an iPhone, plug the iPhone into the Mac. Pick the relevant device (in the bar down the left), and filter the output (in the box at top right) to `nesession`, and try to connect. (On Windows or Linux I don't know where you find the logs — if _you_ know, feel free to write the explanation and send a pull request).
  
* The setup script is now idempotent — you can run it repeatedly with no ill effects — so, when you've fixed any issues, simply run it again.
  
### Users

To add or change VPN users, it's:

    sudo nano /etc/ipsec.secrets
    
Edit usernames and passwords as you see fit (but don't touch the first line, which specifies the server certificate). The line format for each user is:

    someusername %any : EAP "somepassword"

To exit nano it's `Ctrl + O` then `Ctrl + X`, and to have strongSwan pick up the changes it's:

    sudo ipsec secrets

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
