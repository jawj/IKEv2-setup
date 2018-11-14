# IKEv2-setup

## Table of Contents

  * [What?](#what)
    + [VPN server](#vpn-server)
    + [VPN clients](#vpn-clients)
    + [Caveats](#caveats)
  * [How?](#how)
    + [Troubleshooting](#troubleshooting)
    + [Users](#users)
    + [Upgrades](#upgrades)
    + [Bonus paranoia](#bonus-paranoia)
  * [Why?](#why)
    + [Why IKEv2?](#why-ikev2)

## What?

A Bash script that takes Ubuntu Server 18.04 LTS from clean install to production-ready IKEv2 VPN with strongSwan. Comments and pull requests welcome. It may still work on 17.10, 17.04 or 16.10 if you remove the version check, but these are not tested.

### VPN server

* The VPN server identifies itself with a _Let's Encrypt_ certificate, so there's no need for clients to install private certificates — they can simply authenticate with username and strong password (EAP-MSCHAPv2).
* The box is firewalled with `iptables` and configured for unattended security upgrades, and the _Let's Encrypt_ certificate is set up to auto-renew, so it _could_ be safe to forget about it all until 18.04 reaches end-of-life in 2023. (Note that `iptables` setup includes [basic rate-limiting](https://debian-administration.org/article/187/Using_iptables_to_rate-limit_incoming_connections), dropping new connections if there have been 60+ connection attempts in the last 5 minutes)
* The cheapest VPSs offered by Linode, OVH, vps.ag, Hetzner and Vultr, and Scaleway's ARM64-2GB, have all been tested working as VPN servers. On Scaleway, unblock SMTP ports in the admin panel and *hard* reboot the server first, or your configuration email will not be delivered. On Vultr port 25 may also be blocked, but you won't know, and the only way to fix it is to open a support ticket.

### VPN clients

The VPN is tested working with:

*  **macOS 10.12 – 10.14, iOS 10 – 12**  — Built-in clients. A `.mobileconfig` profile is generated for Mac and iOS, to set up secure ciphers and enable *Connect on demand* support.
* **Windows 10 Pro** — Built-in client. PowerShell commands are generated to configure the VPN and secure ciphers.
* **Ubuntu (17.04 and presumably others)** — Using strongSwan. A Bash script is generated to set this up.
* **Android** — Using the strongSwan app.

Configuration files, scripts and instructions are sent by email. They are also dropped in the newly-created non-root user's home directory on the server (this point may be important, because VPS providers sometimes block traffic on port 25 by default, and conscientious email providers will sometimes mark a successfully sent email as spam).

### Caveats

* There's no IPv6 support — and, in fact, IPv6 networking is disabled — because supporting IPv6 prevents the use of `forceencaps`, and honestly also because I haven't got to grips with the security implications (`ip6tables` rules and so on).
* The script **won't** work as-is on 16.04 LTS because the `certbot` package is outdated, found under the name `letsencrypt`, and doesn't renew certificates automatically.
* Don't use this unmodified on a server you use for anything else, as it does as it sees fit with various wider settings that may conflict with what you're doing.


## How?

* _Either:_ Pick a domain name for the VPN server and **ensure that it already resolves to the correct IP** by creating the appropriate A record in the DNS and making sure it has propagated. _Let's Encrypt_ needs this in order to create your server certificate.

    _Or:_ Choose to rely on an automatic DNS name from [sslip.io](https://sslip.io/) of the form _nnn.nnn.nnn.nnn.sslip.io_, which will be used automatically if you omit to enter a hostname when prompted by the script.

* Start with a clean Ubuntu 18.04 Server installation.

* Optionally, set up [key-based SSH authentication](https://help.ubuntu.com/community/SSH/OpenSSH/Keys) (alternatively, this may have been handled automatically by your server provider, or you may choose to stick with password-based authentication). This may require you to run some or all of the following commands, with appropriate substitutions, on the machine you're going to be logging in from:

      ssh-keygen -t ed25519 -C "me@my-domain.tld"      # if you need a new key, ed25519 is the latest and possibly most secure option
      ssh-keygen -t rsa -b 4096 -C "me@my-domain.tld"  # alternatively, use RSA and go (4,096 bits) large

      ssh root@myvpn.example.net  # if your host forces a password change before anything else (e.g. Hetzner), do it now, then exit
      ssh-copy-id -i ~/.ssh/id_ed25519 root@myvpn.example.net  # copy your public key over to the VPN server
      ssh root@myvpn.example.net  # log back in to the server for the next step ...

* On your new server installation, become `root`, download the script, give it execute permissions, and run it:

      wget https://raw.githubusercontent.com/jawj/IKEv2-setup/master/setup.sh
      chmod u+x setup.sh
      ./setup.sh
    
* You'll be prompted to enter all the necessary details. If you are not using key-based SSH authentication, **you *must* pick a really strong password** for the login user when prompted, or your server *will* be compromised. 

### Troubleshooting

If things don't work out right away ...

* Make sure you created the client connection using the emailed `.mobileconfig` file or PowerShell commands. Setting it up manually via the OS GUI will not work, since it will default to insecure ciphers which the server has not been configured to support.

* Check the server logs on strongSwan startup and when you try to connect, and the client logs when you try to connect. 

  * __On the server:__  Log in via SSH, then `sudo less +F /var/log/syslog`. To see startup logs, log in to another session and `sudo ipsec restart` there, then switch back. To see what's logged during a connection attempt, try to connect from a client. 
  
  * __On the client:__  On a Mac, open Console.app in /Applications/Utilities. If connecting from an iPhone, plug the iPhone into the Mac. Pick the relevant device (in the bar down the left), filter the output (in the box at top right) to `nesession`, and try to connect. (On Windows or Linux I don't know where you find the logs — if _you_ know, feel free to write the explanation and send a pull request).
  
* The setup script is now idempotent — you can run it repeatedly with no ill effects — so, when you've fixed any issues, simply run it again.

* If you have a tricky question about strongSwan, it's probably better to [raise it with the strongSwan team](https://strongswan.org/support.html) than file an issue here.
  
### Users

To add or change VPN users, it's:

      sudo nano /etc/ipsec.secrets
    
Edit usernames and passwords as you see fit (but don't touch the first line, which specifies the server certificate). The line format for each user is:

      someusername : EAP "somepassword"

To exit nano it's `Ctrl + O` then `Ctrl + X`, and to have strongSwan pick up the changes it's:

      sudo ipsec secrets

### Upgrades

If you're on a pre-18.04 version of Ubuntu, it's probably easiest to make a record of any changes to `ipsec.secrets`, blow the whole thing away and reinstall, then reinstate `ipsec.secrets`.

Note that you may also need to delete and recreate all your client connection settings using the updated PowerShell commands or .mobileconfig file, since there have been a few cipher changes over time. 

### Bonus paranoia

Your traffic is not logged on the server, but if you're feeling especially paranoid there are various things you could do to reduce logging further. A simple and somewhat drastic option (once you've got everything working) is:

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
