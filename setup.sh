#!/bin/bash -e

# == update to 16.10 if required:
# nano /etc/update-manager/release-upgrades -> Prompt=normal
# apt-get update
# do-release-upgrade

# == then run this script
# wget https://raw.githubusercontent.com/jawj/IKEv2-setup/master/setup.sh
# chmod u+x setup.sh
# ./setup.sh

echo
echo "=== Requesting configuration data ==="
echo

read -p "Timezone (e.g. Europe/London): " TZONE
read -p "Email address for sysadmin (e.g. j.bloggs@example.com): " EMAIL
read -p "Port for SSH login (e.g. 22): " SSHPORT
echo

read -p "Login username: " LOGINUSERNAME
while true; do
  read -s -p "Login password (must be STRONG!): " LOGINPASSWORD
  echo
  read -s -p "Confirm login password: " LOGINPASSWORD2
  echo
  [ "$LOGINPASSWORD" = "$LOGINPASSWORD2" ] && break
  echo "Passwords didn't match -- please try again"
done
echo

echo "** Hostname for VPN must ALREADY resolve to this machine, to enable Let's Encrypt certificate setup** "
read -p "Hostname for VPN (e.g. vpn.example.com): " VPNHOST

read -p "VPN username: " VPNUSERNAME
while true; do
read -s -p "VPN password (no quotes, please): " VPNPASSWORD
echo
read -s -p "Confirm VPN password: " VPNPASSWORD2
echo
[ "$VPNPASSWORD" = "$VPNPASSWORD2" ] && break
echo "Passwords didn't match -- please try again"
done

VPNIPPOOL="10.10.10.0/24"


echo
echo "=== Updating and installing software ==="
echo

export DEBIAN_FRONTEND=noninteractive
apt-get update && apt-get upgrade -y

debconf-set-selections <<< "postfix postfix/mailname string ${VPNHOST}"
debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"

apt-get install -y language-pack-en strongswan strongswan-plugin-eap-mschapv2 moreutils iptables-persistent postfix mailutils unattended-upgrades certbot


ETH0ORSIMILAR=$(ip route get 8.8.8.8 | awk -- '{printf $5}')
IP=$(ifdata -pa $ETH0ORSIMILAR)

echo
echo "Network interface: ${ETH0ORSIMILAR}"
echo "External IP: ${IP}"


echo
echo "=== Configuring firewall ==="
echo

# firewall
# https://www.strongswan.org/docs/LinuxKongress2009-strongswan.pdf
# https://wiki.strongswan.org/projects/strongswan/wiki/ForwardingAndSplitTunneling
# https://www.zeitgeist.se/2013/11/26/mtu-woes-in-ipsec-tunnels-how-to-fix/

iptables -P INPUT   ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT  ACCEPT

iptables -F
iptables -t nat -F
iptables -t mangle -F

# INPUT

# accept anything already accepted
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# accept anything on the loopback interface
iptables -A INPUT -i lo -j ACCEPT

# drop invalid packets
iptables -A INPUT -m state --state INVALID -j DROP

# rate-limit repeated new requests from same IP to any ports
iptables -I INPUT -i $ETH0ORSIMILAR -m state --state NEW -m recent --set
iptables -I INPUT -i $ETH0ORSIMILAR -m state --state NEW -m recent --update --seconds 60 --hitcount 12 -j DROP

# accept (non-standard) SSH
iptables -A INPUT -p tcp --dport $SSHPORT -j ACCEPT


# VPN

# accept IPSec/NAT-T for VPN (ESP not needed with forceencaps, as ESP goes inside UDP)
iptables -A INPUT -p udp --dport  500 -j ACCEPT
iptables -A INPUT -p udp --dport 4500 -j ACCEPT

# forward VPN traffic anywhere
iptables -A FORWARD --match policy --pol ipsec --dir in  --proto esp -s $VPNIPPOOL -j ACCEPT
iptables -A FORWARD --match policy --pol ipsec --dir out --proto esp -d $VPNIPPOOL -j ACCEPT

# reduce MTU/MSS values for dumb VPN clients
iptables -t mangle -A FORWARD --match policy --pol ipsec --dir in -s $VPNIPPOOL -o $ETH0ORSIMILAR -p tcp -m tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1361:1536 -j TCPMSS --set-mss 1360

# masquerade VPN traffic over eth0 etc.
iptables -t nat -A POSTROUTING -s $VPNIPPOOL -o $ETH0ORSIMILAR -m policy --pol ipsec --dir out -j ACCEPT  # exempt IPsec traffic from masquerading
iptables -t nat -A POSTROUTING -s $VPNIPPOOL -o $ETH0ORSIMILAR -j MASQUERADE


# fall through to drop any other input and forward traffic

iptables -A INPUT   -j DROP
iptables -A FORWARD -j DROP

iptables -L

debconf-set-selections <<< "iptables-persistent iptables-persistent/autosave_v4 boolean true"
debconf-set-selections <<< "iptables-persistent iptables-persistent/autosave_v6 boolean true"
dpkg-reconfigure iptables-persistent


echo
echo "=== Configuring RSA certificates ==="
echo

mkdir -p /etc/letsencrypt

echo 'rsa-key-size = 4096
pre-hook = /sbin/iptables -I INPUT -p tcp --dport 443 -j ACCEPT
post-hook = /sbin/iptables -D INPUT -p tcp --dport 443 -j ACCEPT
renew-hook = /usr/sbin/ipsec reload && /usr/sbin/ipsec secrets
' > /etc/letsencrypt/cli.ini

certbot certonly --non-interactive --agree-tos --email $EMAIL --standalone -d $VPNHOST

ln -s /etc/letsencrypt/live/$VPNHOST/cert.pem    /etc/ipsec.d/certs/cert.pem
ln -s /etc/letsencrypt/live/$VPNHOST/privkey.pem /etc/ipsec.d/private/privkey.pem
ln -s /etc/letsencrypt/live/$VPNHOST/chain.pem   /etc/ipsec.d/cacerts/chain.pem

echo "/etc/letsencrypt/archive/${VPNHOST}/* r," >> /etc/apparmor.d/local/usr.lib.ipsec.charon
aa-status --enabled && invoke-rc.d apparmor reload


echo
echo "=== Configuring VPN ==="
echo

# ip_forward is for VPN
# ip_no_pmtu_disc is for UDP fragmentation
# others are for security

echo '
net.ipv4.ip_forward = 1
net.ipv4.ip_no_pmtu_disc = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
' >> /etc/sysctl.conf

sysctl -p

# these ike and esp settings are tested on Mac 10.12, iOS 10.1 and Windows 10
# iOS/Mac with appropriate configuration profiles use (up to) AES_GCM_16_256/PRF_HMAC_SHA2_512/ECP_521 
# Windows 10 uses AES_CBC_256/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1024 -- disabling any of aes256, sha1 or modp1024 causes a connection failure 

echo "config setup
  strictcrlpolicy=yes
  uniqueids=no

conn roadwarrior
  auto=add
  compress=no
  type=tunnel
  keyexchange=ikev2
  fragmentation=yes
  forceencaps=yes
  ike=aes256gcm16-aes256-sha512-sha384-sha256-sha1-ecp521-ecp384-ecp256-ecp224-ecp192-modp3072-modp2048-modp1536-modp1024!
  esp=aes256gcm16-aes256-sha512-sha384-sha256-sha1!
  dpdaction=clear
  dpddelay=300s
  rekey=no
  left=%any
  leftid=@${VPNHOST}
  leftcert=cert.pem
  leftsendcert=always
  leftsubnet=0.0.0.0/0
  right=%any
  rightid=%any
  rightauth=eap-mschapv2
  eap_identity=%any
  rightdns=8.8.8.8,8.8.4.4
  rightsourceip=${VPNIPPOOL}
  rightsendcert=never
" > /etc/ipsec.conf

echo "${VPNHOST} : RSA \"privkey.pem\"
${VPNUSERNAME} %any : EAP \""${VPNPASSWORD}"\"
" > /etc/ipsec.secrets

ipsec restart



echo
echo "=== User ==="
echo

# user + SSH

adduser --disabled-password --gecos "" $LOGINUSERNAME
echo "${LOGINUSERNAME}:${LOGINPASSWORD}" | chpasswd
adduser ${LOGINUSERNAME} sudo

sed -r \
-e "s/^Port 22$/Port ${SSHPORT}/" \
-e 's/^LoginGraceTime 120$/LoginGraceTime 30/' \
-e 's/^PermitRootLogin yes$/PermitRootLogin no/' \
-e 's/^X11Forwarding yes$/X11Forwarding no/' \
-e 's/^UsePAM yes$/UsePAM no/' \
-i.original /etc/ssh/sshd_config

echo "
MaxStartups 1
MaxAuthTries 2
UseDNS no" >> /etc/ssh/sshd_config

service ssh restart


echo
echo "=== Timezone, mail, unattended upgrades ==="
echo

timedatectl set-timezone $TZONE
/usr/sbin/update-locale LANG=en_GB.UTF-8


sed -r \
-e "s/^myhostname =.*$/myhostname = ${VPNHOST}/" \
-e 's/^inet_interfaces =.*$/inet_interfaces = loopback-only/' \
-i.original /etc/postfix/main.cf

echo "root: ${EMAIL}
${LOGINUSERNAME}: ${EMAIL}
" >> /etc/aliases

newaliases
service postfix restart


sed -r \
-e 's|^//\s*"\$\{distro_id\}:\$\{distro_codename\}-updates";$|//        "${distro_id}:${distro_codename}-updates";|' \
-e 's|^//Unattended-Upgrade::MinimalSteps "true";$|Unattended-Upgrade::MinimalSteps "true";|' \
-e 's|^//Unattended-Upgrade::Mail "root";$|Unattended-Upgrade::Mail "root";|' \
-e 's|^//Unattended-Upgrade::Automatic-Reboot "false";$|Unattended-Upgrade::Automatic-Reboot "true";|' \
-e 's|^//Unattended-Upgrade::Automatic-Reboot-Time "02:00";$|Unattended-Upgrade::Automatic-Reboot-Time "03:00";|' \
-i /etc/apt/apt.conf.d/50unattended-upgrades

echo 'APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
' > /etc/apt/apt.conf.d/10periodic

service unattended-upgrades restart


echo
echo "=== Creating Apple .mobileconfig file ==="
echo

echo "<?xml version='1.0' encoding='UTF-8'?>
<!DOCTYPE plist PUBLIC '-//Apple//DTD PLIST 1.0//EN' 'http://www.apple.com/DTDs/PropertyList-1.0.dtd'>
<plist version='1.0'>
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>IKEv2</key>
      <dict>
        <key>AuthenticationMethod</key>
        <string>None</string>
        <key>ChildSecurityAssociationParameters</key>
        <dict>
          <key>EncryptionAlgorithm</key>
          <string>AES-256-GCM</string>
          <key>IntegrityAlgorithm</key>
          <string>SHA2-384</string>
          <key>DiffieHellmanGroup</key>
          <integer>21</integer>
          <key>LifeTimeInMinutes</key>
          <integer>1440</integer>
        </dict>
        <key>DeadPeerDetectionRate</key>
        <string>Medium</string>
        <key>DisableMOBIKE</key>
        <integer>0</integer>
        <key>DisableRedirect</key>
        <integer>0</integer>
        <key>EnableCertificateRevocationCheck</key>
        <integer>0</integer>
        <key>EnablePFS</key>
        <true/>
        <key>ExtendedAuthEnabled</key>
        <true/>
        <key>IKESecurityAssociationParameters</key>
        <dict>
          <key>EncryptionAlgorithm</key>
          <string>AES-256-GCM</string>
          <key>IntegrityAlgorithm</key>
          <string>SHA2-384</string>
          <key>DiffieHellmanGroup</key>
          <integer>21</integer>
          <key>LifeTimeInMinutes</key>
          <integer>1440</integer>
        </dict>
        <key>LocalIdentifier</key>
        <string>${VPNHOST}</string>
        <key>OnDemandEnabled</key>
        <integer>1</integer>
        <key>OnDemandRules</key>
        <array>
          <dict>
            <key>Action</key>
            <string>Connect</string>
          </dict>
        </array>
        <key>RemoteAddress</key>
        <string>${VPNHOST}</string>
        <key>RemoteIdentifier</key>
        <string>${VPNHOST}</string>
        <key>UseConfigurationAttributeInternalIPSubnet</key>
        <integer>0</integer>
      </dict>
      <key>IPv4</key>
      <dict>
        <key>OverridePrimary</key>
        <integer>1</integer>
      </dict>
      <key>PayloadDescription</key>
      <string>Configures VPN settings</string>
      <key>PayloadDisplayName</key>
      <string>VPN</string>
      <key>PayloadIdentifier</key>
      <string>com.apple.vpn.managed.$(uuidgen)</string>
      <key>PayloadType</key>
      <string>com.apple.vpn.managed</string>
      <key>PayloadUUID</key>
      <string>$(uuidgen)</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>Proxies</key>
      <dict>
        <key>HTTPEnable</key>
        <integer>0</integer>
        <key>HTTPSEnable</key>
        <integer>0</integer>
      </dict>
      <key>UserDefinedName</key>
      <string>IKEv2 VPN</string>
      <key>VPNType</key>
      <string>IKEv2</string>
    </dict>
  </array>
  <key>PayloadDisplayName</key>
  <string>IKEv2 VPN configuration</string>
  <key>PayloadIdentifier</key>
  <string>com.mackerron.vpn.$(uuidgen)</string>
  <key>PayloadRemovalDisallowed</key>
  <false/>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>$(uuidgen)</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>
" > vpn.mobileconfig

echo 'Your IKEv2 VPN configuration profile for iOS and macOS is attached. Please double-click to install. You will need your device PIN or password, plus your VPN username and password.
' | mail -s "VPN configuration profile" -A vpn.mobileconfig $EMAIL


# necessary for IKEv2?
# Windows: https://support.microsoft.com/en-us/kb/926179
# HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PolicyAgent += AssumeUDPEncapsulationContextOnSendRule, DWORD = 2

