#!/bin/bash -e

# github.com/jawj/IKEv2-setup
# Copyright (c) 2015 – 2021 George MacKerron
# Released under the MIT licence: http://opensource.org/licenses/mit-license

echo
echo "There's a Windows 10 bug where rasdial.exe fails to download root certificates."
echo "That makes VPN connections fail with the message 'IKE authentication credentials are unacceptable'."
echo
echo "The current PowerShell VPN client setup script provided by this project works around the bug on each local Windows 10 machine."
echo "Or you can work around the issue on any existing VPN client simply by visiting https://valid-isrgrootx1.letsencrypt.org in Edge on that machine."
echo
echo "If you have existing clients for which you cannot easily apply that workaround, this script applies a server-side workaround instead."
echo "It forces a different intermediate certificate to be used. This is not recommended, since future changes by Let's Encrypt may break it."
echo
read -r -p "Press [Return] to apply the server-side workaround, which is not recommended, or Ctrl-C to abort"

function exit_badly {
  echo "$1"
  exit 1
}

[[ $(lsb_release -rs) == "18.04" ]] || [[ $(lsb_release -rs) == "20.04" ]] || exit_badly "This script is for Ubuntu 20.04 or 18.04 only: aborting (if you know what you're doing, try deleting this check)"
[[ $(id -u) -eq 0 ]] || exit_badly "Please re-run as root (e.g. sudo ./path/to/this/script)"

export DEBIAN_FRONTEND=noninteractive
apt-get -o Acquire::ForceIPv4=true update
apt-get -o Acquire::ForceIPv4=true install -y curl

curl https://letsencrypt.org/certs/lets-encrypt-r3-cross-signed.pem > /etc/ipsec.d/cacerts/chain.pem
ipsec rereadcacerts

echo "
#!/bin/bash -e
curl https://letsencrypt.org/certs/lets-encrypt-r3-cross-signed.pem > /etc/ipsec.d/cacerts/chain.pem
ipsec rereadcacerts
" > /etc/letsencrypt/renewal-hooks/post/win10fix

chmod +x /etc/letsencrypt/renewal-hooks/post/win10fix
