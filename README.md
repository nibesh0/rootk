# rootk
# VirtualBox Kernel Module Setup and SSH Access

```bash
sudo apt update
sudo apt install build-essential linux-headers-$(uname -r)
sudo /sbin/vboxconfig
sudo /usr/src/vboxhost-$(uname -r)/vboxdrv.sh setup
mkdir ~/certs
cd ~/certs
openssl req -new -x509 -newkey rsa:2048 -keyout MOK.priv -outform DER -out MOK.der -days 36500 -nodes -subj "/CN=VirtualBox Module Signing"
sudo /sbin/vboxconfig
sudo /usr/src/vboxhost-$(uname -r)/vboxdrv.sh setup
scp -i ~/.vagrant.d/insecure_private_key <local_file_path> vagrant@127.0.0.1:<remote_directory>
ssh -i /path/to/private_key vagrant@<IP_ADDRESS>
vagrant ssh
