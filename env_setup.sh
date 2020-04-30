#!/usr/bin/env bash

cwd="$(dirname "$0")"
cd "$cwd"

set -ex

VAGRANT_CWD="$(pwd)"
export VAGRANT_CWD

if [[ -f Vagrantfile ]]; then
    vagrant destroy -f
    rm Vagrantfile
fi

cat <<EOD > Vagrantfile
Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/bionic64"
  config.vm.synced_folder "$GOPATH/src/github.com/Gui774ume/network-security-probe", "/home/vagrant/go/src/github.com/Gui774ume/network-security-probe"
end
EOD

vagrant up

echo "Installing tools (invoke, clang format, jq, vim, libbcc, linux-source)"
cat <<EOD | vagrant ssh
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 4052245BD4284CDD
echo "deb https://repo.iovisor.org/apt/bionic bionic main" | sudo tee /etc/apt/sources.list.d/iovisor.list
sudo apt-get update
sudo apt-get install -y python-pip unzip curl jq vim clang-format httpie git libbcc linux-tools-4.15.0-54-generic --fix-missing
sudo pip install invoke pyyaml
curl -Lo minikube https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64 && chmod +x minikube
sudo mkdir -p /usr/local/bin/
sudo install minikube /usr/local/bin/
EOD

echo "Installing golang"
cat <<EOD | vagrant ssh
wget -qO- https://dl.google.com/go/go1.13.5.linux-amd64.tar.gz | sudo tar -zxf - -C /usr/local
EOD

echo "Installing clang and LLVM v8"
cat <<EOD | vagrant ssh
wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -
echo "deb http://apt.llvm.org/bionic/ llvm-toolchain-bionic-8 main" | sudo tee -a /etc/apt/sources.list
echo "deb-src http://apt.llvm.org/bionic/ llvm-toolchain-bionic-8 main" | sudo tee -a /etc/apt/sources.list
sudo apt-get update
sudo apt-get install -y clang-8 llvm-8
sudo ln -sf /usr/bin/clang-8 /usr/bin/clang
sudo ln -sf /usr/bin/llc-8 /usr/bin/llc
EOD

echo "Installing linux-headers"
cat <<EOD | vagrant ssh
sudo apt-get install -y linux-headers-\$(uname -r)
EOD

echo "Installing docker"
cat <<EOD | vagrant ssh
sudo apt-get install -y apt-transport-https ca-certificates curl software-properties-common ruby mercurial
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
echo "deb https://download.docker.com/linux/ubuntu bionic stable" | sudo tee -a /etc/apt/sources.list
sudo apt-get update
sudo apt-get install -y docker-ce
sudo groupadd docker
sudo usermod -aG docker vagrant
sudo service docker start
sudo curl -L "https://github.com/docker/compose/releases/download/1.25.3/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
EOD

vagrant reload

echo "Installing helm"
cat <<EOD | vagrant ssh
curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/master/scripts/get-helm-3
chmod 700 get_helm.sh
./get_helm.sh
EOD

echo "Configuring env variables"
cat <<EOD | vagrant ssh
echo 'export GOROOT=/usr/local/go' >> ~/.bashrc
echo 'export GOPATH=/home/vagrant/go' >> ~/.bashrc
echo 'export PATH=/opt/go/bin:/home/vagrant/go/bin:/usr/local/go/bin:$PATH' >> ~/.bashrc
EOD

echo "Fixing permissions"
cat <<EOD | vagrant ssh
sudo chown vagrant /home/vagrant/go
sudo chown vagrant /home/vagrant/go/src/
sudo chown vagrant /home/vagrant/go/src/gitlab.com
EOD

echo "Add veth module"
cat <<EOD | vagrant ssh
sudo modprobe veth
EOD

vagrant reload
