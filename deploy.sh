# Install python

sudo apt-get update
sudo apt-get install python3
sudo apt-get install python3-pip

# Install libraries
sudo pip3 install pycryptodome
sudo pip3 install interfaces

cd ..

# Removing unused folder
sudo rm -rf mininet

sudo apt-get install openvswitch-switch
sudo apt-get install openvswitch-testcontroller
sudo ln /usr/bin/ovs-testcontroller /usr/bin/controller 

killall ovs-testcontroller

# Cloning the database
git clone https://github.com/mininet/mininet.git

# Installing the mininet globally
sudo PYTHON=python3 mininet/util/install.sh -a

# Running the VPLS emulated environment
cd hip-vpls-routing
sudo python3 l3-vpn-mn.py
