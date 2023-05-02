# One-Click Deployment Script for Ocserv

This repository contains a simple script to automate the deployment of Ocserv on CentOS and Ubuntu servers. Ocserv is an SSL VPN server that provides secure access to a network of clients. With this script, you can deploy Ocserv with one click and without any manual intervention required.

## Prerequisites

- A fresh installation of CentOS 7/8 or Ubuntu 16.04/18.04/20.04/22.04.
- An internet connection is required to download the necessary packages.

## Installation

 Run this code in your terminal

   ```
sudo -i yum install wget -y && wget https://raw.githubusercontent.com/wangwanjie/ocserv-install/master/ocserv-install.sh && chmod +x ocserv-install.sh && ./ocserv-install.sh
   ```


## References

- [Ocserv Official Website](http://www.infradead.org/ocserv/)
- [OpenConnect VPN Client](http://www.infradead.org/openconnect/)
- [CentOS](https://www.centos.org/)
- [Ubuntu](https://ubuntu.com/)