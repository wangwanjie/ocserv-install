# One-Click Deployment Script for Ocserv

This repository contains a simple script to automate the deployment of Ocserv on CentOS and Ubuntu servers. Ocserv is an SSL VPN server that provides secure access to a network of clients. With this script, you can deploy Ocserv with one click and without any manual intervention required.

## Preview

```
[root@ip-172-26-9-233 ~]# ./ocserv-install.sh 
检查是否安装了 ocserv ...
请选择要执行的功能：
1) 升级 ocserv           5) 配置域名             9) 关闭 ocserv
2) 卸载 ocserv           6) 查看ocserv登录日志  10) 查看 ocserv 状态
3) 添加 ocserv 用户      7) 查看系统日志        11) 退出
4) 移除 ocserv 用户      8) 启动或重启 ocserv
#? 
```

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