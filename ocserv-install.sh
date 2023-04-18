#!/bin/bash

# 判断系统版本，根据不同系统选择不同的安装命令
if cat /etc/os-release | grep -q "centos"; then
    PKG_MANAGER="yum"
elif cat /etc/os-release | grep -q "ubuntu\|debian"; then
    PKG_MANAGER="apt-get"
else
    echo "当前系统不受支持！"
    exit 1
fi

# Detect Debian users running the script with "sh" instead of bash
if readlink /proc/$$/exe | grep -q "dash"; then
	echo 'This installer needs to be run with "bash", not "sh".'
	exit
fi

# Discard stdin. Needed when running from an one-liner which includes a newline
read -N 999999 -t 0.001

# Detect OpenVZ 6
if [[ $(uname -r | cut -d "." -f 1) -eq 2 ]]; then
	echo "The system is running an old kernel, which is incompatible with this installer."
	exit
fi

# Detect OS
# $os_version variables aren't always in use, but are kept here for convenience
if grep -qs "ubuntu" /etc/os-release; then
	os="ubuntu"
	os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
	group_name="nogroup"
elif [[ -e /etc/debian_version ]]; then
	os="debian"
	os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
	group_name="nogroup"
elif [[ -e /etc/almalinux-release || -e /etc/rocky-release || -e /etc/centos-release ]]; then
	os="centos"
	os_version=$(grep -shoE '[0-9]+' /etc/almalinux-release /etc/rocky-release /etc/centos-release | head -1)
	group_name="nobody"
elif [[ -e /etc/fedora-release ]]; then
	os="fedora"
	os_version=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
	group_name="nobody"
else
	echo "This installer seems to be running on an unsupported distribution.
Supported distros are Ubuntu, Debian, AlmaLinux, Rocky Linux, CentOS and Fedora."
	exit
fi

if [[ "$os" == "ubuntu" && "$os_version" -lt 1804 ]]; then
	echo "Ubuntu 18.04 or higher is required to use this installer.
This version of Ubuntu is too old and unsupported."
	exit
fi

if [[ "$os" == "debian" && "$os_version" -lt 9 ]]; then
	echo "Debian 9 or higher is required to use this installer.
This version of Debian is too old and unsupported."
	exit
fi

if [[ "$os" == "centos" && "$os_version" -lt 7 ]]; then
	echo "CentOS 7 or higher is required to use this installer.
This version of CentOS is too old and unsupported."
	exit
fi

# Detect environments where $PATH does not include the sbin directories
if ! grep -q sbin <<< "$PATH"; then
	echo '$PATH does not include sbin. Try using "su -" instead of "su".'
	exit
fi

if [[ "$EUID" -ne 0 ]]; then
	echo "This installer needs to be run with superuser privileges."
	exit
fi

if [[ ! -e /dev/net/tun ]] || ! ( exec 7<>/dev/net/tun ) 2>/dev/null; then
	echo "The system does not have the TUN device available.
TUN needs to be enabled before running this installer."
	exit
fi

OCSERV=/etc/ocserv
PORT=443
ipv4_network="192.169.103.0"

# 升级ocserv
function upgradeOcserv() {
    echo "升级 ocserv ..."

    # 根据系统使用合适的更新命令
    if [[ $PKG_MANAGER == "yum" ]]; then
        $PKG_MANAGER -y upgrade ocserv
    else
        $PKG_MANAGER -y upgrade
        $PKG_MANAGER -y install ocserv
    fi

    echo "ocserv 升级完成！"
}

# 卸载ocserv
function uninstallOcserv() {
     read -p "此操作将会卸载 ocserv 及其所有相关文件和配置，确认执行吗？ [y/n]: " confirm
    if [[ "$confirm" = [yY] ]]; then
        echo "卸载 ocserv ..."
        $PKG_MANAGER -y remove ocserv
        rm -rf $OCSERV/
        rm -rf /root/anyconnect
        rm -rf /var/www/html/user
        echo "ocserv 卸载完成！"
    else
        echo "已取消操作。"
    fi
}

# 添加用户
function addUser() {
    sudo /root/anyconnect/user_add.sh
}

# 移除用户
function removeUser() {
    sudo /root/anyconnect/user_del.sh
}

# 启动或重启 ocserv
function startOrOcserv() {
    if pgrep "ocserv" > /dev/null ; then
        echo "正在重启 ocserv ..."
        systemctl restart ocserv
    else 
        echo "正在启动 ocserv ..."
        systemctl start ocserv
    fi
    if pgrep "httpd" > /dev/null ; then
        echo "正在重启 httpd ..."
        sudo systemctl restart httpd
    else 
        echo "正在启动 httpd ..."
        sudo systemctl start httpd
    fi
}

# 关闭 ocserv
function stopOcserv() {
    echo "正在关闭 ocserv ..."
    systemctl stop ocserv
}

# 查看ocserv状态
function statusOcserv() {
    systemctl status ocserv
}

# 配置 ipv4防火墙
function configIpv4Firewall() {
    echo "配置 ipv4防火墙 ..."
    echo "net.ipv4.ip_forward = 1" | sudo tee /etc/sysctl.d/60-custom.conf
    echo "net.core.default_qdisc=fq" | sudo tee -a /etc/sysctl.d/60-custom.conf
    echo "net.ipv4.tcp_congestion_control=bbr" | sudo tee -a /etc/sysctl.d/60-custom.conf
    sudo sysctl -p /etc/sysctl.d/60-custom.conf

    sudo systemctl start firewalld
    sudo firewall-cmd --permanent --add-port=$PORT/tcp
    sudo firewall-cmd --permanent --add-port=$PORT/udp
    sudo firewall-cmd --permanent --add-port=80/tcp
    sudo firewall-cmd --permanent --add-service=https

    sudo firewall-cmd --permanent --add-rich-rule="rule family='ipv4' source address='${vpnnetwork}/24' masquerade"
    sudo systemctl reload firewalld

    echo "配置 ipv4防火墙结束，已重启防火墙"
}

function prepare() {
    cd /etc/yum.repos.d/
    sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-*
    sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*
    wget -O /etc/yum.repos.d/CentOS-Base.repo https://mirrors.aliyun.com/repo/Centos-vault-8.5.2111.repo
    yum clean all
    yum makecache

    sudo yum install wget -y
    sudo yum install dnf -y
    sudo yum install expect -y

    sudo dnf install httpd -y
    sudo systemctl enable httpd

    sudo dnf install epel-release -y
    sudo yum install -y gnutls-utils
    sudo dnf install ocserv -y

    get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" || curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")")
    read -p "Public IPv4 address / hostname [$get_public_ip]: " public_ip
    # If the checkip service is unavailable and user didn't provide input, ask again
    until [[ -n "$get_public_ip" || -n "$public_ip" ]]; do
        echo "Invalid input."
        read -p "Public IPv4 address / hostname: " public_ip
    done
    [[ -z "$public_ip" ]] && public_ip="$get_public_ip"

    echo "公网 IP:$public_ip"

    cd $OCSERV
    mkdir -p pki user config-per-group config-per-user defaults tmpl pem
    mkdir -p /root/anyconnect
   
    remote_repo=https://raw.githubusercontent.com/wangwanjie/ocserv-install
    remote_repo_branch=master

    rm -rf ocserv.conf connect-script config-per-group/* tmpl/* pem/*

    wget --no-check-certificate $remote_repo/$remote_repo_branch/ocserv.conf
    wget --no-check-certificate $remote_repo/$remote_repo_branch/connect-script
    wget --no-check-certificate $remote_repo/$remote_repo_branch/config-per-group/main -O config-per-group/main
    wget --no-check-certificate $remote_repo/$remote_repo_branch/config-per-group/others -O config-per-group/others
    chmod +x connect-script

    cd /root/anyconnect
    wget --no-check-certificate $remote_repo/$remote_repo_branch/gen-client-cert.sh
    wget --no-check-certificate $remote_repo/$remote_repo_branch/user_add.sh
    wget --no-check-certificate $remote_repo/$remote_repo_branch/user_del.sh
    chmod +x gen-client-cert.sh
    chmod +x user_add.sh
    chmod +x user_del.sh

    cd $OCSERV/tmpl
cat >ca.tmpl <<EOF
cn = "VanJay AnyConnect CA"
organization = "vanjay.cn"
serial = 1
expiration_days = 3650
ca
signing_key
cert_signing_key
crl_signing_key
EOF

cat >server.tmpl <<EOF
cn = "VanJay AnyConnect CA"
organization = "vanjay.cn"
serial = 2
expiration_days = 3650
encryption_key
signing_key
tls_www_server
EOF

cat << _EOF_ >crl.tmpl
crl_next_update = 365
crl_number = 1
_EOF_
}

function configDomain() {
    read -p "请输入 VPN 域名！(默认为 tz.vanjay.cn): " domain_name
    if [ -z "$domain_name" ]; then
        domain_name="tz.vanjay.cn"
    fi

    read -p "请输入您的 Email！(默认为 396736694@qq.com): " mail_address
    if [ -z "$mail_address" ]; then
        mail_address="396736694@qq.com"
    fi

    while true; do
        read -p "请输入ali_key: " ali_key
        if [[ -n "$ali_key" ]]; then
            break
        else
            echo "无效的 ali_key"
        fi
    done

    while true; do
        read -p "请输入ali_secret: " ali_secret
        if [[ -n "$ali_secret" ]]; then
            break
        else
            echo "无效的 ali_secret"
        fi
    done

    export Ali_Key=$ali_key
    export Ali_Secret=$ali_secret

    yum install socat -y

    curl https://get.acme.sh | sh
    export PATH="$PATH:$HOME/.acme.sh"
    alias acme.sh=~/.acme.sh/acme.sh
    acme.sh  --register-account  -m $mail_address --server zerossl
    acme.sh --issue --dns dns_ali -d $domain_name
    mkdir -p $OCSERV/pki

    cp -Rf ~/.acme.sh/${domain_name}_ecc/ $OCSERV/pki

    cer_path=$OCSERV/pki/${domain_name}_ecc/${domain_name}.cer
    key_path=$OCSERV/pki/${domain_name}_ecc/${domain_name}.key

    # 更新 ocserv.conf 文件
    sed -i "s#\(server-cert = \).*#\1$cer_path#" $OCSERV/ocserv.conf
    sed -i "s#\(server-key = \).*#\1$key_path#" $OCSERV/ocserv.conf
    sed -i "s#\(default-domain = \).*#\1$domain_name#" $OCSERV/ocserv.conf

    startOrRestartOcserv

    echo "已修改 ocserv.conf，已重启 ocserv 服务"
} 

function generate_server_cert() {
    cd $OCSERV/pem
    # 生成 CA 证书
    certtool --generate-privkey --outfile ca-key.pem

    certtool --generate-self-signed --load-privkey ca-key.pem --template $OCSERV/tmpl/ca.tmpl --outfile ca-cert.pem

    # 生成本地服务器证书
    certtool --generate-privkey --outfile server-key.pem

    certtool --generate-certificate --load-privkey server-key.pem \
    --load-ca-certificate ca-cert.pem --load-ca-privkey ca-key.pem \
    --template $OCSERV/tmpl/server.tmpl --outfile server-cert.pem

    # 生成证书注销文件
    touch $OCSERV/pem/revoked.pem

    certtool --generate-crl --load-ca-privkey ca-key.pem \
            --load-ca-certificate ca-cert.pem \
            --template $OCSERV/tmpl/crl.tmpl --outfile crl.pem
}

function useSystemDNS() {
    sed -i -e "/^#*\s*dns\s*=.*$/d" $OCSERV/ocserv.conf

    # Locate the proper resolv.conf
    # Needed for systems running systemd-resolved
    if grep '^nameserver' "/etc/resolv.conf" | grep -qv '127.0.0.53' ; then
        resolv_conf="/etc/resolv.conf"
    else
        resolv_conf="/run/systemd/resolve/resolv.conf"
    fi
    # Obtain the resolvers from resolv.conf and use them for OpenVPN
    grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | grep -v '127.0.0.53' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | while read line; do
        echo "\ndns = $line" >> $OCSERV/ocserv.conf
    done
}

function useOtherDNS() {
    sed -i "s|dns = 1.1.1.1|dns = $1|g" $OCSERV/ocserv.conf
    sed -i "s|dns = 8.8.8.8 # the second|dns = $2|g" $OCSERV/ocserv.conf
}

# 配置 ocserv.conf
function configOcserv() {
    read -p "请输入要监听的端口号（推荐使用80或443或10443）[443]: " PORT
    until [[ -z "$PORT" || "$PORT" =~ ^[0-9]+$ && "$PORT" -le 65535 ]]; do
		echo "$PORT: invalid port."
		read -p "Port [443]: " PORT
	done
	[[ -z "$PORT" ]] && PORT="443"

    echo "请选择DNS："
    select FUNC in "Current system resolvers" "Google" "1.1.1.1" "Google & 1.1.1.1" "OpenDNS" "Quad9" "AdGuard"; do
        case $FUNC in
            "Current system resolvers" ) useSystemDNS; break;;
            "Google" ) useOtherDNS 8.8.8.8 8.8.4.4; break;;
            "1.1.1.1" ) useOtherDNS 1.1.1.1 1.0.0.1; break;;
            "Google & 1.1.1.1" ) useOtherDNS 1.1.1.1 8.8.8.8; break;;
            "OpenDNS" ) useOtherDNS 208.67.222.222 208.67.220.220; break;;
            "Quad9" ) useOtherDNS 9.9.9.9 149.112.112.112; break;;
            "AdGuard" ) useOtherDNS 94.140.14.14 94.140.15.15; break;;
        esac
    done

    until [[ $valid_ip == true ]]
    do
        read -p "请输入 ipv4_network [192.168.103.0]: " ipv4_network

        [[ -z "$ipv4_network" ]] && ipv4_network="192.168.103.0"

        valid_ip=true
        IFS='.' read -ra ip_array <<< "$ipv4_network"
        if [[ ${#ip_array[@]} -ne 4 ]]; then
            valid_ip=false
        else
            for (( i=0; i<${#ip_array[@]}; i++ ))
            do
                octet=${ip_array[i]}
                if [[ "$i" -eq 0 ]]; then
                    if [[ "$octet" -eq 0 ]]; then
                        echo "$i ----- $octet"
                        valid_ip=false
                        break
                    else
                        # 判断第一个分段是否为1到3位数字，且不能以0开头
                        if [[ ! "$octet" =~ ^[1-9][0-9]{0,2}$ ]]; then
                            valid_ip=false
                            break
                        fi
                    fi
                else
                    # 判断每个分段是否为1到3位数字，可以以0开头
                    if [[ ! "$octet" =~ ^([0-9]|[1-9][0-9]{1,2})$ ]]; then
                        valid_ip=false
                        break
                    elif [[ "$octet" -lt 0 || "$octet" -gt 255 ]]; then
                        valid_ip=false
                        break
                    fi
                fi
            done
        fi

        if [[ $valid_ip == false ]]; then
            echo "输入的IP地址不合法，请重新输入！"
        fi
    done

    sed -i "s|tcp-port = 443|tcp-port = $PORT|g" $OCSERV/ocserv.conf
    sed -i "s|udp-port = 443|udp-port = $PORT|g" $OCSERV/ocserv.conf
    sed -i "s|ipv4-network = 192.168.103.0|ipv4-network = $ipv4_network|g" $OCSERV/ocserv.conf
    if [[ -n "$public_ip" ]]; then
        sed -i "s/47.242.201.43/$public_ip/g" $OCSERV/ocserv.conf
    fi

    echo "ocserv配置修改成功！"
}

# 启用开机自启
function enableAutoStart() {
    echo "是否开启开机自启？（yes或no）"
    select yn in "yes" "no"; do
        case $yn in
            yes ) systemctl enable ocserv; break;;
            no ) break;;
        esac
    done
}

function logOcserv() {
    if [ -f /etc/ocserv/login.log ]; then
        tail -f /etc/ocserv/login.log
    else
        echo "Error: /etc/ocserv/login.log not found!"
    fi 
}

function logSystem() {
     if [ -f /var/log/messages ]; then
        tail -f /var/log/messages
    else
        echo "Error: /var/log/messages not found!"
    fi 
}

# 安装ocserv
echo "检查是否安装了 ocserv ..."

if ! hash ocserv 2>/dev/null; then
    echo "ocserv 未安装！"
    echo "请选择安装 ocserv 或退出:"
    select yn in "安装" "退出"; do
        case $yn in
            安装 ) break;;
            退出 ) exit;;
        esac
    done

    # 根据系统使用合适的安装命令
    if [[ $PKG_MANAGER == "yum" ]]; then
        $PKG_MANAGER -y upgrade
        $PKG_MANAGER -y install epel-release
        $PKG_MANAGER -y install ocserv
    else
        sudo -i 
        $PKG_MANAGER install wget -y 
        $PKG_MANAGER -y update
        $PKG_MANAGER install epel-release wget -y
        $PKG_MANAGER install ocserv httpd -y
    fi

    prepare
    generate_server_cert
    configOcserv
    configIpv4Firewall
    enableAutoStart

    echo "ocserv 安装完成！"
else
    # 主程序
    echo "请选择要执行的功能："
    select FUNC in "升级 ocserv" "卸载 ocserv" "添加 ocserv 用户" "移除 ocserv 用户" "配置域名" "查看ocserv登录日志" "查看系统日志" "启动或重启 ocserv" "关闭 ocserv" "查看 ocserv 状态" "退出"; do
        case $FUNC in
            "升级 ocserv" ) upgradeOcserv; break;;
            "卸载 ocserv" ) uninstallOcserv; break;;
            "添加 ocserv 用户" ) addUser; break;;
            "移除 ocserv 用户" ) removeUser; break;;
            "配置域名" ) configDomain; break;;
            "查看ocserv登录日志" ) logOcserv; break;;
            "查看系统日志" ) logSystem; break;;
            "启动或重启 ocserv" ) startOrRestartOcserv; break;;
            "关闭 ocserv" ) stopOcserv; break;;
            "查看 ocserv 状态" ) statusOcserv; break;;
            "退出" ) exit;;
        esac
    done
fi

echo "ocserv 脚本运行结束！"
echo "再次运行此脚本可选择功能！"
