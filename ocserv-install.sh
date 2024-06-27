#!/bin/bash

# 判断系统版本，根据不同系统选择不同的安装命令
if grep -qs "centos" /etc/os-release; then
    PKG_MANAGER="yum"
    UPDATE_CMD="$PKG_MANAGER check-update -y"
    INSTALL_CMD="$PKG_MANAGER install -y"
    UPGRADE_CMD="$PKG_MANAGER upgrade -y"
    REMOVE_CMD="$PKG_MANAGER remove -y"
elif grep -qs "ubuntu\|debian" /etc/os-release; then
    PKG_MANAGER="apt"
    UPDATE_CMD="$PKG_MANAGER update -y"
    INSTALL_CMD="$PKG_MANAGER install -y"
    UPGRADE_CMD="$PKG_MANAGER full-upgrade -y"
    REMOVE_CMD="$PKG_MANAGER remove -y"
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

# Detect OS and version, adjust for dependencies and compatibility
os="unknown"
os_version="unknown"
group_name="nogroup"

if grep -qs "ubuntu" /etc/os-release; then
    os="ubuntu"
    os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
    group_name="nogroup"
elif grep -qs "debian" /etc/os-release; then
    os="debian"
    os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
    group_name="nogroup"
elif grep -qs "centos" /etc/os-release; then
    os="centos"
    os_version=$(grep -shoE '[0-9]+' /etc/centos-release | head -1)
    group_name="nobody"
elif grep -qs "fedora" /etc/os-release; then
    os="fedora"
    os_version=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
    group_name="nobody"
else
    echo "This installer seems to be running on an unsupported distribution."
    exit
fi

if [[ "$os" == "ubuntu" && "$os_version" -lt 1804 ]]; then
    echo "Ubuntu 18.04 or higher is required to use this installer."
    exit
fi

if [[ "$os" == "debian" && "$os_version" -lt 9 ]]; then
    echo "Debian 9 or higher is required to use this installer."
    exit
fi

if [[ "$os" == "centos" && "$os_version" -lt 7 ]]; then
    echo "CentOS 7 or higher is required to use this installer."
    exit
fi

# Detect environments where $PATH does not include the sbin directories
if ! grep -q sbin <<<"$PATH"; then
    echo '$PATH does not include sbin. Try using "su -" instead of "su".'
    exit
fi

if [[ "$EUID" -ne 0 ]]; then
    echo "This installer needs to be run with superuser privileges."
    exit
fi

if [[ ! -e /dev/net/tun ]] || ! (exec 7<>/dev/net/tun) 2>/dev/null; then
    echo "The system does not have the TUN device available."
    exit
fi

OCSERV=/etc/ocserv
PORT=443
ipv4_network="192.169.103.0"

# 升级ocserv
function upgradeOcserv() {
    echo "升级 ocserv ..."
    $UPGRADE_CMD ocserv
    echo "ocserv 升级完成！"
}

# 卸载ocserv
function uninstallOcserv() {
    read -p "此操作将会卸载 ocserv 及其所有相关文件和配置，确认执行吗？ [y/n]: " confirm
    if [[ "$confirm" = [yY] ]]; then
        echo "卸载 ocserv ..."
        $REMOVE_CMD ocserv
        rm -rf $OCSERV/
        rm -rf /root/anyconnect
        rm -rf /var/www/html/user
        rm -rf /var/lib/ocserv
        echo "ocserv 卸载完成！"
    else
        echo "已取消操作。"
    fi
}

# 添加用户
function addUser() {
    /root/anyconnect/user_add.sh
}

# 移除用户
function removeUser() {
    /root/anyconnect/user_del.sh
}

# 启动或重启 ocserv
function startOrRestartOcserv() {
    if pgrep "ocserv" >/dev/null; then
        echo "正在重启 ocserv ..."
        systemctl restart ocserv
    else
        echo "正在启动 ocserv ..."
        systemctl start ocserv
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

# 检查并安装 iptables（如果尚未安装）
function install_iptables() {
    if ! command -v iptables &>/dev/null; then
        echo "Installing iptables..."
        if [[ "$os" == "centos" ]]; then
            if [[ "$os_version" -eq "8" ]]; then
                dnf install -y iptables-services
                systemctl start iptables
                systemctl enable iptables
            elif [[ "$os_version" -eq "7" ]]; then
                yum install -y iptables-services
                systemctl start iptables
                systemctl enable iptables
            fi
        elif [[ "$os" == "ubuntu" || "$os" == "debian" ]]; then
            apt-get update
            apt-get install -y iptables
            systemctl start netfilter-persistent
            systemctl enable netfilter-persistent
        else
            echo "Unsupported OS type."
            exit 1
        fi
    fi
}

# 配置 ipv4防火墙
function configIpv4Firewall() {
    echo "配置 ipv4防火墙 ..."
    echo "net.ipv4.ip_forward = 1" | tee /etc/sysctl.d/60-custom.conf

    read -p "是否开启bbr？ [y/n]: " confirm
    if [[ "$confirm" = [yY] ]]; then
        if [[ "$os" == "centos" ]]; then
            if [[ "$os_version" -eq "8" ]]; then
                echo "net.core.default_qdisc=fq" | tee -a /etc/sysctl.d/60-custom.conf
                echo "net.ipv4.tcp_congestion_control=bbr" | tee -a /etc/sysctl.d/60-custom.conf
            elif [[ "$os_version" -eq "7" ]]; then
                rpm --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org
                rpm -Uvh https://www.elrepo.org/elrepo-release-7.0-3.el7.elrepo.noarch.rpm
                yum --enablerepo=elrepo-kernel install kernel-ml -y
                # egrep ^menuentry /etc/grub2.cfg | cut -f 2 -d \'
                # grub2-set-default 0
                # grub2-mkconfig -o /boot/grub2/grub.cfg
            fi
        elif [[ "$os" == "ubuntu" ]]; then
            echo "net.core.default_qdisc=fq" | tee -a /etc/sysctl.d/60-custom.conf
            echo "net.ipv4.tcp_congestion_control=bbr" | tee -a /etc/sysctl.d/60-custom.conf
        elif [[ "$os" == "debian" ]]; then
            echo "net.core.default_qdisc=fq" | tee -a /etc/sysctl.d/60-custom.conf
            echo "net.ipv4.tcp_congestion_control=bbr" | tee -a /etc/sysctl.d/60-custom.conf
        else
            echo "Unsupported OS type."
            exit 1
        fi
    else
        echo "不安装bbr"
    fi

    sysctl -p /etc/sysctl.d/60-custom.conf

    # 获取默认网卡名称
    default_interface=$(ip route show | sed -n 's/^default.* dev \([^ ]*\).*/\1/p')

    # 检查是否成功获取网卡名称
    if [ -z "$default_interface" ]; then
        echo "无法获取默认网络接口。本脚本不支持当前系统配置。"
        exit 1
    fi

    echo "使用默认网络接口：$default_interface"

    # 检查并安装 iptables（如果尚未安装）
    install_iptables

    # 配置防火墙规则
    echo "配置 iptables 防火墙规则..."
    iptables -A INPUT -p tcp --dport $PORT -j ACCEPT
    iptables -A INPUT -p udp --dport $PORT -j ACCEPT
    iptables -A INPUT -p tcp --dport 80 -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    iptables -t nat -A POSTROUTING -s ${ipv4_network}/24 -o $default_interface -j MASQUERADE
    iptables -A FORWARD -s ${ipv4_network}/24 -j ACCEPT
    iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT

    # 保存 iptables 规则
    if [[ "$os" == "ubuntu" || "$os" == "debian" ]]; then
        netfilter-persistent save
    elif [[ "$os" == "centos" ]]; then
        iptables-save >/etc/sysconfig/iptables
    else
        iptables-save >/etc/iptables/rules.v4
    fi

    echo "IPv4 防火墙配置完成，iptables 规则已设置。"

}

function prepare() {
    if [[ "$os" == "centos" && "$os_version" -ge 8 ]]; then
        # CentOS 8 和 CentOS Stream 的处理逻辑
        dnf install epel-release -y
        dnf install wget expect ocserv gnutls-utils -y
    elif [[ "$os" == "centos" && "$os_version" -eq 7 ]]; then
        # CentOS 7 的处理逻辑
        yum install epel-release -y
        yum install wget expect ocserv gnutls-utils -y
    elif [[ "$os" == "ubuntu" ]]; then
        # Ubuntu 的处理逻辑
        apt update
        apt install wget expect ocserv gnutls-bin -y
    elif [[ "$os" == "debian" ]]; then
        # debian 的处理逻辑
        apt update
        apt install wget expect ocserv gnutls-bin -y
    else
        echo "Unsupported OS type."
        exit 1
    fi

    # 公共逻辑
    get_public_ip=$(curl -s http://ip1.dynupdate.no-ip.com/ || curl -s http://icanhazip.com/)
    read -p "Public IPv4 address / hostname [$get_public_ip]: " public_ip
    public_ip=${public_ip:-$get_public_ip}
    echo "公网 IP: $public_ip"

    echo "ccccc:$OCSERV"

    # 证书和配置文件的准备工作
    mkdir -p $OCSERV/{pki,user,config-per-group,config-per-user,defaults,tmpl,pem}
    mkdir -p /root/anyconnect

    remote_repo=https://raw.githubusercontent.com/wangwanjie/ocserv-install
    remote_repo_branch=master

    # 从远程仓库下载配置文件和脚本
    wget --no-check-certificate "$remote_repo/$remote_repo_branch/ocserv.conf" -O $OCSERV/ocserv.conf
    wget --no-check-certificate "$remote_repo/$remote_repo_branch/connect-script" -O $OCSERV/connect-script
    wget --no-check-certificate "$remote_repo/$remote_repo_branch/config-per-group/main" -O $OCSERV/config-per-group/main
    wget --no-check-certificate "$remote_repo/$remote_repo_branch/config-per-group/others" -O $OCSERV/config-per-group/others
    chmod +x $OCSERV/connect-script

    # 下载和准备客户端证书生成脚本
    wget --no-check-certificate "$remote_repo/$remote_repo_branch/gen-client-cert.sh" -O /root/anyconnect/gen-client-cert.sh
    wget --no-check-certificate "$remote_repo/$remote_repo_branch/user_add.sh" -O /root/anyconnect/user_add.sh
    wget --no-check-certificate "$remote_repo/$remote_repo_branch/user_del.sh" -O /root/anyconnect/user_del.sh
    chmod +x /root/anyconnect/{gen-client-cert.sh,user_add.sh,user_del.sh}

    # 证书签发组织和有效期的配置
    read -p "请输入证书签发组织名称 [vanjay.cn]: " sign_org
    sign_org=${sign_org:-"vanjay.cn"}
    read -p "请输入证书有效期(天) [3650]: " cert_valid_days
    cert_valid_days=${cert_valid_days:-3650}

    # 创建 CA 和服务器证书模板
    cat >$OCSERV/tmpl/ca.tmpl <<EOF
cn = "VanJay AnyConnect CA"
organization = "$sign_org"
serial = 1
expiration_days = $cert_valid_days
ca
signing_key
cert_signing_key
crl_signing_key
EOF

    cat >$OCSERV/tmpl/server.tmpl <<EOF
cn = "VanJay AnyConnect CA"
organization = "$sign_org"
serial = 2
expiration_days = $cert_valid_days
encryption_key
signing_key
tls_www_server
EOF

    cat >$OCSERV/tmpl/crl.tmpl <<EOF
crl_next_update = 365
crl_number = 1
EOF
}

function configDomain() {
    echo "请选择使用的 DNS 验证服务："
    select dns_provider in "Ali" "Cloudflare"; do
        case $dns_provider in
        "Ali")
            read -p "请输入 VPN 域名！(默认为 tz.vanjay.cn): " domain_name
            if [ -z "$domain_name" ]; then
                domain_name="tz.vanjay.cn"
            fi

            read -p "请输入您的 Email！(默认为 396736694@qq.com): " mail_address
            if [ -z "$mail_address" ]; then
                mail_address="396736694@qq.com"
            fi

            read -p "请输入 ali_key: " ali_key
            while [ -z "$ali_key" ]; do
                echo "无效的 ali_key，请重新输入："
                read -p "请输入 ali_key: " ali_key
            done

            read -p "请输入 ali_secret: " ali_secret
            while [ -z "$ali_secret" ]; do
                echo "无效的 ali_secret，请重新输入："
                read -p "请输入 ali_secret: " ali_secret
            done

            export Ali_Key=$ali_key
            export Ali_Secret=$ali_secret
            dns_mode="dns_ali"
            break
            ;;
        "Cloudflare")
            read -p "请输入 VPN 域名！(默认为 tz.beautyy.uk): " domain_name
            if [ -z "$domain_name" ]; then
                domain_name="tz.beautyy.uk"
            fi

            read -p "请输入您的 Email！(默认为 vanjay.dev@gmail.com): " mail_address
            if [ -z "$mail_address" ]; then
                mail_address="vanjay.dev@gmail.com"
            fi

            read -p "请输入 Cloudflare Email: " cf_email
            while [ -z "$cf_email" ]; do
                echo "无效的 Cloudflare Email，请重新输入："
                read -p "请输入 Cloudflare Email: " cf_email
            done

            read -p "请输入 Cloudflare API Key: " cf_key
            while [ -z "$cf_key" ]; do
                echo "无效的 Cloudflare API Key，请重新输入："
                read -p "请输入 Cloudflare API Key: " cf_key
            done

            export CF_Email=$cf_email
            export CF_Key=$cf_key
            dns_mode="dns_cf"
            break
            ;;
        *)
            echo "选择无效，请选择 'Ali' 或 'Cloudflare'."
            ;;
        esac
    done

    # 安装 socat
    $INSTALL_CMD socat || {
        echo "安装 socat 失败，脚本终止。"
        exit 1
    }

    # 安装并初始化 acme.sh
    curl https://get.acme.sh | sh && source "$HOME/.acme.sh/acme.sh.env" || {
        echo "安装 acme.sh 失败，脚本终止。"
        exit 1
    }

    export PATH="$PATH:$HOME/.acme.sh"
    alias acme.sh=~/.acme.sh/acme.sh

    # 注册 acme.sh 账户
    acme.sh --register-account -m "$mail_address" --server zerossl || {
        echo "注册 acme.sh 账户失败，脚本终止。"
        exit 1
    }

    # 生成证书
    acme.sh --issue --dns "$dns_mode" -d "$domain_name" || {
        echo "证书生成失败，脚本终止。"
        exit 1
    }

    # 确保创建证书存放目录
    mkdir -p "$OCSERV/pki" || {
        echo "创建证书存放目录失败，脚本终止。"
        exit 1
    }

    # 拷贝证书到指定目录
    cp -Rf "$HOME/.acme.sh/${domain_name}_ecc/" "$OCSERV/pki/" || {
        echo "拷贝证书失败，脚本终止。"
        exit 1
    }

    # 设置证书路径
    cer_path="$OCSERV/pki/${domain_name}_ecc/${domain_name}.cer"
    key_path="$OCSERV/pki/${domain_name}_ecc/${domain_name}.key"

    # 更新 ocserv 配置文件
    sed -i "s#\(server-cert = \).*#\1$cer_path#" "$OCSERV/ocserv.conf" || {
        echo "更新 server-cert 配置失败，脚本终止。"
        exit 1
    }
    sed -i "s#\(server-key = \).*#\1$key_path#" "$OCSERV/ocserv.conf" || {
        echo "更新 server-key 配置失败，脚本终止。"
        exit 1
    }
    sed -i "s#\(default-domain = \).*#\1$domain_name#" "$OCSERV/ocserv.conf" || {
        echo "更新 default-domain 配置失败，脚本终止。"
        exit 1
    }

    # 启动或重启 ocserv
    if startOrRestartOcserv; then
        echo "已修改 ocserv.conf，已重启 ocserv 服务"
    else
        echo "启动或重启 ocserv 服务失败，脚本终止。"
        exit 1
    fi

}

function generate_server_cert() {
    cd $OCSERV/pem
    # 生成 CA 证书
    certtool --generate-privkey --outfile ca-key.pem

    certtool --generate-self-signed --load-privkey ca-key.pem --template $OCSERV/tmpl/ca.tmpl --outfile ca-cert.pem

    # 生成服务器私钥
    certtool --generate-privkey --outfile server-key.pem

    # 生成服务器证书
    certtool --generate-certificate --load-privkey server-key.pem \
        --load-ca-certificate ca-cert.pem --load-ca-privkey ca-key.pem \
        --template $OCSERV/tmpl/server.tmpl --outfile server-cert.pem

    # 生成证书注销列表文件
    touch revoked.pem

    certtool --generate-crl --load-ca-privkey ca-key.pem \
        --load-ca-certificate ca-cert.pem \
        --template $OCSERV/tmpl/crl.tmpl --outfile crl.pem
}

function useSystemDNS() {
    # 删除 ocserv.conf 中所有现有的 DNS 设置
    sed -i -e "/^#*\s*dns\s*=.*$/d" $OCSERV/ocserv.conf

    # 根据系统配置选择正确的 resolv.conf 文件
    if grep '^nameserver' "/etc/resolv.conf" | grep -qv '127.0.0.53'; then
        resolv_conf="/etc/resolv.conf"
    else
        resolv_conf="/run/systemd/resolve/resolv.conf"
    fi

    # 从 resolv.conf 文件中获取 DNS 设置，并添加到 ocserv.conf
    grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | while read line; do
        echo "dns = $line" >>$OCSERV/ocserv.conf
    done
}

function useOtherDNS() {
    # 先删除所有现有的 DNS 设置
    sed -i -e "/^#*\s*dns\s*=.*$/d" $OCSERV/ocserv.conf

    # 添加新的 DNS 服务器地址
    echo "dns = $1" >>$OCSERV/ocserv.conf
    echo "dns = $2" >>$OCSERV/ocserv.conf
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
        "Current system resolvers")
            useSystemDNS
            break
            ;;
        "Google")
            useOtherDNS 8.8.8.8 8.8.4.4
            break
            ;;
        "1.1.1.1")
            useOtherDNS 1.1.1.1 1.0.0.1
            break
            ;;
        "Google & 1.1.1.1")
            useOtherDNS 1.1.1.1 8.8.8.8
            break
            ;;
        "OpenDNS")
            useOtherDNS 208.67.222.222 208.67.220.220
            break
            ;;
        "Quad9")
            useOtherDNS 9.9.9.9 149.112.112.112
            break
            ;;
        "AdGuard")
            useOtherDNS 94.140.14.14 94.140.15.15
            break
            ;;
        esac
    done

    until [[ $valid_ip == true ]]; do
        read -p "请输入 ipv4_network [192.168.103.0]: " ipv4_network

        [[ -z "$ipv4_network" ]] && ipv4_network="192.168.103.0"

        valid_ip=true
        IFS='.' read -ra ip_array <<<"$ipv4_network"
        if [[ ${#ip_array[@]} -ne 4 ]]; then
            valid_ip=false
        else
            for ((i = 0; i < ${#ip_array[@]}; i++)); do
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
        yes)
            systemctl enable ocserv
            break
            ;;
        no) break ;;
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
        安装) break ;;
        退出) exit ;;
        esac
    done

    # 根据系统使用合适的安装命令
    if [[ $PKG_MANAGER == "yum" ]]; then
        $PKG_MANAGER -y upgrade
        $PKG_MANAGER -y install epel-release
        $PKG_MANAGER -y install ocserv
    else
        $PKG_MANAGER install wget -y
        $PKG_MANAGER -y update
        $PKG_MANAGER install epel-release wget -y
        $PKG_MANAGER install ocserv -y
    fi

    prepare
    generate_server_cert
    configOcserv
    configIpv4Firewall
    enableAutoStart

    # 创建ocserv运行所需的用户和组，如果不存在的话
    if ! id "ocserv" &>/dev/null; then
        echo "Creating 'ocserv' user and group..."
        adduser --system --no-create-home --group ocserv
    fi

    # 确保配置文件和目录的权限正确
    echo "设置配置文件权限..."

    chown -R ocserv:ocserv /etc/ocserv
    chmod -R 640 /etc/ocserv/ocserv.conf

    mkdir -p /var/lib/ocserv

    echo "ocserv 安装完成！"
else
    # 主程序
    echo "请选择要执行的功能："
    select FUNC in "升级 ocserv" "卸载 ocserv" "添加 ocserv 用户" "移除 ocserv 用户" "配置域名" "查看ocserv登录日志" "查看系统日志" "启动或重启 ocserv" "关闭 ocserv" "查看 ocserv 状态" "退出"; do
        case $FUNC in
        "升级 ocserv")
            upgradeOcserv
            break
            ;;
        "卸载 ocserv")
            uninstallOcserv
            break
            ;;
        "添加 ocserv 用户")
            addUser
            break
            ;;
        "移除 ocserv 用户")
            removeUser
            break
            ;;
        "配置域名")
            configDomain
            break
            ;;
        "查看ocserv登录日志")
            logOcserv
            break
            ;;
        "查看系统日志")
            logSystem
            break
            ;;
        "启动或重启 ocserv")
            startOrRestartOcserv
            break
            ;;
        "关闭 ocserv")
            stopOcserv
            break
            ;;
        "查看 ocserv 状态")
            statusOcserv
            break
            ;;
        "退出") exit ;;
        esac
    done
fi

echo "ocserv 脚本运行结束！"
echo "再次运行此脚本可选择功能！"
