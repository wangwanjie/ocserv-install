#!/bin/bash

# 这个脚本是用来同时添加 VPN 用户和他们的证书的

# 检查是否使用 root 账户执行脚本
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root."
   exit 1
fi

# 自动检测包管理器并确定 expect 的路径
if [ -x "$(command -v apt)" ]; then
    EXPECT_CMD="/usr/bin/expect"
elif [ -x "$(command -v yum)" ]; then
    EXPECT_CMD="/usr/bin/expect"
else
    EXPECT_CMD="/usr/bin/env expect"
fi

function input_user() {
    # 使用 curl 来获取公网 IP，因为 curl 在大多数 Linux 发行版上都是可用的
    get_public_ip=$(curl -s http://ip1.dynupdate.no-ip.com/)
    public_ip="$get_public_ip"

    # 如果 curl 获取失败，尝试使用另一种方式
    if [[ -z "$public_ip" ]]; then
        public_ip=$(curl -s http://icanhazip.com/)
    fi

    # 从 ocserv.conf 文件中获取 VPN 端口号
    PORT=$(grep ^\s*tcp-port /etc/ocserv/ocserv.conf | awk '{print $NF}')

    # 获取 VPN 用户名和组别
    read -p "请输入您的 VPN 用户名： " user_name
    read -p "请输入您的 VPN 用户组别（默认为 others）： " user_group
    user_group=${user_group:-others}

    read -s -p "请输入您的密码： " user_pass
    echo

    if [[ ! -n "$user_name" || ! -n "$user_pass" ]]; then
        echo "用户名或密码未输入，请重新执行程序"
    else
        user_add
        cert_add
    fi
}

function user_add() {
    sudo touch /etc/ocserv/ocpasswd
    sudo chmod 600 /etc/ocserv/ocpasswd

    $EXPECT_CMD <<-END
    spawn sudo ocpasswd -c /etc/ocserv/ocpasswd -g $user_group $user_name
    expect "Enter password:"
    send "$user_pass\r"
    expect "Re-enter password:"
    send "$user_pass\r"
    expect eof
    exit
END
}

function cert_add() {
    OCSERV=/etc/ocserv
    user_root_dir=$OCSERV/user
    mkdir -p $user_root_dir/$user_name
    cd $user_root_dir/$user_name

    $EXPECT_CMD <<-END
    spawn sudo /root/anyconnect/gen-client-cert.sh $user_name $OCSERV
    expect "Enter Export Password:"
    send "$user_pass\r"
    expect "Verifying - Enter Export Password:"
    send "$user_pass\r"
    expect eof
    exit
END

    cd $user_root_dir && mkdir -p /var/www/html/user
    cp -R $user_name /var/www/html/user/$user_name
    echo "$user_name 用户已成功创建，密码为 $user_pass"
    echo "$user_name 的证书已成功创建，请点击以下链接进行下载。"
    echo "http://$public_ip/user/$user_name/$user_name.p12"
    echo "证书本地路径为：$user_root_dir/$user_name"
    echo "导入证书的密码是 $user_pass"
    echo "VPN 地址和端口是 $public_ip:$PORT"
}

shell_install() {
    input_user
}

shell_install
