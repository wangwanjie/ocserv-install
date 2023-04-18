#!/bin/bash

# 这个脚本是用来同时添加 VPN 用户和他们的证书的

# 检查是否使用 root 账户执行脚本
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root."
   exit 1
fi

function input_user() {
	
	# 从两个数据源获取服务器的公网 IP
	get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" || curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")")
	public_ip="$get_public_ip"

	# 如果第一个数据源没有返回正确的公网 IP，就尝试第二个数据源
	if [[ -z "$public_ip" ]]; then
		public_ip=$(lynx --source www.monip.org | sed -nre 's/^.* (([0-9]{1,3}\.){3}[0-9]{1,3}).*$/\1/p')
	fi

	# 从 ocserv.conf 文件中获取 VPN 端口号
	PORT=$(grep ^\s*tcp-port /etc/ocserv/ocserv.conf | awk '{print $NF}')

	# 获取 VPN 用户名和组别
	read -p "请输入您的 VPN 用户名： " user_name
	if  [[ ! -n "$user_name" ]]; then
		echo "您没有输入用户名，请重新执行程序"
	else
		read -p "请输入您的 VPN 用户组别： " user_group
	fi

	# 获取 VPN 用户密码
	if [[ ! -n "$user_group" ]]; then
		echo "您没有输入用户组别，将使用配置文件中的默认组别"
		user_group="others"
	fi
	
	read -p "请输入您的密码： " user_pass

	if [[ ! -n "$user_pass" ]]; then
		echo "您没有输入密码，请重新执行程序"
	else
		user_add
		cert_add
	fi
}

function user_add() {
	# 根据不同的系统，选择不同的 expect 路径
	if [ -x "$(command -v yum)" ]; then
		EXPECT_CMD="/usr/bin/expect"
	else
		EXPECT_CMD="/usr/bin/env expect"
	fi

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

# 为用户添加证书
function cert_add() {
	OCSERV=/etc/ocserv
	user_root_dir=$OCSERV/user
	mkdir -p $user_root_dir/$user_name
	cd $user_root_dir/$user_name

	# 根据不同的系统，选择不同的 expect 路径
	if [ -x "$(command -v yum)" ]; then
		EXPECT_CMD="/usr/bin/expect"
	else
		EXPECT_CMD="/usr/bin/env expect"
	fi

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
	echo "http://$public_ip/$user_name.p12"
	echo "证书本地路径为：$user_root_dir/$user_name"
	echo "导入证书的密码是 $user_pass"
	echo "VPN 地址和端口是 $public_ip:$PORT"
}

# 安装 shell
function shell_install() {
	input_user
}

shell_install
