#!/bin/bash

# ocserv 删除用户及注销用户的证书脚本文件

# 检查是否使用 root 账户执行脚本
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root."
   exit 1
fi

function user_del() {
    OCSERV=/etc/ocserv
    
    # 获取要删除用户的用户名
    read -p "请输入您想要删除的用户名！" user_name
    if  [[ ! -n "$user_name" ]]; then
        echo "您没有输入用户名，请重新执行程序"
    else
        # 使用 ocpasswd 命令删除用户
        /usr/bin/ocpasswd -d $user_name
        echo "$user_name 用户已成功删除"
        
        # 将用户证书添加到撤销列表，并生成 CRL 文件
        cat $OCSERV/user/$user_name/$user_name-cert.pem >> $OCSERV/pem/revoked.pem
        certtool --generate-crl --load-ca-privkey $OCSERV/pem/ca-key.pem  --load-ca-certificate $OCSERV/pem/ca-cert.pem --load-certificate $OCSERV/pem/revoked.pem  --template $OCSERV/tmpl/crl.tmpl --outfile $OCSERV/pem/crl.pem
        echo "$user_name 用户的证书已被注销"
        
        # 重启 ocserv 服务
        systemctl restart ocserv.service
    fi
}

# 调用函数
user_del
