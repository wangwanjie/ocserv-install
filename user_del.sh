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
    read -p "请输入您想要删除的用户名: " user_name
    if  [[ -z "$user_name" ]]; then
        echo "您没有输入用户名，请重新执行程序"
        return 1 # 返回非零值表示失败
    fi

    # 使用 ocpasswd 命令删除用户，此处假设 ocpasswd 路径已经正确配置在环境变量中
    if ocpasswd -c $OCSERV/ocpasswd -d $user_name; then
        echo "$user_name 用户已成功删除"
    else
        echo "删除 $user_name 用户失败，可能用户不存在。"
        return 1
    fi

    user_cert_path="$OCSERV/user/$user_name/$user_name-cert.pem"
    # 检查用户证书是否存在
    if [[ -f "$user_cert_path" ]]; then
        # 将用户证书添加到撤销列表，并生成 CRL 文件
        cat $user_cert_path >> $OCSERV/pem/revoked.pem
        certtool --generate-crl --load-ca-privkey $OCSERV/pem/ca-key.pem --load-ca-certificate $OCSERV/pem/ca-cert.pem --load-certificate $OCSERV/pem/revoked.pem --template $OCSERV/tmpl/crl.tmpl --outfile $OCSERV/pem/crl.pem
        echo "$user_name 用户的证书已被注销"
    else
        echo "未找到 $user_name 用户的证书文件，跳过证书注销步骤。"
    fi

    # 重启 ocserv 服务
    if systemctl restart ocserv.service; then
        echo "ocserv 服务已重启。"
    else
        echo "ocserv 服务重启失败，请手动重启。"
        return 1
    fi
}

# 调用函数
user_del
