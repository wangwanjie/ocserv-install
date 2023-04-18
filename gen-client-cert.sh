#!/bin/bash

# 检查是否使用 root 账户执行脚本
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root."
   exit 1
fi

# 从命令行参数获取用户名和路径
USER=$1
OCSERV=$2
USER_DIR=$OCSERV/user/$USER

# 确保目录存在
mkdir -p $USER_DIR && cd $USER_DIR

# 生成私钥
SERIAL=`date +%s`
certtool --generate-privkey --outfile $USER-key.pem

# 生成证书的模板文件
cat << _EOF_ >$USER.tmpl
cn = "$USER"
unit = "users"
serial = "$SERIAL"
expiration_days = 9999
signing_key
tls_www_client
_EOF_

# 用私钥、证书模板以及根证书生成证书文件
cd $USER_DIR
certtool --generate-certificate --load-privkey $USER-key.pem --load-ca-certificate $OCSERV/pem/ca-cert.pem --load-ca-privkey $OCSERV/pem/ca-key.pem --template $USER.tmpl --outfile $USER-cert.pem

# 将证书文件导出为 p12 格式
openssl pkcs12 -export -inkey $USER-key.pem -in $USER-cert.pem -name "$USER VPN Client Cert" -certfile $OCSERV/pem/ca-cert.pem -out $USER.p12
