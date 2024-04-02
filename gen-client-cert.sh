#!/bin/bash

# 检查是否使用 root 账户执行脚本
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root."
   exit 1
fi

# 检查命令行参数
if [[ -z "$1" || -z "$2" ]]; then
    echo "Usage: $0 <username> <ocserv-directory>"
    exit 1
fi

USER="$1"
OCSERV="$2"
USER_DIR="$OCSERV/user/$USER"

# 确保目录存在
mkdir -p "$USER_DIR" && cd "$USER_DIR" || { echo "Failed to create or access $USER_DIR"; exit 1; }

# 生成私钥
SERIAL=$(date +%s)
certtool --generate-privkey --outfile "$USER-key.pem" || { echo "Failed to generate private key"; exit 1; }

# 生成证书的模板文件
cat << _EOF_ > "$USER.tmpl"
cn = "$USER"
unit = "users"
serial = "$SERIAL"
expiration_days = 9999
signing_key
tls_www_client
_EOF_

# 用私钥、证书模板以及根证书生成证书文件
certtool --generate-certificate --load-privkey "$USER-key.pem" --load-ca-certificate "$OCSERV/pem/ca-cert.pem" --load-ca-privkey "$OCSERV/pem/ca-key.pem" --template "$USER.tmpl" --outfile "$USER-cert.pem" || { echo "Failed to generate certificate"; exit 1; }

# 检测 OpenSSL 版本
OPENSSL_VERSION=$(openssl version | cut -d" " -f2)
LEGACY_OPTION=""

# 比较版本号，如果新版则添加 -legacy 参数
if [[ $(echo "$OPENSSL_VERSION 3.0" | tr " " "\n" | sort -V | head -n1) == "3.0" ]]; then
    LEGACY_OPTION="-legacy"
fi

# 将证书文件导出为 p12 格式
openssl pkcs12 -export $LEGACY_OPTION -inkey "$USER-key.pem" -in "$USER-cert.pem" -name "$USER VPN Client Cert" -certfile "$OCSERV/pem/ca-cert.pem" -out "$USER.p12" || { echo "Failed to export certificate to PKCS#12 format"; exit 1; }

echo "Certificate and key for $USER have been successfully generated and stored in $USER_DIR."
