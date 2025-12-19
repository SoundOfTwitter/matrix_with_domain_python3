#!/bin/bash

# 脚本需要在拥有完整 sudo 权限的admin用户下运行。

# --- 1. 变量输入与生成 ---
read -p "请输入 域名 (例如: matrix.yourdomain.com): " server_domain
read -p "请输入 IP: " server_IP
read -p "请输入 完整的系统邮箱(gmail): " server_email
read -p "请输入 系统邮箱的授权码: " server_email_passwd
read -p "请输入 在Google申请的网站密钥 (reCAPTCHA Site Key): " google_webkey
read -p "请输入 在Google申请的密钥 (reCAPTCHA Secret Key): " google_key

# 自动生成安全的随机密码 (使用 sudo 执行 tee 写入 /home，确保权限)
# 因为 /dev/urandom 不需要 root 权限，所以生成操作可以不变
passwd_matrix=$(< /dev/urandom tr -dc 'A-Za-z0-9' | head -c 26)
passwd_psycopg2=$(< /dev/urandom tr -dc 'A-Za-z0-9' | head -c 26)
passwd_turnserver=$(< /dev/urandom tr -dc 'A-Za-z0-9' | head -c 26)

# 将域名写入 /home，如果 /home/admin/domain.txt 不存在，则需要 sudo 权限
echo "$server_domain" | sudo tee /home/admin/domain.txt > /dev/null
echo "域名已写入 /home/admin/domain.txt"

# --- 2. 基础环境与 Coturn 安装 (包含编译 psycopg2 所需的依赖) ---
echo "--- 安装基础工具和 Coturn ---"
sudo apt update
sudo apt install -y lsb-release wget apt-transport-https coturn python3-venv build-essential python3-dev libffi-dev libssl-dev libjpeg-dev libpq-dev
sleep 2

# --- 3. PostgreSQL 数据库安装与配置 ---
echo "--- 安装与配置 PostgreSQL ---"
sudo apt install -y postgresql postgresql-contrib
sudo systemctl enable postgresql
sudo systemctl start postgresql

# 切换到postgres系统用户并添加synapse数据库、新建用户synapse_user
# 注意：使用 sudo -u postgres 执行 psql 命令
echo "正在创建 PostgreSQL 数据库和用户..."
sudo -u postgres psql << SQL
-- Create the database with specified parameters
CREATE DATABASE synapse ENCODING 'UTF8' LC_COLLATE='C' LC_CTYPE='C' template=template0;
-- Create the user with the generated secure password
CREATE USER synapse_user WITH PASSWORD '$passwd_psycopg2';
-- Change the owner of the database to the newly created user
ALTER DATABASE synapse OWNER TO synapse_user;
-- Grant all privileges on the database to the user
GRANT ALL PRIVILEGES ON DATABASE synapse TO synapse_user;
\q
SQL
sleep 10


# ----------------------------------------------------------------------
# --- 4. Matrix Synapse Python 虚拟环境部署 (使用 synapse 用户运行) ---
# ----------------------------------------------------------------------
echo "--- 配置 Synapse Python 虚拟环境 ---"

# 1. 创建 synapse 系统用户和组
echo "正在创建 synapse 系统用户和组..."
# 确保 synapse 组存在
if ! getent group synapse > /dev/null; then
    sudo groupadd --system synapse
fi
# 创建 synapse 用户 (如果已存在则跳过)
sudo adduser --system --no-create-home --ingroup synapse synapse

# 2. 确保安装和数据目录存在
sudo mkdir -p /opt/synapse
sudo mkdir -p /etc/matrix-synapse
sudo mkdir -p /var/lib/matrix-synapse
sudo mkdir -p /var/log/matrix-synapse

# 3. 创建和激活虚拟环境 (创建 VENV 需要 root/sudo 权限来写入 /opt/synapse)
sudo python3 -m venv /opt/synapse/env
# 因为后续的 pip 安装需要在虚拟环境中执行，我们不能直接使用 source。
# 所有的虚拟环境命令都需要使用其完整路径 /opt/synapse/env/bin/...

# 4. 升级 pip 并安装 Synapse 及其所需的 PostgreSQL 驱动
# 定义要尝试的镜像源列表
MIRRORS=(
    "https://pypi.org/simple/"                   # 官方 PyPI 源 (国际)
    "https://pypi.tuna.tsinghua.edu.cn/simple/"  # 清华大学 (TUNA)
    "https://mirrors.aliyun.com/pypi/simple/"    # 阿里云
    "https://pypi.mirrors.ustc.edu.cn/simple/"   # 中科大 (USTC)
    "https://pypi.baidu.com/simple/"
    "https://mirrors.cloud.tencent.com/pypi/simple/"
    "https://repo.huaweicloud.com/repository/pypi/simple/"
)

SUCCESS=0

# 升级 pip
sudo /opt/synapse/env/bin/pip install --upgrade pip

echo "--- 尝试使用多个 PyPI 镜像源安装 Synapse ---"
for MIRROR in "${MIRRORS[@]}"; do
    echo "--- 正在尝试使用镜像源: $MIRROR ---"
    # 尝试安装
    sudo /opt/synapse/env/bin/pip install -i "$MIRROR" matrix-synapse[postgres]
    
    if [ $? -eq 0 ]; then
        echo "✅ 安装成功！使用源: $MIRROR"
        SUCCESS=1
        break # 安装成功，跳出循环
    else
        echo "❌ 使用源 $MIRROR 失败，尝试下一个..."
    fi
done

if [ $SUCCESS -eq 0 ]; then
    echo "致命错误：所有 PyPI 镜像源尝试均失败，请检查网络连接或依赖问题。"
    echo "请手动检查 /opt/synapse/env/bin/pip install 命令是否能成功运行。"
    exit 1 # 如果所有尝试都失败，则终止脚本
fi

# 5. 生成初始配置 (由 root/sudo 运行 VENV 命令)
echo "--- 生成 homeserver.yaml 初始配置 ---"
sudo /opt/synapse/env/bin/python -m synapse.app.homeserver \
    --server-name "$server_domain" \
    --config-path /etc/matrix-synapse/homeserver.yaml \
    --generate-config \
    --report-stats no
    
# 6. 设置正确的权限 (现在 synapse:synapse 应该有效了)
echo "正在设置 synapse 用户权限..."
sudo chown -R synapse:synapse /opt/synapse
sudo chown -R synapse:synapse /etc/matrix-synapse
sudo chown -R synapse:synapse /var/lib/matrix-synapse
sudo chown -R synapse:synapse /var/log/matrix-synapse

sleep 5


# --- 5. 配置 /etc/matrix-synapse/homeserver.yaml ---
echo "--- 写入自定义 homeserver.yaml 配置 ---"
# 使用 sudo tee 写入 /etc 目录下的文件
cat << EOF | sudo tee /etc/matrix-synapse/homeserver.yaml > /dev/null
server_name: "$server_domain"
public_baseurl: "https://$server_domain/"
pid_file: "/var/run/matrix-synapse.pid"
listeners:
  - port: 8008
    tls: false
    type: http
    x_forwarded: true
    bind_addresses: ['::1', '127.0.0.1']
    resources:
      - names: [client, federation]
        compress: false
tls_certificate_path: /etc/letsencrypt/live/$server_domain/fullchain.pem
tls_private_key_path: /etc/letsencrypt/live/$server_domain/privkey.pem
database:
  name: "psycopg2"
  args:
    user: "synapse_user"
    password: "$passwd_psycopg2"
    database: "synapse"
    host: "localhost"
    cp_min: 5
    cp_max: 10
log_config: "/etc/matrix-synapse/log.yaml"
# 明确设置统计报告选项以避免启动错误
report_stats: False
media_store_path: /var/lib/matrix-synapse/media
signing_key_path: "/etc/matrix-synapse/homeserver.signing.key"
trusted_key_servers:
  - server_name: "matrix.org"
max_avatar_size: 10M
max_upload_size: 50M
# 自动清理媒体缓存
media_retention_period: 7d  # 仅保留最近 7 天的媒体文件，过期的会被物理删除
remote_media_cache_ttl: 5d   # 远程服务器（联盟）的缓存仅保留 5 天
password_config:
  enabled: true
registration_shared_secret: "$passwd_matrix"
enable_registration: true
registrations_require_3pid:
  - email  # 这行表示注册时必须通过邮件验证
# 如果你只想要邮件验证，确保这里逻辑正确
enable_registration_without_verification: false
# enable_registration_captcha: true

# 填入你在 Google 申请的 Site Key (网站密钥)
recaptcha_public_key: "$google_webkey"
# 填入你在 Google 申请的 Secret Key (密钥)
recaptcha_private_key: "$google_key"
# 验证 API 地址，通常保持默认即可
recaptcha_siteverify_api: "https://www.google.com/recaptcha/api/siteverify"

# -------------------------------------------------------------------------
# WebRTC/VoIP STUN/TURN 配置
# -------------------------------------------------------------------------
turn_uris:
    - "turn:$server_domain:3478?transport=udp"
    - "turn:$server_domain:3478?transport=tcp"
    - "turns:$server_domain:5349?transport=udp"
    - "turns:$server_domain:5349?transport=tcp"

# 【关键】必须与 coturn 配置中的 static-auth-secret 保持一致！
turn_shared_secret: "$passwd_turnserver"
# 动态密码有效期 (毫秒)
turn_user_lifetime: 86400000 # 24 小时
email:
  # 启用邮件功能
  enable_notifs: true
  enable_password_resets: true # 开启找回密码
  # SMTP 服务器设置 (gmail邮箱)
  smtp_host: "smtp.gmail.com"
  smtp_port: 465
  smtp_user: "$server_email"
  # 注意：这里的密码必须是 gmail邮箱设置里开启 SMTP 后生成的“授权码”
  smtp_pass: "$server_email_passwd"
  # 是否使用 TLS (465端口对应 true, 587端口对应 false 并开启 require_transport_security)
  force_tls: true
  # 发件人显示名称和地址
  notif_from: "Matrix Server <$server_email>"
  # 邮件模板中显示的服务器名称
  client_base_url: "https://$server_domain"
EOF

# 重新应用正确的权限给配置
sudo chown -R synapse:synapse /etc/matrix-synapse
sudo chown -R synapse:synapse /var/lib/matrix-synapse
# 单独设置关键文件的权限
sudo chown synapse:synapse /etc/matrix-synapse/homeserver.signing.key
if [ -f /etc/matrix-synapse/log.yaml ]; then
    sudo chown synapse:synapse /etc/matrix-synapse/log.yaml
fi


# --- 6. 配置 /etc/turnserver.conf 和 Coturn 服务 ---
echo "--- 配置 Coturn ---"
cat << EOF | sudo tee /etc/turnserver.conf > /dev/null
# ... (Coturn 配置保持不变) ...
# 监听地址 (通常是服务器的公共 IP 或 0.0.0.0)
listening-ip=0.0.0.0
# 监听端口
listening-port=3478
# 增加 TLS 监听 (处理严格防火墙)
tls-listening-port=5349
# 外部 IP (如果服务器有多个 IP，请指定公网 IP)
external-ip=$server_IP

# use-auth-secret 是关键，它允许 Synapse 动态生成用户名和密码
use-auth-secret
static-auth-secret=$passwd_turnserver
realm=$server_domain

# 转发端口范围 (用于媒体流中继，范围越大越好)
min-port=49152
max-port=65535
# 证书配置 (关键：开启加密中继)
cert=/etc/coturn/certs/fullchain.pem
pkey=/etc/coturn/certs/privkey.pem
# 安全与性能优化
no-stdout-log
log-file=/var/log/turnserver.log
no-loopback-peers
no-multicast-peers
EOF

sudo systemctl enable coturn
sudo systemctl restart coturn


# --- 7. Nginx 与 Let's Encrypt 证书配置 (保持不变) ---
echo "--- 配置 Nginx 和 Let's Encrypt ---"
sudo apt install -y nginx

# 创建用于certbot验证的目录
sudo mkdir -p /var/www/certbot

# 先配置一个临时的nginx服务器块用于获取证书
cat << EOF | sudo tee /etc/nginx/sites-available/matrix-temp > /dev/null
server {
    listen 80;
    server_name $server_domain;
    
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        return 404;
    }
}
EOF

sudo ln -sf /etc/nginx/sites-available/matrix-temp /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo systemctl restart nginx

# 安装certbot并使用webroot方式获取证书
sudo apt install -y certbot python3-certbot-nginx

# 使用webroot方式获取初始证书
# 注意：你需要手动替换一个有效的 email 地址。我保留了你原始脚本中的地址。
sudo certbot certonly --webroot -w /var/www/certbot -d $server_domain --email liuxt2@hku-szh.org --agree-tos --non-interactive

# 在获取证书后添加
sudo mkdir -p /etc/coturn/certs
sudo chown -R turnserver:turnserver /etc/coturn
# 创建一个同步钩子脚本，确保续期后证书也能更新
cat << EOF | sudo tee /etc/letsencrypt/renewal-hooks/deploy/coturn.sh > /dev/null
#!/bin/bash
cp /etc/letsencrypt/live/$server_domain/fullchain.pem /etc/coturn/certs/
cp /etc/letsencrypt/live/$server_domain/privkey.pem /etc/coturn/certs/
chown -R turnserver:turnserver /etc/coturn/certs
systemctl restart coturn
EOF
sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/coturn.sh
# 立即手动执行一次同步
sudo /etc/letsencrypt/renewal-hooks/deploy/coturn.sh

# 配置 Nginx 正式代理
cat << EOF | sudo tee /etc/nginx/sites-available/matrix > /dev/null
# ... (Nginx 配置保持不变) ...
server {
    listen 80;
    server_name $server_domain;

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name $server_domain;

    ssl_certificate /etc/letsencrypt/live/$server_domain/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$server_domain/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'HIGH:!aNULL:!MD5';
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;

    add_header Strict-Transport-Security "max-age=63072000" always;

    location / {
        proxy_pass http://127.0.0.1:8008;
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        client_max_body_size 500M;
    }

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }
}
EOF

sudo ln -sf /etc/nginx/sites-available/matrix /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/matrix-temp
sudo systemctl reload nginx

echo "--- 配置证书自动续期 ---"
sudo certbot renew --dry-run
# 使用 crontab -l | cat 命令来确保非 root 用户可以读取自己的 crontab，然后使用 sudo tee 写入 root 的 crontab 文件
# 或者直接使用带 sudo 的 crontab -e，但这里使用 -l 和 tee 组合更适合脚本自动化
(sudo crontab -l 2>/dev/null; echo "0 12 * * * /usr/bin/certbot renew --quiet --post-hook \"systemctl reload nginx\"") | sudo crontab -

# --- 8. 创建 Systemd 服务文件 (使用 synapse 用户) ---
echo "--- 创建 systemd 服务文件 ---"
cat << EOF | sudo tee /etc/systemd/system/matrix-synapse.service > /dev/null
[Unit]
Description=Matrix Synapse Homeserver (Python VENV)
# 确保在 postgresql 和网络之后启动
Requires=network.target postgresql.service
After=network.target postgresql.service

[Service]
# 使用 synapse 用户和组运行服务
User=synapse
Group=synapse

# 虚拟环境的 Python 路径
ExecStart=/opt/synapse/env/bin/python -m synapse.app.homeserver -c /etc/matrix-synapse/homeserver.yaml

# Synapse 的工作目录
WorkingDirectory=/var/lib/matrix-synapse

# 重启策略
Restart=always
RestartSec=10

# 标准输出和标准错误输出到 syslog
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=matrix-synapse

LimitNOFILE=65536
LimitNPROC=1024

[Install]
WantedBy=multi-user.target
EOF

# 重新加载 systemd 配置
sudo systemctl daemon-reload

# 启用并启动 Synapse
sudo systemctl enable matrix-synapse
sudo systemctl start matrix-synapse
sleep 10


# --- 9. 最终输出 ---
echo "--- 部署完成 ---"
echo "Matrix Synapse 已通过 Python 虚拟环境安装并以 synapse 用户运行。"
echo "请使用以下命令检查服务状态: sudo systemctl status matrix-synapse"
echo "以下是生成的关键密码，请妥善保存："
echo "Synapse 注册共享密钥: $passwd_matrix"
echo "PostgreSQL 数据库密码: $passwd_psycopg2"
echo "TURN 服务器共享密钥: $passwd_turnserver"
echo "--------------------------------------------------------"
echo "✅ 注意：脚本最后一步的系统重启命令已移除。"
echo "请手动检查所有服务状态并决定是否重启系统。"
echo "--------------------------------------------------------"
