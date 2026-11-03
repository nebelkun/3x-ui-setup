#!/usr/bin/env bash
# Установка OpenVPN для ферм Hive OS: N ригов + admin, все видят друг друга как в локалке.
# Ubuntu 20.04 / 22.04 / 24.04. Запуск: sudo ./hive-vpn-setup.sh
#
# Переменные окружения (необязательно):
#   PUBLIC_IP=1.2.3.4   публичный IP/домен сервера (иначе определяется автоматически)
#   PORT=1194           порт
#   RIGS=20             количество ригов
#   PREFIX=rig          префикс имён ригов (rig1..rig20)
#   ADMINS="admin"      доп. клиенты для ноутбука/телефона (через пробел), получают 10.8.0.2, .3, ...
#
# Адреса: admin -> 10.8.0.2.., rigN -> 10.8.0.(10+N)  (rig1 = 10.8.0.11, rig20 = 10.8.0.30)
# Скрипт можно запускать повторно: существующие ключи и клиенты не пересоздаются.

set -euo pipefail

PORT="${PORT:-1194}"
PROTO="udp"
RIGS="${RIGS:-20}"
PREFIX="${PREFIX:-rig}"
ADMINS="${ADMINS:-admin}"
NET="10.8.0"
OVPN_DIR="/etc/openvpn/server"
EASY_DIR="/etc/openvpn/easy-rsa"
OUT_DIR="/root/ovpn"
MARKER="$OVPN_DIR/.hive-setup"

[[ $EUID -eq 0 ]] || { echo "Запусти от root: sudo $0"; exit 1; }

# Защита от конфликта с другим установщиком (например, angristan/openvpn-install)
if [[ -f "$OVPN_DIR/server.conf" && ! -f "$MARKER" ]]; then
  echo "ОШИБКА: на сервере уже есть другая установка OpenVPN ($OVPN_DIR/server.conf)."
  echo "Удали её (например: ./openvpn-install.sh uninstall) и запусти этот скрипт снова."
  exit 1
fi

echo "==> Установка пакетов"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y openvpn easy-rsa openssl curl iptables ca-certificates

# Публичный IP
if [[ -z "${PUBLIC_IP:-}" ]]; then
  PUBLIC_IP="$(curl -4 -fsS --max-time 10 https://ifconfig.me 2>/dev/null \
            || curl -4 -fsS --max-time 10 https://api.ipify.org 2>/dev/null || true)"
fi
[[ -n "$PUBLIC_IP" ]] || { echo "Не удалось определить IP. Запусти: PUBLIC_IP=x.x.x.x $0"; exit 1; }
echo "==> Публичный адрес сервера: $PUBLIC_IP"

mkdir -p "$OVPN_DIR/ccd" "$OUT_DIR"
chmod 755 "$OVPN_DIR/ccd"

# ---------- PKI ----------
if [[ ! -d "$EASY_DIR/pki" ]]; then
  echo "==> Создание PKI"
  rm -rf "$EASY_DIR"
  cp -r /usr/share/easy-rsa "$EASY_DIR"
  cd "$EASY_DIR"
  export EASYRSA_BATCH=1 EASYRSA_CERT_EXPIRE=3650 EASYRSA_CA_EXPIRE=3650 EASYRSA_CRL_DAYS=3650
  ./easyrsa init-pki
  ./easyrsa --req-cn="Hive-VPN-CA" build-ca nopass
  ./easyrsa build-server-full server nopass
  ./easyrsa gen-crl
fi
cd "$EASY_DIR"
export EASYRSA_BATCH=1 EASYRSA_CERT_EXPIRE=3650 EASYRSA_CA_EXPIRE=3650 EASYRSA_CRL_DAYS=3650

# tls-crypt ключ
if [[ ! -f "$OVPN_DIR/tls-crypt.key" ]]; then
  openvpn --genkey secret "$OVPN_DIR/tls-crypt.key" 2>/dev/null \
    || openvpn --genkey --secret "$OVPN_DIR/tls-crypt.key"
fi

cp pki/ca.crt pki/issued/server.crt pki/private/server.key pki/crl.pem "$OVPN_DIR/"
chmod 600 "$OVPN_DIR/server.key" "$OVPN_DIR/tls-crypt.key"
chmod 644 "$OVPN_DIR/crl.pem"

# ---------- server.conf ----------
echo "==> Конфиг сервера"
cat > "$OVPN_DIR/server.conf" <<EOF
port $PORT
proto $PROTO
dev tun

ca ca.crt
cert server.crt
key server.key
dh none
crl-verify crl.pem
tls-crypt tls-crypt.key

topology subnet
server ${NET}.0 255.255.255.0

# Фиксированные адреса клиентов лежат в ccd/
client-config-dir $OVPN_DIR/ccd

# Клиенты видят друг друга как в локальной сети
client-to-client

keepalive 10 60
persist-key
persist-tun

cipher AES-256-GCM
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
auth SHA256
tls-version-min 1.2

user nobody
group nogroup

status /var/log/openvpn-status.log 30
verb 3
explicit-exit-notify 1
EOF

# redirect-gateway НЕ пушится: обычный трафик ригов (пулы и т.д.) идёт напрямую, не через VPS.

# ---------- Клиенты ----------
make_client() {
  local name="$1" ip="$2"

  if [[ ! -f "pki/issued/${name}.crt" ]]; then
    ./easyrsa build-client-full "$name" nopass >/dev/null 2>&1
    echo "   + сертификат: $name"
  fi

  echo "ifconfig-push $ip 255.255.255.0" > "$OVPN_DIR/ccd/$name"
  chmod 644 "$OVPN_DIR/ccd/$name"

  cat > "$OUT_DIR/${name}.ovpn" <<EOF
client
dev tun
proto $PROTO
remote $PUBLIC_IP $PORT
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
auth SHA256
tls-version-min 1.2
verb 3

<ca>
$(cat pki/ca.crt)
</ca>
<cert>
$(openssl x509 -in "pki/issued/${name}.crt")
</cert>
<key>
$(cat "pki/private/${name}.key")
</key>
<tls-crypt>
$(cat "$OVPN_DIR/tls-crypt.key")
</tls-crypt>
EOF
  chmod 600 "$OUT_DIR/${name}.ovpn"
}

echo "==> Создание клиентов"
i=2
for a in $ADMINS; do
  make_client "$a" "${NET}.${i}"
  i=$((i+1))
done
for n in $(seq 1 "$RIGS"); do
  make_client "${PREFIX}${n}" "${NET}.$((10+n))"
done

# ---------- Firewall ----------
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
  echo "==> ufw: открываю ${PORT}/${PROTO}"
  ufw allow "${PORT}/${PROTO}"
fi

# ---------- Запуск ----------
echo "==> Запуск сервиса"
touch "$MARKER"
systemctl enable openvpn-server@server >/dev/null 2>&1 || true
systemctl restart openvpn-server@server
sleep 2
systemctl --no-pager --full status openvpn-server@server | head -n 8 || true

# Архив для удобного скачивания
tar -czf /root/hive-ovpn-configs.tar.gz -C "$OUT_DIR" .
chmod 600 /root/hive-ovpn-configs.tar.gz

cat <<EOF

================= ГОТОВО =================
Сервер:    $PUBLIC_IP:$PORT/$PROTO
Подсеть:   ${NET}.0/24  (сервер = ${NET}.1)
Конфиги:   $OUT_DIR/*.ovpn
Архив:     /root/hive-ovpn-configs.tar.gz

Скачать на компьютер (с твоей машины):
  scp root@$PUBLIC_IP:/root/hive-ovpn-configs.tar.gz .

Адреса: admin = ${NET}.2, ${PREFIX}1 = ${NET}.11 ... ${PREFIX}${RIGS} = ${NET}.$((10+RIGS))

ВАЖНО: откройте UDP $PORT в firewall панели хостера, если он там есть.
.ovpn содержат приватные ключи: не отправляй их через мессенджеры.
Проверка: ss -ulpn | grep $PORT ; cat /var/log/openvpn-status.log
==========================================
EOF
