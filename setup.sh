#!/usr/bin/env bash
#
# setup.sh — разворачивает 3x-ui + fail2ban + ufw на чистом Debian/Ubuntu.
#
# Запуск:
#   bash <(curl -Ls https://raw.githubusercontent.com/ВАШ_ЛОГИН/ВАШ_РЕПО/main/setup.sh)
#
# Опциональные переменные (передаются перед командой):
#   ADMIN_IP=auto           открыть порт панели ТОЛЬКО для IP, с которого вы сейчас зашли по SSH
#   ADMIN_IP=<ваш IP>       то же самое, но IP задан вручную (это IP вашего компьютера/сети,
#                           а не сервера; узнать: curl ifconfig.me на своём компьютере)
#   PANEL_CLOSED=1          не открывать панель наружу вообще (доступ через SSH-туннель)
#   PANEL_PORT=43433        порт панели (по умолчанию случайный 20000-60000)
#   REALITY_PORT=443        порт под VLESS+Reality
#   SSH_PORT=22             порт SSH (по умолчанию определяется автоматически)
#
# Пример (панель доступна только с того IP, откуда вы подключились к серверу):
#   ADMIN_IP=auto PANEL_PORT=43433 bash <(curl -Ls https://raw.githubusercontent.com/.../setup.sh)
#
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

[[ $EUID -eq 0 ]] || { echo "Запустите от root (sudo -i)." >&2; exit 1; }
command -v apt-get >/dev/null || { echo "Скрипт рассчитан на Debian/Ubuntu." >&2; exit 1; }

REALITY_PORT="${REALITY_PORT:-443}"
PANEL_PORT="${PANEL_PORT:-$(shuf -i 20000-60000 -n 1)}"
ADMIN_IP="${ADMIN_IP:-}"
PANEL_CLOSED="${PANEL_CLOSED:-0}"
SSH_PORT="${SSH_PORT:-$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}' || true)}"
SSH_PORT="${SSH_PORT:-22}"

if [[ "$ADMIN_IP" == "auto" ]]; then
    ADMIN_IP="${SSH_CLIENT:-}"
    ADMIN_IP="${ADMIN_IP%% *}"
    if [[ -z "$ADMIN_IP" ]]; then
        echo "Не удалось определить ваш IP из SSH-сессии. Задайте ADMIN_IP вручную или уберите параметр." >&2
        exit 1
    fi
    echo "Определён ваш IP: $ADMIN_IP"
fi

PANEL_USER="$(openssl rand -hex 5 2>/dev/null || echo admin$RANDOM)"
PANEL_PASS="$(openssl rand -hex 12 2>/dev/null || echo pass$RANDOM$RANDOM)"
PANEL_PATH="$(openssl rand -hex 8 2>/dev/null || echo path$RANDOM)"

echo "== [1/5] Пакеты =="
apt-get update -qq
apt-get install -y -qq curl wget openssl ufw fail2ban python3-systemd ca-certificates

echo "== [2/5] Установка 3x-ui =="
# stdin закрыт: интерактивные вопросы установщика получают пустой ответ -> случайные значения.
# Нужные нам значения выставляем сами сразу после установки.
XUI_REPO="MHSanaei/3x-ui"   # https://github.com/MHSanaei/3x-ui
XUI_INSTALLER="$(mktemp)"
curl -fsSL "https://raw.githubusercontent.com/${XUI_REPO}/main/install.sh" -o "$XUI_INSTALLER" \
    || curl -fsSL "https://raw.githubusercontent.com/${XUI_REPO}/master/install.sh" -o "$XUI_INSTALLER" \
    || { echo "Не удалось скачать install.sh из ${XUI_REPO}" >&2; exit 1; }
bash "$XUI_INSTALLER" </dev/null || true
rm -f "$XUI_INSTALLER"

if [[ ! -x /usr/local/x-ui/x-ui ]]; then
    echo "Не удалось установить 3x-ui — /usr/local/x-ui/x-ui не найден." >&2
    exit 1
fi

/usr/local/x-ui/x-ui setting \
    -username "$PANEL_USER" -password "$PANEL_PASS" \
    -port "$PANEL_PORT" -webBasePath "$PANEL_PATH" >/dev/null
systemctl restart x-ui
sleep 2
systemctl is-active --quiet x-ui || { echo "Служба x-ui не запустилась: journalctl -u x-ui" >&2; exit 1; }

echo "== [3/5] Firewall (ufw) =="
ufw --force reset >/dev/null
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
ufw limit "${SSH_PORT}/tcp" comment 'SSH' >/dev/null
ufw allow "${REALITY_PORT}/tcp" comment 'Xray Reality' >/dev/null

if [[ "$PANEL_CLOSED" == "1" ]]; then
    PANEL_MODE="закрыта (только через SSH-туннель)"
elif [[ -n "$ADMIN_IP" ]]; then
    ufw allow from "$ADMIN_IP" to any port "$PANEL_PORT" proto tcp comment '3x-ui panel (admin only)' >/dev/null
    PANEL_MODE="открыта только для $ADMIN_IP"
else
    ufw allow "${PANEL_PORT}/tcp" comment '3x-ui panel' >/dev/null
    PANEL_MODE="ОТКРЫТА ВСЕМ (панель по HTTP!)"
fi
ufw logging low >/dev/null
ufw --force enable >/dev/null

echo "== [4/5] Fail2ban =="
cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
backend           = systemd
banaction         = ufw
bantime           = 1h
findtime          = 10m
maxretry          = 4
bantime.increment = true
bantime.factor    = 2
bantime.maxtime   = 1w
${ADMIN_IP:+ignoreip = 127.0.0.1/8 ::1 $ADMIN_IP}

[sshd]
enabled = true
port    = ${SSH_PORT}
EOF
systemctl enable --now fail2ban >/dev/null 2>&1
systemctl restart fail2ban

echo "== [5/5] Сохраняю доступы =="
SERVER_IP="$(curl -s --max-time 5 https://api.ipify.org || hostname -I | awk '{print $1}')"
CRED_FILE=/root/3x-ui-credentials.txt
umask 077
cat > "$CRED_FILE" <<EOF
URL:      http://${SERVER_IP}:${PANEL_PORT}/${PANEL_PATH}/
Логин:    ${PANEL_USER}
Пароль:   ${PANEL_PASS}
Панель:   ${PANEL_MODE}
SSH порт: ${SSH_PORT}
Reality:  ${REALITY_PORT}/tcp
EOF

echo
echo "=============== ГОТОВО ==============="
cat "$CRED_FILE"
echo "(сохранено в $CRED_FILE, права 600)"
if [[ "$PANEL_CLOSED" == "1" ]]; then
    echo
    echo "Доступ к панели через туннель:"
    echo "  ssh -L ${PANEL_PORT}:127.0.0.1:${PANEL_PORT} -p ${SSH_PORT} root@${SERVER_IP}"
    echo "  затем http://127.0.0.1:${PANEL_PORT}/${PANEL_PATH}/"
fi
echo
echo "Дальше: зайдите в панель и создайте инбаунд VLESS + TCP + Reality на порту ${REALITY_PORT}."
echo "Не закрывайте текущую SSH-сессию, пока не проверите вход во второй."
