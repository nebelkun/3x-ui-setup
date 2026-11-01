#!/usr/bin/env bash
#
# add-inbound.sh — создаёт инбаунд VLESS + TCP + Reality в 3x-ui через API панели
# и печатает готовые vless:// ссылки для клиентов.
#
# Запуск на сервере (от root), после setup.sh:
#   bash <(curl -Ls https://raw.githubusercontent.com/nebelkun/3x-ui-setup/main/add-inbound.sh)
#
# Переменные (все необязательные):
#   PORT=443              порт инбаунда
#   SNI=yastatic.net      домен маскировки (Target и SNI)
#   FP=firefox            uTLS fingerprint (chrome / firefox / safari ...)
#   REMARK=reality        имя инбаунда
#   CLIENTS=1             сколько клиентов создать
#   PANEL_URL=...         базовый URL панели, если не берётся из /root/3x-ui-credentials.txt
#   PANEL_USER / PANEL_PASS   логин и пароль, если файла с доступами нет
#   XRAY_BIN=...          путь к бинарнику xray (по умолчанию ищется в /usr/local/x-ui/bin)
#
set -euo pipefail

PORT="${PORT:-443}"
SNI="${SNI:-yastatic.net}"
FP="${FP:-firefox}"
REMARK="${REMARK:-reality}"
CLIENTS="${CLIENTS:-1}"
CRED_FILE="${CRED_FILE:-/root/3x-ui-credentials.txt}"
OUT_FILE="${OUT_FILE:-/root/3x-ui-clients.txt}"

[[ $EUID -eq 0 ]] || { echo "Запустите от root." >&2; exit 1; }
command -v curl    >/dev/null || { echo "Нужен curl." >&2; exit 1; }
command -v python3 >/dev/null || { apt-get update -qq && apt-get install -y -qq python3; }

# --- доступы к панели ---------------------------------------------------
if [[ -z "${PANEL_URL:-}" || -z "${PANEL_USER:-}" || -z "${PANEL_PASS:-}" ]]; then
    [[ -f "$CRED_FILE" ]] || { echo "Нет $CRED_FILE. Задайте PANEL_URL, PANEL_USER, PANEL_PASS." >&2; exit 1; }
    PANEL_USER="${PANEL_USER:-$(awk -F':[ ]*' '/^Логин:/{print $2; exit}' "$CRED_FILE")}"
    PANEL_PASS="${PANEL_PASS:-$(awk -F':[ ]*' '/^Пароль:/{print $2; exit}' "$CRED_FILE")}"
    if [[ -z "${PANEL_URL:-}" ]]; then
        URL_LINE="$(awk '/^URL:/{print $2; exit}' "$CRED_FILE")"
        # http://IP:PORT/PATH/  ->  http://127.0.0.1:PORT/PATH
        PANEL_URL="$(echo "$URL_LINE" | sed -E 's#^(https?)://[^:/]+:([0-9]+)/([^/]*)/?.*#\1://127.0.0.1:\2/\3#')"
    fi
fi
PANEL_URL="${PANEL_URL%/}"
SERVER_IP="${SERVER_IP:-$(curl -s --max-time 5 https://api.ipify.org || hostname -I | awk '{print $1}')}"

# --- ключи Reality через бинарник xray ----------------------------------
XRAY_BIN="${XRAY_BIN:-$(ls /usr/local/x-ui/bin/xray-linux-* 2>/dev/null | head -n1 || true)}"
[[ -x "${XRAY_BIN:-}" ]] || { echo "Не найден бинарник xray в /usr/local/x-ui/bin. Задайте XRAY_BIN." >&2; exit 1; }
KEYS="$("$XRAY_BIN" x25519)"
PRIV="$(echo "$KEYS" | awk -F': *' 'tolower($1) ~ /private/ {print $2; exit}')"
PUB="$(echo  "$KEYS" | awk -F': *' 'tolower($1) ~ /public|password/ {print $2; exit}')"
[[ -n "$PRIV" && -n "$PUB" ]] || { echo "Не удалось получить ключи Reality из вывода xray:" >&2; echo "$KEYS" >&2; exit 1; }
SHORT_ID="$(openssl rand -hex 8)"

# --- JSON инбаунда -------------------------------------------------------
export PORT SNI FP REMARK CLIENTS PRIV PUB SHORT_ID
PAYLOAD_DIR="$(mktemp -d)"
trap 'rm -rf "$PAYLOAD_DIR"' EXIT
python3 - "$PAYLOAD_DIR" <<'PY'
import json, os, sys, uuid, secrets
d = sys.argv[1]
e = os.environ
clients = []
for i in range(1, int(e["CLIENTS"]) + 1):
    clients.append({
        "id": str(uuid.uuid4()), "flow": "xtls-rprx-vision",
        "email": f'{e["REMARK"]}-{i}', "limitIp": 0, "totalGB": 0,
        "expiryTime": 0, "enable": True, "tgId": "",
        "subId": secrets.token_hex(8), "comment": "", "reset": 0,
    })
settings = {"clients": clients, "decryption": "none", "fallbacks": []}
target = e["SNI"] + ":443"
stream = {
    "network": "tcp", "security": "reality", "externalProxy": [],
    "realitySettings": {
        "show": False, "xver": 0, "target": target, "dest": target,
        "serverNames": [e["SNI"]], "privateKey": e["PRIV"],
        "minClient": "", "maxClient": "", "maxTimediff": 0,
        "shortIds": [e["SHORT_ID"]],
        "settings": {"publicKey": e["PUB"], "fingerprint": e["FP"],
                     "serverName": "", "spiderX": "/"},
    },
    "tcpSettings": {"acceptProxyProtocol": False, "header": {"type": "none"}},
}
sniffing = {"enabled": True, "destOverride": ["http", "tls", "quic", "fakedns"],
            "metadataOnly": False, "routeOnly": False}
for name, obj in (("settings", settings), ("stream", stream), ("sniffing", sniffing)):
    open(os.path.join(d, name + ".json"), "w").write(json.dumps(obj, separators=(",", ":")))
open(os.path.join(d, "clients.tsv"), "w").write(
    "".join(f'{c["id"]}\t{c["email"]}\n' for c in clients))
PY

# --- логин и создание ----------------------------------------------------
COOKIE="$PAYLOAD_DIR/cookie"
LOGIN_JSON="$(PANEL_USER="$PANEL_USER" PANEL_PASS="$PANEL_PASS" python3 -c \
    'import json,os;print(json.dumps({"username":os.environ["PANEL_USER"],"password":os.environ["PANEL_PASS"]}))')"
# пробует войти формой, затем JSON-ом; в LOGIN остаётся ответ, в LOGIN_CODE — HTTP-код последней попытки
try_login() {
    local url="$1" out
    out="$(curl -sSk --max-time 15 -c "$COOKIE" -w '\n%{http_code}' -X POST "$url/login" \
        --data-urlencode "username=$PANEL_USER" --data-urlencode "password=$PANEL_PASS" \
        2>"$PAYLOAD_DIR/curl.err" || true)"
    LOGIN="${out%$'\n'*}"; LOGIN_CODE="${out##*$'\n'}"
    echo "$LOGIN" | grep -q '"success": *true' && return 0
    out="$(curl -sSk --max-time 15 -c "$COOKIE" -w '\n%{http_code}' -X POST "$url/login" \
        -H 'Content-Type: application/json' -d "$LOGIN_JSON" \
        2>>"$PAYLOAD_DIR/curl.err" || true)"
    LOGIN="${out%$'\n'*}"; LOGIN_CODE="${out##*$'\n'}"
    echo "$LOGIN" | grep -q '"success": *true'
}
if ! try_login "$PANEL_URL"; then
    FIRST_ERR="$(cat "$PAYLOAD_DIR/curl.err")"; FIRST_RESP="$LOGIN"; FIRST_CODE="$LOGIN_CODE"
    # панель могла быть на другой схеме (http <-> https): пробуем вторую
    ALT_URL="${PANEL_URL/#http:/https:}"
    [[ "$ALT_URL" == "$PANEL_URL" ]] && ALT_URL="${PANEL_URL/#https:/http:}"
    : > "$PAYLOAD_DIR/curl.err"
    if try_login "$ALT_URL"; then
        echo "Панель отвечает по ${ALT_URL%%:*}, использую $ALT_URL"
        PANEL_URL="$ALT_URL"
    else
        echo "Не удалось войти в панель." >&2
        echo "  $PANEL_URL -> HTTP ${FIRST_CODE}, ответ: '${FIRST_RESP}' ${FIRST_ERR}" >&2
        echo "  $ALT_URL -> HTTP ${LOGIN_CODE}, ответ: '${LOGIN}' $(cat "$PAYLOAD_DIR/curl.err")" >&2
        echo "Проверьте: порт/путь панели (x-ui settings), 2FA, логин и пароль в $CRED_FILE." >&2
        echo "Адрес можно задать вручную: PANEL_URL=https://127.0.0.1:ПОРТ/ПУТЬ" >&2
        exit 1
    fi
fi

RESP="$(curl -sk -b "$COOKIE" -X POST "$PANEL_URL/panel/api/inbounds/add" \
    --data-urlencode "up=0" --data-urlencode "down=0" --data-urlencode "total=0" \
    --data-urlencode "remark=$REMARK" --data-urlencode "enable=true" \
    --data-urlencode "expiryTime=0" --data-urlencode "listen=" \
    --data-urlencode "port=$PORT" --data-urlencode "protocol=vless" \
    --data-urlencode "settings@$PAYLOAD_DIR/settings.json" \
    --data-urlencode "streamSettings@$PAYLOAD_DIR/stream.json" \
    --data-urlencode "sniffing@$PAYLOAD_DIR/sniffing.json" \
    --data-urlencode 'allocate={"strategy":"always","refresh":5,"concurrency":3}')"
echo "$RESP" | grep -q '"success": *true' || {
    echo "Панель отклонила создание инбаунда. Ответ: $RESP" >&2
    echo "(частые причины: порт $PORT уже занят другим инбаундом, или версия панели использует другой формат API)" >&2
    exit 1
}

if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
    ufw allow "${PORT}/tcp" comment 'Xray Reality' >/dev/null || true
fi

# --- ссылки для клиентов -------------------------------------------------
umask 077
: > "$OUT_FILE"
while IFS=$'\t' read -r CID CEMAIL; do
    echo "vless://${CID}@${SERVER_IP}:${PORT}?type=tcp&encryption=none&security=reality&pbk=${PUB}&fp=${FP}&sni=${SNI}&sid=${SHORT_ID}&spx=%2F&flow=xtls-rprx-vision#${CEMAIL}" >> "$OUT_FILE"
done < "$PAYLOAD_DIR/clients.tsv"

echo
echo "=============== ИНБАУНД СОЗДАН ==============="
echo "VLESS + TCP + Reality, порт ${PORT}, SNI ${SNI}, fingerprint ${FP}"
echo "Ссылки для клиентов (сохранены в $OUT_FILE):"
echo
cat "$OUT_FILE"
echo
echo "Инбаунд появится в панели, Xray применит его в течение нескольких секунд."
