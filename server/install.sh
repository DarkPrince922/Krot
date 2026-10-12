#!/usr/bin/env bash
# Install or update the Krot server as a systemd service (Debian 12+ / Ubuntu 24.04+).
#   git clone https://github.com/DarkPrince922/Krot.git /opt/krot
#   sudo bash /opt/krot/server/install.sh tunnel.example.ru
# Re-running updates the code from the checked-out branch and keeps the password.
# Env: KROT_BRANCH (default: current branch of /opt/krot), KROT_BIND (default: IPv4 of the default route).
set -euo pipefail

DOMAIN=${1:?usage: install.sh tunnel.example.ru}
DOMAIN=${DOMAIN,,}; DOMAIN=${DOMAIN%.}
DIR=/opt/krot
REPO=https://github.com/DarkPrince922/Krot.git

[ "$(id -u)" = 0 ] || { echo "Запустите от root (sudo)"; exit 1; }
[[ $DOMAIN =~ ^tunnel(\.[a-z0-9-]+)+$ ]] || { echo "Зона должна быть вида tunnel.example.ru"; exit 1; }

echo "== Пакеты"
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq git python3 python3-venv dnsutils >/dev/null
python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))' \
  || { echo "Нужен Python >= 3.11 (Debian 12 / Ubuntu 24.04)"; exit 1; }

echo "== Код в $DIR"
if [ -d "$DIR/.git" ]; then
  BRANCH=${KROT_BRANCH:-$(git -C "$DIR" rev-parse --abbrev-ref HEAD)}
  git -C "$DIR" fetch -q origin "$BRANCH"
  git -C "$DIR" checkout -q -f -B "$BRANCH" FETCH_HEAD # deployment copy: local edits are discarded
else
  BRANCH=${KROT_BRANCH:-main}
  git clone -q -b "$BRANCH" "$REPO" "$DIR"
fi
echo "   ветка $BRANCH, коммит $(git -C "$DIR" rev-parse --short HEAD)"
python3 -m venv "$DIR/.venv"
"$DIR/.venv/bin/pip" install -q --disable-pip-version-check -r "$DIR/server/requirements.txt"

BIND=${KROT_BIND:-$(ip -4 route get 1.1.1.1 | awk '{for (i = 1; i < NF; i++) if ($i == "src") print $(i + 1)}')}
[ -n "$BIND" ] || { echo "Не найден IPv4 интерфейса; задайте KROT_BIND=..."; exit 1; }
echo "== Адрес $BIND:53"

# systemd-resolved (127.0.0.53/54) can stay; anything else on this address or a wildcard conflicts.
CONFLICT=$(ss -Hlunp 'sport = :53' | awk -v ip="$BIND" '$4 == ip":53" || $4 ~ /^(0\.0\.0\.0|\*|\[::\]):53$/' || true)
if [ -n "$CONFLICT" ] && ! systemctl is-active -q krot; then
  echo "UDP/53 занят другим процессом:"; echo "$CONFLICT"; exit 1
fi

if [ ! -s /etc/krot.env ]; then
  PASSWORD=$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')
  (umask 077; echo "KROT_PASSWORD=$PASSWORD" > /etc/krot.env)
  NEW_PASSWORD=1
fi
chmod 600 /etc/krot.env

sed "s|^ExecStart=.*|ExecStart=$DIR/.venv/bin/python $DIR/server/krot.py --domain $DOMAIN --bind $BIND|" \
  "$DIR/server/krot.service" > /etc/systemd/system/krot.service
systemctl daemon-reload
systemctl enable -q krot
systemctl restart krot

if command -v ufw >/dev/null && ufw status | grep -q '^Status: active'; then ufw allow 53/udp >/dev/null; echo "== ufw: открыт 53/udp"; fi
if command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
  firewall-cmd -q --permanent --add-port=53/udp && firewall-cmd -q --reload; echo "== firewalld: открыт 53/udp"
fi

sleep 2
if ! systemctl is-active -q krot; then
  journalctl -u krot -n 20 --no-pager; echo "Сервис не запустился"; exit 1
fi
journalctl -u krot -n 1 --no-pager -o cat

echo "== Делегирование"
PARENT=${DOMAIN#tunnel.}
PARENT_NS=$(dig +short +time=3 NS "$PARENT" @1.1.1.1 | head -1 || true)
if [ -z "$PARENT_NS" ]; then
  echo "   Не удалось получить NS зоны $PARENT"
else
  NS=$(dig +norec +time=3 +noall +authority NS "$DOMAIN" @"$PARENT_NS" | awk '$4 == "NS" {print $5}' | head -1 || true)
  if [ -z "$NS" ]; then
    echo "   В зоне $PARENT нет записи: $DOMAIN NS <имя этого сервера>."
  else
    echo "   $DOMAIN NS $NS -> $(dig +short +time=3 A "$NS" @1.1.1.1 | tr '\n' ' ' || true)(этот сервер: $BIND; при NAT сверьте с публичным IP)"
  fi
fi

echo
echo "Готово. В приложении: зона $DOMAIN"
if [ "${NEW_PASSWORD:-}" = 1 ]; then echo "Пароль (сохраните): $PASSWORD"; else echo "Пароль прежний: sudo cat /etc/krot.env"; fi
echo "Журнал: journalctl -u krot -f   Обновление: sudo bash $DIR/server/install.sh $DOMAIN"
