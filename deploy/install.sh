#!/bin/bash
# PAW Proxy Pilot installer for Ubuntu Server 24.04 LTS (also works on Debian 12).
#
#   sudo ./install.sh               first install, or update to the version in this folder
#   sudo ./install.sh --reconfigure re-ask hostname, port, Entra and certificate questions
#   sudo ./install.sh --entra       new Entra setup code / rotated secret only
#   sudo ./install.sh --self-signed use a self-signed cert instead of Let's Encrypt
#   sudo ./install.sh --squid-conf  rewrite /etc/squid/squid.conf (asks which networks the PAWs are on)
#
# The Entra app is created by deploy/New-PAWProxyPilotApp.ps1, run on your Windows or Mac machine;
# it prints a setup code that you paste in here.
#
# Safe to re-run: it keeps /etc/pawpilot/pawpilot.env, the database, certificates,
# the Squid allow list and (unless you pass --squid-conf) squid.conf.
set -euo pipefail

APP_DIR=/opt/pawpilot
ETC_DIR=/etc/pawpilot
DATA_DIR=/var/lib/pawpilot
TLS_DIR=$ETC_DIR/tls
ENV_FILE=$ETC_DIR/pawpilot.env
CF_INI=$ETC_DIR/cloudflare.ini
ACL_FILE=/etc/squid/allowed_paw.acl
SQUID_CONF_FILE=/etc/squid/squid.conf
SRC_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

RECONFIGURE=0
ENTRA_ONLY=0
SELF_SIGNED=0
SQUID_CONF=0
for arg in "$@"; do
  case "$arg" in
    --reconfigure) RECONFIGURE=1 ;;
    --entra) ENTRA_ONLY=1 ;;
    --self-signed) SELF_SIGNED=1 ;;
    --squid-conf) SQUID_CONF=1 ;;
    -h|--help) sed -n '2,/^set -euo/p' "$0" | grep '^#' | sed -E 's/^# ?//'; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; exit 64 ;;
  esac
done

say()  { printf '\n\033[1;33m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;31m!!  %s\033[0m\n' "$*" >&2; }
ask() {  # ask VAR "Question" "default"
  local __var=$1 __q=$2 __def=${3:-} __ans
  if [[ -n $__def ]]; then read -r -p "$__q [$__def]: " __ans; else read -r -p "$__q: " __ans; fi
  printf -v "$__var" '%s' "${__ans:-$__def}"
}
ask_secret() {
  local __var=$1 __q=$2 __ans
  read -r -s -p "$__q: " __ans; echo
  printf -v "$__var" '%s' "$__ans"
}
env_get() { [[ -f $ENV_FILE ]] && sed -n "s/^$1=//p" "$ENV_FILE" | tail -n1 || true; }
yes_no() {  # yes_no "Question" Y|N  -> returns 0 for yes
  local __ans __def=${2:-Y}
  read -r -p "$1 [$( [[ $__def == Y ]] && echo Y/n || echo y/N )]: " __ans
  __ans=${__ans:-$__def}
  [[ $__ans =~ ^[Yy] ]]
}

[[ $EUID -eq 0 ]] || { warn "Run with sudo."; exit 1; }
command -v apt-get >/dev/null || { warn "This installer needs apt (Ubuntu or Debian)."; exit 1; }

say "Installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq squid python3-venv python3-pip rsync openssl sudo curl ca-certificates \
  certbot python3-certbot-dns-cloudflare >/dev/null
systemctl enable squid >/dev/null 2>&1 || true

say "Creating the pawpilot service account"
if ! id pawpilot >/dev/null 2>&1; then
  useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin pawpilot
fi
usermod -aG proxy pawpilot   # the proxy group can read Squid's access log

install -d -m 0750 -o root -g pawpilot "$ETC_DIR"
install -d -m 0750 -o root -g pawpilot "$TLS_DIR"
install -d -m 0750 -o pawpilot -g pawpilot "$DATA_DIR"

say "Installing PAW Proxy Pilot to $APP_DIR"
install -d -m 0755 "$APP_DIR"
rsync -a --delete --exclude '.git' --exclude 'venv' --exclude '__pycache__' --exclude 'tests' --exclude 'dist' \
  "$SRC_DIR/" "$APP_DIR/"
chown -R root:root "$APP_DIR"
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install -q --upgrade pip
"$APP_DIR/venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"

say "Installing the apply helper and sudo rule"
install -m 0755 -o root -g root "$APP_DIR/deploy/pawpilot-apply" /usr/local/sbin/pawpilot-apply
install -m 0440 -o root -g root "$APP_DIR/deploy/pawpilot.sudoers" /etc/sudoers.d/pawpilot
visudo -cf /etc/sudoers.d/pawpilot >/dev/null || { warn "sudoers rule failed validation"; rm -f /etc/sudoers.d/pawpilot; exit 1; }

# --------------------------------------------------------------------------
# Entra ID app registration helpers
# --------------------------------------------------------------------------
install_pwsh() {
  command -v pwsh >/dev/null && return 0
  say "Installing PowerShell 7 (used once to create the Entra app)"
  # shellcheck disable=SC1091
  . /etc/os-release
  if [[ $(dpkg --print-architecture) == amd64 && ( $ID == ubuntu || $ID == debian ) ]]; then
    local deb
    deb=$(mktemp --suffix=.deb)
    if curl -fsSL -o "$deb" "https://packages.microsoft.com/config/$ID/$VERSION_ID/packages-microsoft-prod.deb"; then
      dpkg -i "$deb" >/dev/null && apt-get update -qq && apt-get install -y -qq powershell >/dev/null || true
    fi
    rm -f "$deb"
  fi
  if ! command -v pwsh >/dev/null && command -v snap >/dev/null; then
    snap install powershell --classic >/dev/null || true
  fi
  command -v pwsh >/dev/null
}

create_entra_app() {  # sets TENANT_ID CLIENT_ID CLIENT_SECRET ROLE SECRET_EXPIRES; returns 1 on failure
  install_pwsh || { warn "Couldn't install PowerShell 7."; return 1; }
  local out admin
  echo
  echo "Next you'll sign in to Microsoft with a code (use any browser, e.g. on your phone)."
  echo "Use an account that can create apps and grant admin consent (Global Admin,"
  echo "or Cloud Application Admin + Privileged Role Admin)."
  echo "The first run also downloads the Microsoft Graph PowerShell modules, which takes a few minutes."
  ask admin "UPN to give the PAW Proxy Pilot Admin role (blank = the account you sign in with)" "${ADMIN_UPN:-}"
  out=$(mktemp /run/pawpilot-app.XXXXXX)
  chmod 600 "$out"
  local args=(-NoProfile -File "$APP_DIR/deploy/New-PAWProxyPilotApp.ps1" -HostName "$HOSTNAME_FQDN" -Port "$PORT"
              -UseDeviceCode -OutputJson "$out")
  [[ -n $admin ]] && args+=(-AssignTo "$admin")
  [[ -n $TENANT_ID ]] && args+=(-TenantId "$TENANT_ID")
  if ! pwsh "${args[@]}" || [[ ! -s $out ]]; then
    rm -f "$out"
    return 1
  fi
  local fields
  mapfile -t fields < <(python3 -c 'import json,sys
d=json.load(open(sys.argv[1], encoding="utf-8-sig"))
for k in ("tenantId","clientId","clientSecret","role","secretExpires"): print(d.get(k,""))' "$out")
  rm -f "$out"
  TENANT_ID=${fields[0]}; CLIENT_ID=${fields[1]}; CLIENT_SECRET=${fields[2]}
  ROLE=${fields[3]}; SECRET_EXPIRES=${fields[4]}
  [[ -n $TENANT_ID && -n $CLIENT_ID && -n $CLIENT_SECRET ]]
}

paste_setup_code() {  # sets TENANT_ID CLIENT_ID CLIENT_SECRET ROLE SECRET_EXPIRES; returns 1 on a bad code
  echo
  echo "On your Windows or Mac machine, in the folder you extracted PAW Proxy Pilot to, run:"
  echo
  echo "    pwsh ./deploy/New-PAWProxyPilotApp.ps1 -HostName $HOSTNAME_FQDN -Port $PORT -AssignTo you@yourdomain.com"
  echo
  echo "(Windows PowerShell works too. If Windows blocks the script, run Unblock-File on it first.)"
  echo "It signs you in to Entra, creates the app and prints a setup code starting PAWPILOT1."
  local code fields
  ask_secret code "Paste the setup code (hidden)"
  code=${code//[[:space:]]/}
  if ! mapfile -t fields < <(python3 - "$code" <<'PY'
import base64, json, sys
code = sys.argv[1]
if not code.startswith("PAWPILOT1."):
    sys.exit("That doesn't look like a PAW Proxy Pilot setup code (it should start PAWPILOT1.).")
try:
    raw = code[10:]
    d = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)).decode("utf-8-sig"))
except Exception:
    sys.exit("The setup code is damaged or incomplete. Copy the whole line and try again.")
for k in ("tenantId", "clientId", "clientSecret", "role", "secretExpires", "redirectUri"):
    print(d.get(k, ""))
PY
  ) || [[ ${#fields[@]} -lt 6 ]]; then
    return 1
  fi
  TENANT_ID=${fields[0]}; CLIENT_ID=${fields[1]}; CLIENT_SECRET=${fields[2]}
  ROLE=${fields[3]}; SECRET_EXPIRES=${fields[4]}
  local expected="https://$HOSTNAME_FQDN:$PORT/auth/callback"
  if [[ ${fields[5]} != "$expected" ]]; then
    warn "The app was registered for ${fields[5]}, but this server is $expected."
    warn "Sign-in will fail until they match: re-run the script with -HostName $HOSTNAME_FQDN -Port $PORT."
  fi
  echo "Setup code accepted: app $CLIENT_ID in tenant $TENANT_ID, secret expires ${SECRET_EXPIRES:-unknown}."
  [[ -n $TENANT_ID && -n $CLIENT_ID && -n $CLIENT_SECRET ]]
}

enter_entra_manually() {
  echo "Redirect URI to register on the app:  https://$HOSTNAME_FQDN:$PORT/auth/callback"
  ask TENANT_ID "Directory (tenant) ID" "$TENANT_ID"
  ask CLIENT_ID "Application (client) ID" "$CLIENT_ID"
  local new_secret
  ask_secret new_secret "Client secret value (blank keeps the current one)"
  CLIENT_SECRET=${new_secret:-$CLIENT_SECRET}
  ask SECRET_EXPIRES "Secret expiry date, YYYY-MM-DD (blank if unknown)" "$SECRET_EXPIRES"
  ask ROLE "App role required to sign in (type none for no role)" "${ROLE:-PAWProxyPilot.Admin}"
  [[ $ROLE == none ]] && ROLE=""
  ask ALLOWED "Allowed users, comma separated UPNs (blank for anyone with the role)" "$ALLOWED"
}

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
HOSTNAME_FQDN=$(env_get PAWPILOT_BASE_URL | sed -E 's#^https?://##; s#[:/].*$##')
PORT=$(env_get PAWPILOT_PORT)
TENANT_ID=$(env_get PAWPILOT_ENTRA_TENANT_ID)
CLIENT_ID=$(env_get PAWPILOT_ENTRA_CLIENT_ID)
CLIENT_SECRET=$(env_get PAWPILOT_ENTRA_CLIENT_SECRET)
SECRET_EXPIRES=$(env_get PAWPILOT_ENTRA_SECRET_EXPIRES)
ROLE=$(env_get PAWPILOT_REQUIRED_ROLE)
ALLOWED=$(env_get PAWPILOT_ALLOWED_USERS)
ADMIN_UPN=${ALLOWED%%,*}
SESSION_SECRET=$(env_get PAWPILOT_SESSION_SECRET)
[[ -f $ENV_FILE ]] || ROLE=PAWProxyPilot.Admin

ASK_SITE=0; ASK_ENTRA=0
if [[ ! -f $ENV_FILE || $RECONFIGURE -eq 1 ]]; then ASK_SITE=1; ASK_ENTRA=1; fi
if [[ $ENTRA_ONLY -eq 1 ]]; then
  [[ -f $ENV_FILE ]] || { warn "Run the full install first: sudo ./install.sh"; exit 1; }
  ASK_ENTRA=1
fi

if [[ $ASK_SITE -eq 1 ]]; then
  say "PAW Proxy Pilot web address"
  echo "PAW Proxy Pilot needs a DNS name for its web page, e.g. pawproxy.example.com,"
  echo "pointing at this server's internal IP (internal DNS record or hosts file)."
  ask HOSTNAME_FQDN "PAW Proxy Pilot hostname" "${HOSTNAME_FQDN:-pawproxy.example.com}"
  ask PORT "PAW Proxy Pilot web port" "${PORT:-8443}"
  while [[ ! $PORT =~ ^[0-9]+$ || $PORT -lt 1024 || $PORT -gt 65535 || $PORT -eq 3128 ]]; do
    warn "PAW Proxy Pilot's port must be 1024-65535, and not 3128 (that's Squid)."
    ask PORT "PAW Proxy Pilot web port" "8443"
  done
fi
PORT=${PORT:-8443}

if [[ $ASK_ENTRA -eq 1 ]]; then
  say "Entra ID sign-in"
  choice=create
  if [[ -n $CLIENT_ID && $ENTRA_ONLY -eq 0 ]]; then
    echo "Current app: $CLIENT_ID (tenant $TENANT_ID)."
    if yes_no "Keep it?" Y; then
      choice=keep
      echo "If you changed the hostname or port, re-run with --entra to update the redirect URI."
    fi
  fi
  if [[ $choice == create ]]; then
    echo
    echo "How do you want to set up the PAW Proxy Pilot app registration?"
    echo "  1) Paste a setup code from New-PAWProxyPilotApp.ps1 run on your Windows or Mac machine (recommended)"
    echo "  2) Create it from this server (installs PowerShell here; sign in with a device code)"
    echo "  3) Enter the tenant ID, client ID and secret by hand"
    ask how "Choose 1, 2 or 3" "1"
    case $how in
      2)
        if ! create_entra_app; then
          warn "Creating the app from this server didn't finish."
          how=1
        fi ;;
      3) enter_entra_manually ;;
      *) how=1 ;;
    esac
    if [[ $how == 1 ]]; then
      until paste_setup_code; do
        warn "That setup code didn't work."
        yes_no "Try pasting it again?" Y || { enter_entra_manually; break; }
      done
    fi
  fi
  if [[ -z $ROLE && -z $ALLOWED ]]; then
    warn "Set an app role or an allow-list, otherwise nobody can sign in."
    exit 1
  fi
fi

if [[ $ASK_SITE -eq 1 || $ASK_ENTRA -eq 1 ]]; then
  SESSION_SECRET=${SESSION_SECRET:-$(openssl rand -base64 48 | tr -d '\n=+/')}
  umask 027
  cat > "$ENV_FILE" <<EOF
# PAW Proxy Pilot settings. Written by install.sh on $(date -u +%F). See deploy/pawpilot.env.example.
PAWPILOT_BASE_URL=https://$HOSTNAME_FQDN:$PORT
PAWPILOT_LISTEN=0.0.0.0
PAWPILOT_PORT=$PORT
PAWPILOT_TLS_CERT=$TLS_DIR/pawpilot.crt
PAWPILOT_TLS_KEY=$TLS_DIR/pawpilot.key
PAWPILOT_SESSION_SECRET=$SESSION_SECRET
PAWPILOT_SESSION_HOURS=8
PAWPILOT_ENTRA_TENANT_ID=$TENANT_ID
PAWPILOT_ENTRA_CLIENT_ID=$CLIENT_ID
PAWPILOT_ENTRA_CLIENT_SECRET=$CLIENT_SECRET
PAWPILOT_ENTRA_SECRET_EXPIRES=$SECRET_EXPIRES
PAWPILOT_REQUIRED_ROLE=$ROLE
PAWPILOT_ALLOWED_USERS=$ALLOWED
PAWPILOT_SQUID_ACL=$ACL_FILE
PAWPILOT_SQUID_LOG=/var/log/squid/access.log
PAWPILOT_SQUID_SERVICE=squid
PAWPILOT_APPLY_CMD=sudo -n /usr/local/sbin/pawpilot-apply
PAWPILOT_LOG_MAX_MB=32
PAWPILOT_DATA_DIR=$DATA_DIR
EOF
  chown root:pawpilot "$ENV_FILE"
  chmod 0640 "$ENV_FILE"
  umask 022
fi
if [[ $PORT == 3128 ]]; then
  warn "PAW Proxy Pilot is set to port 3128, which Squid needs."
  warn "Run: sudo ./install.sh --reconfigure   and choose 8443."
  exit 1
fi

# --------------------------------------------------------------------------
# Certificate
# --------------------------------------------------------------------------
HOOK=/etc/letsencrypt/renewal-hooks/deploy/pawpilot.sh
write_hook() {
  install -d -m 0755 "$(dirname "$HOOK")"
  cat > "$HOOK" <<EOF
#!/bin/bash
# Copies the renewed PAW Proxy Pilot certificate into place and restarts PAW Proxy Pilot.
set -e
case " \${RENEWED_DOMAINS:-$HOSTNAME_FQDN} " in *" $HOSTNAME_FQDN "*) ;; *) exit 0 ;; esac
install -m 0640 -o root -g pawpilot /etc/letsencrypt/live/$HOSTNAME_FQDN/fullchain.pem $TLS_DIR/pawpilot.crt
install -m 0640 -o root -g pawpilot /etc/letsencrypt/live/$HOSTNAME_FQDN/privkey.pem $TLS_DIR/pawpilot.key
systemctl restart pawpilot || true
EOF
  chmod 0755 "$HOOK"
}

if [[ $ENTRA_ONLY -eq 1 ]]; then
  :  # --entra leaves the certificate alone
elif [[ $SELF_SIGNED -eq 1 ]]; then
  say "Creating a self-signed certificate for $HOSTNAME_FQDN"
  openssl req -x509 -newkey rsa:2048 -nodes -days 825 -subj "/CN=$HOSTNAME_FQDN" \
    -addext "subjectAltName=DNS:$HOSTNAME_FQDN" \
    -keyout "$TLS_DIR/pawpilot.key" -out "$TLS_DIR/pawpilot.crt" 2>/dev/null
  chown root:pawpilot "$TLS_DIR"/pawpilot.*; chmod 0640 "$TLS_DIR"/pawpilot.*
elif [[ -d /etc/letsencrypt/live/$HOSTNAME_FQDN && $RECONFIGURE -eq 0 ]]; then
  say "Let's Encrypt certificate for $HOSTNAME_FQDN already exists; refreshing the copy"
  write_hook
  RENEWED_DOMAINS=$HOSTNAME_FQDN "$HOOK"
else
  say "Let's Encrypt certificate for $HOSTNAME_FQDN (Cloudflare DNS challenge)"
  if [[ ! -s $CF_INI || $RECONFIGURE -eq 1 ]]; then
    echo "Cloudflare API token with Zone > DNS > Edit on the zone for $HOSTNAME_FQDN."
    ask_secret CF_TOKEN "Cloudflare API token"
    [[ -n $CF_TOKEN ]] || { warn "A Cloudflare token is needed (or re-run with --self-signed)."; exit 1; }
    umask 077
    printf 'dns_cloudflare_api_token = %s\n' "$CF_TOKEN" > "$CF_INI"
    chown root:root "$CF_INI"; chmod 0600 "$CF_INI"
    umask 022
  fi
  ask LE_EMAIL "Email for Let's Encrypt expiry notices" ""
  [[ -n $LE_EMAIL ]] || { warn "An email address is needed (or re-run with --self-signed)."; exit 1; }
  write_hook
  certbot certonly --non-interactive --agree-tos -m "$LE_EMAIL" \
    --dns-cloudflare --dns-cloudflare-credentials "$CF_INI" --dns-cloudflare-propagation-seconds 30 \
    -d "$HOSTNAME_FQDN" --deploy-hook "$HOOK"
  RENEWED_DOMAINS=$HOSTNAME_FQDN "$HOOK"
  systemctl enable --now certbot.timer >/dev/null 2>&1 || true
fi

# --------------------------------------------------------------------------
# Squid
# --------------------------------------------------------------------------
valid_cidrs() {  # every word is an IPv4/IPv6 address or CIDR range
  python3 - "$@" <<'PY'
import ipaddress, sys
try:
    [ipaddress.ip_network(a, strict=False) for a in sys.argv[1:]]
except ValueError as exc:
    sys.exit(str(exc))
sys.exit(0 if len(sys.argv) > 1 else "Enter at least one network.")
PY
}

write_squid_conf() {
  local nets
  echo "Which networks are the PAWs on? Only these (and this server) may use the proxy."
  ask nets "PAW networks, space separated CIDR ranges" "10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"
  until valid_cidrs $nets; do
    ask nets "PAW networks, space separated CIDR ranges" "10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"
  done
  if [[ -f $SQUID_CONF_FILE ]]; then
    cp -a "$SQUID_CONF_FILE" "$SQUID_CONF_FILE.pawpilot-$(date +%Y%m%d-%H%M%S)"
  fi
  {
    echo "# Written by the PAW Proxy Pilot installer on $(date -u +%F). Default deny:"
    echo "# PAWs can only reach domains in $ACL_FILE, which PAW Proxy Pilot manages."
    for net in $nets; do echo "acl paw_clients src $net"; done
    cat <<CONF

acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 443
acl PAW_Access dstdomain "$ACL_FILE"

http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow localhost manager
http_access deny manager
http_access deny to_localhost
http_access deny to_linklocal
include /etc/squid/conf.d/*.conf
http_access allow paw_clients PAW_Access
http_access allow localhost PAW_Access
http_access deny all

http_port 3128
cache_effective_group proxy
CONF
  } > "$SQUID_CONF_FILE.new"
  install -m 0644 -o root -g root "$SQUID_CONF_FILE.new" "$SQUID_CONF_FILE"
  rm -f "$SQUID_CONF_FILE.new"
}

if [[ $ENTRA_ONLY -eq 0 ]]; then
  say "Setting up Squid"
  if [[ ! -f $ACL_FILE ]]; then
    install -m 0644 -o root -g root "$APP_DIR/deploy/default-allow.acl" "$ACL_FILE"
    echo "Installed a starter allow list of Microsoft admin endpoints. Review it in PAW Proxy Pilot."
  fi
  chown root:root "$ACL_FILE"; chmod 0644 "$ACL_FILE"

  if [[ $SQUID_CONF -eq 1 ]] || ! grep -q "$ACL_FILE" "$SQUID_CONF_FILE" 2>/dev/null; then
    write_squid_conf
  else
    echo "Keeping the existing $SQUID_CONF_FILE (it already uses $ACL_FILE)."
    if grep -Eq '^acl +localnet +src +0\.0\.0\.0' "$SQUID_CONF_FILE"; then
      warn "squid.conf lets any source address use the proxy. Re-run with --squid-conf to limit it to your PAW networks."
    fi
  fi

  # "en" is what English browsers get; "templates" is the fallback for clients that send no language.
  for dir in /usr/share/squid/errors/en /usr/share/squid/errors/English /usr/share/squid/errors/templates; do
    if [[ -d $dir && ! -L $dir ]]; then
      install -m 0644 -o root -g root "$APP_DIR/deploy/ERR_ACCESS_DENIED.html" "$dir/ERR_ACCESS_DENIED"
    fi
  done

  if squid -k parse >/dev/null 2>&1; then
    systemctl reload-or-restart squid
  else
    warn "Squid doesn't accept its configuration. Check: sudo squid -k parse"
    exit 1
  fi

  # Leftovers from the old Flask version of PAW Proxy Pilot.
  if systemctl list-unit-files paw_proxy_pilot.service >/dev/null 2>&1 \
     && systemctl list-unit-files paw_proxy_pilot.service | grep -q paw_proxy_pilot; then
    echo
    echo "The old Flask version of PAW Proxy Pilot is installed (service paw_proxy_pilot, behind nginx)."
    echo "Its allowed and hidden lists are imported automatically the first time the new version starts."
    if yes_no "Stop and disable the old service and its nginx site?" Y; then
      systemctl disable --now paw_proxy_pilot >/dev/null 2>&1 || true
      rm -f /etc/nginx/sites-enabled/paw_proxy_pilot
      systemctl reload nginx >/dev/null 2>&1 || true
      echo "Done. MySQL, nginx and /opt/paw_proxy_pilot are left in place; remove them when you're happy."
      echo "The old sudo rule for 'systemctl restart squid' is also still in /etc/sudoers: remove it with visudo."
    fi
  fi
fi

# --------------------------------------------------------------------------
# Service
# --------------------------------------------------------------------------
say "Starting PAW Proxy Pilot"
install -m 0644 "$APP_DIR/deploy/pawpilot.service" /etc/systemd/system/pawpilot.service
systemctl daemon-reload
systemctl enable pawpilot >/dev/null 2>&1
systemctl restart pawpilot
sleep 2
if systemctl is-active --quiet pawpilot; then
  say "Done"
  echo "Open https://$HOSTNAME_FQDN:$PORT and sign in with Entra ID."
  if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
    echo "UFW is active. Allow PAW Proxy Pilot and the proxy from your networks only, e.g.:"
    echo "    sudo ufw allow from 192.168.0.0/16 to any port $PORT proto tcp"
    echo "    sudo ufw allow from 192.168.0.0/16 to any port 3128 proto tcp"
  fi
  echo "Point the PAWs' proxy setting at this server on port 3128."
  echo "Do NOT port-forward $PORT or 3128 on the router. PAW Proxy Pilot is for your internal network only."
else
  warn "PAW Proxy Pilot didn't start. Check: journalctl -u pawpilot -n 50"
  exit 1
fi
