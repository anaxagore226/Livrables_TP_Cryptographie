#!/usr/bin/env bash
# renouveler.sh - renouvelle le certificat du serveur www.tp.local s'il expire
# dans moins de SEUIL_JOURS jours (ou toujours avec --force).
#   1. nouvelle cle + nouvelle demande   2. signature par l'AC intermediaire
#   3. verification de la chaine AVANT deploiement   4. installation, test de la
#   configuration, rechargement de nginx sans interruption   5. archivage de
#   l'ancien certificat et retour arriere automatique en cas d'echec.
set -euo pipefail
export MSYS_NO_PATHCONV=1

# --- Parametres (surchargeables par l'environnement) -----------------------------
PKI_DIR="${PKI_DIR:-/opt/pki}"                  # dossier de l'IGC (inter.cnf, racine/, inter/)
TLS_DIR="${TLS_DIR:-/etc/nginx/tls}"            # fichiers lus par nginx
NOM="${NOM:-www.tp.local}"
SAN="${SAN:-DNS:www.tp.local,DNS:tp.local}"
JOURS="${JOURS:-90}"
SEUIL_JOURS="${SEUIL_JOURS:-30}"
NGINX_TEST="${NGINX_TEST:-nginx -t}"
NGINX_RELOAD="${NGINX_RELOAD:-systemctl reload nginx}"

log() { echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') renouveler: $*"; }

# --- 0. Faut-il renouveler ? --------------------------------------------------------
if [ "${1:-}" != "--force" ] && \
   openssl x509 -in "$TLS_DIR/serveur_chaine.crt" -noout -checkend $((SEUIL_JOURS * 86400)) >/dev/null; then
    log "certificat valable encore plus de $SEUIL_JOURS jours : rien a faire"
    exit 0
fi

TRAVAIL="$(mktemp -d)"
trap 'rm -rf "$TRAVAIL"' EXIT
# Git Bash (Windows) uniquement : chemin /tmp -> chemin Windows lisible par openssl
if command -v cygpath >/dev/null; then TRAVAIL="$(cygpath -m "$TRAVAIL")"; fi
umask 077

# --- 1. Nouvelle cle et nouvelle demande (la cle ne quitte pas le serveur) ----------
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$TRAVAIL/serveur.key"
openssl req -new -key "$TRAVAIL/serveur.key" -subj "/CN=$NOM" \
    -addext "subjectAltName=$SAN" -out "$TRAVAIL/serveur.csr"

# --- 2. Signature par l'AC intermediaire ---------------------------------------------
( cd "$PKI_DIR" && openssl ca -batch -config inter.cnf -extensions ext_serveur \
      -days "$JOURS" -in "$TRAVAIL/serveur.csr" -out "$TRAVAIL/serveur.crt" ) 2>/dev/null
cat "$TRAVAIL/serveur.crt" "$PKI_DIR/inter/inter.crt" > "$TRAVAIL/serveur_chaine.crt"

# --- 3. Verifications avant tout deploiement -----------------------------------------
openssl verify -CAfile "$PKI_DIR/racine/racine.crt" -untrusted "$PKI_DIR/inter/inter.crt" \
    -verify_hostname "$NOM" -purpose sslserver "$TRAVAIL/serveur.crt" >/dev/null
# la cle correspond-elle bien au certificat ?
[ "$(openssl pkey -in "$TRAVAIL/serveur.key" -pubout)" = \
  "$(openssl x509 -in "$TRAVAIL/serveur.crt" -noout -pubkey)" ] || { log "cle/certificat incoherents"; exit 1; }
log "nouveau certificat verifie (serie $(openssl x509 -in "$TRAVAIL/serveur.crt" -noout -serial | cut -d= -f2))"

# --- 4 et 5. Archivage, installation, test, rechargement ou retour arriere ----------
ARCHIVE="$TLS_DIR/archive/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$ARCHIVE"
cp -p "$TLS_DIR/serveur_chaine.crt" "$TLS_DIR/serveur.key" "$ARCHIVE/"

install -m 600 "$TRAVAIL/serveur.key"         "$TLS_DIR/serveur.key.new"
install -m 644 "$TRAVAIL/serveur_chaine.crt"  "$TLS_DIR/serveur_chaine.crt.new"
mv -f "$TLS_DIR/serveur.key.new"        "$TLS_DIR/serveur.key"          # remplacement atomique
mv -f "$TLS_DIR/serveur_chaine.crt.new" "$TLS_DIR/serveur_chaine.crt"

if $NGINX_TEST >/dev/null 2>&1 && $NGINX_RELOAD >/dev/null 2>&1; then
    log "certificat installe et nginx recharge ; ancien conserve dans $ARCHIVE"
else
    log "ECHEC du test ou du rechargement de nginx : retour a l'ancien certificat"
    cp -p "$ARCHIVE/serveur_chaine.crt" "$ARCHIVE/serveur.key" "$TLS_DIR/"
    $NGINX_TEST >/dev/null 2>&1 && $NGINX_RELOAD >/dev/null 2>&1 || true
    exit 1
fi
