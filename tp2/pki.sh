#!/usr/bin/env bash
# pki.sh - construit l'IGC du TP 2 (etapes 1 a 4) : racine -> intermediaire -> serveur + client.
# A lancer dans le dossier pki/ contenant racine.cnf et inter.cnf (annexe B).
set -euo pipefail
export MSYS_NO_PATHCONV=1        # Git Bash (Windows) : ne pas transformer "/CN=..." en chemin
umask 077                        # tout fichier cree n'est lisible que par son proprietaire

cd "$(dirname "$0")"
[ -f racine.cnf ] && [ -f inter.cnf ] || { echo "racine.cnf / inter.cnf manquants" >&2; exit 1; }

# --- Etape 1 : arborescence (serial et crlnumber : 1000 pour la racine, 2000 pour l'intermediaire)
init_ac() {   # $1 = dossier, $2 = premier numero
    if [ -e "$1/index.txt" ]; then
        echo "ERREUR : $1/ existe deja, rien n'est ecrase" >&2; exit 1
    fi
    mkdir -p "$1"/{certs,crl,newcerts}
    : > "$1/index.txt"
    echo "unique_subject = no" > "$1/index.txt.attr"   # autorise le renouvellement (TP 3)
    echo "$2" > "$1/serial"
    echo "$2" > "$1/crlnumber"
}
init_ac racine 1000
init_ac inter 2000

# --- Etape 2 : AC racine (P-384, 10 ans, auto-signee) ------------------------------
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out racine/racine.key
openssl req -x509 -new -key racine/racine.key -sha384 -days 3650 \
    -subj "/C=BF/O=Universite TP/CN=Racine TP" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" -out racine/racine.crt

# --- Etape 3 : AC intermediaire (P-256, 5 ans), signee par la racine --------------
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out inter/inter.key
openssl req -new -key inter/inter.key \
    -subj "/C=BF/O=Universite TP/CN=AC Intermediaire TP" -out inter/inter.csr
openssl ca -batch -config racine.cnf -extensions ext_inter -days 1825 \
    -in inter/inter.csr -out inter/inter.crt

# --- Etape 4 : certificats feuilles (chaque demandeur genere sa propre cle) ---------
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out serveur.key
openssl req -new -key serveur.key -subj "/CN=www.tp.local" \
    -addext "subjectAltName=DNS:www.tp.local,DNS:tp.local" -out serveur.csr
openssl ca -batch -config inter.cnf -extensions ext_serveur -days 90 \
    -in serveur.csr -out serveur.crt

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out alice.key
openssl req -new -key alice.key -subj "/CN=alice@tp.local" -out alice.csr
openssl ca -batch -config inter.cnf -extensions ext_client -days 90 \
    -in alice.csr -out alice.crt

# --- Controle : on ne termine que si les chaines sont valides ----------------------
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt \
    -verify_hostname www.tp.local serveur.crt
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt \
    -purpose sslclient alice.crt
chmod 644 racine/racine.crt inter/inter.crt serveur.crt alice.crt
echo "IGC construite avec succes."
