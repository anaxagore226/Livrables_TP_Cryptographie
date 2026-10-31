# Ingénierie de la cryptographie (EC1) - Travaux pratiques

Travaux pratiques du module **EC1 – Ingénierie de la cryptographie** (cryptologie, clés et certificats),
École Polytechnique de Ouagadougou, IGIT 2, année universitaire 2026–2027.

- **Étudiant :** TANKOANO Yamindi Martin
- **Enseignant :** Dr. Zakaria Sawadogo

Le projet assemble des primitives cryptographiques éprouvées, sans en réimplémenter aucune, pour construire
un système complet :

| TP | Sujet | Réalisation | Rapport |
|----|-------|-------------|---------|
| **TP 1** | Chiffrement authentifié et dérivation de clés | Coffre de fichiers `coffre.py` (Argon2id + HKDF + AES-256-GCM), 13 tests pytest | [tp1/Rapport_TP1_chiffrement_authentifie.md](tp1/Rapport_TP1_chiffrement_authentifie.md) |
| **TP 2** | Infrastructure de gestion de clés (IGC) | AC racine P-384 → AC intermédiaire contrainte → certificats serveur et client, CRL, script `pki.sh` | [tp2/Rapport_TP2_infrastructure_de_cles.md](tp2/Rapport_TP2_infrastructure_de_cles.md) |
| **TP 3** | Canal TLS et gestion des certificats | nginx TLS 1.2/1.3 avec authentification mutuelle et CRL, supervision `surveiller.py`, renouvellement `renouveler.sh` | [tp3/Rapport_TP3_canal_TLS.md](tp3/Rapport_TP3_canal_TLS.md) |

Chaque dossier contient aussi les réponses détaillées aux questions de réflexion du TP
(`Reponses_Questions_TP1.md`, `Reponses_Questions_TP2.md`, `Reponses_Questions_TP3.md`).

---

## Arborescence

```
.
├── README.md                                   ce fichier
│
├── tp1/                                        TP 1 – Coffre de fichiers
│   ├── coffre.py                               module de chiffrement au format CFR1
│   ├── test_coffre.py                          tests des propriétés de sécurité (pytest)
│   ├── mesure_argon2.py                        mesure du temps de dérivation Argon2id
│   ├── Rapport_TP1_chiffrement_authentifie.md  rapport du TP 1
│   └── Reponses_Questions_TP1.md               réponses aux questions de réflexion
│
├── tp2/                                        TP 2 – Infrastructure de gestion de clés
│   ├── racine.cnf, inter.cnf                   configurations des AC (annexe B de l'énoncé)
│   ├── bob.ext                                 extensions du certificat client de Bob
│   ├── pki.sh                                  construction automatique de l'IGC
│   ├── racine.crt, inter.crt                   certificats des autorités
│   ├── serveur.crt, alice.crt,                 certificats finaux (alice et example : révoqués)
│   │   bob.crt, example.crt
│   ├── racine.crl, inter.crl, crls.pem         listes de révocation
│   ├── Rapport_TP2_infrastructure_de_cles.md   rapport du TP 2
│   └── Reponses_Questions_TP2.md               réponses aux questions de réflexion
│
└── tp3/                                        TP 3 – Canal TLS sécurisé
    ├── tp.conf                                 configuration nginx finale (durcie)
    ├── tp_initial_enonce.conf                  configuration de l'énoncé, avant durcissement
    ├── surveiller.py                           supervision des dates d'expiration
    ├── renouveler.sh                           renouvellement automatique du certificat serveur
    ├── capture.pcap                            capture de la poignée de main TLS 1.3 mutuelle
    ├── Rapport_TP3_canal_TLS.md                rapport du TP 3
    └── Reponses_Questions_TP3.md               réponses aux questions de réflexion
```

Les certificats et les CRL de `tp2/` sont ceux obtenus pendant le TP et cités dans les rapports.
Conformément aux règles du TP, **aucune clé privée** (`*.key`) n'est fournie.

---

## Prérequis

- Linux (machine, VM ou conteneur) ou Windows avec **Git Bash**
- **Python 3.10+** et **OpenSSL 3.x**
- Bibliothèques Python : `cryptography`, `argon2-cffi`, `pytest`
- Pour le TP 3 : **nginx**, ou **Docker** (méthode utilisée ici sous Windows)

```bash
python3 -m venv ~/ec1 && source ~/ec1/bin/activate
pip install cryptography argon2-cffi pytest
openssl version            # doit afficher OpenSSL 3.x
```

Versions utilisées pour les résultats des rapports : Python 3.14.7, cryptography 50.0.2, argon2-cffi 25.1.0,
pytest 9.2.0, OpenSSL 3.2.1 (hôte), nginx 1.31.8 (`nginx:alpine`), Docker 29.7.2.

Toutes les commandes ci-dessous se lancent depuis la racine du projet.

---

## TP 1 — Coffre de fichiers

Format d'un fichier chiffré (`CFR1`) :

```
| "CFR1" 4 o | t, m, p 12 o | sel 16 o | nonce 12 o | chiffré n o | étiquette GCM 16 o |
|<---------- en-tête 44 octets (données associées, avec le nom du fichier) -------->|
```

Clé AES-256 = `HKDF-SHA256(Argon2id(mot de passe, sel, t=3, m=256 Mio, p=4), info="coffre-v1|chiffrement")`.

```bash
cd tp1

# Lancer les tests (13 tests)
python -m pytest -v test_coffre.py

# Mesurer Argon2id sur sa machine (viser ~0,5 s, machine au repos)
python mesure_argon2.py

# Chiffrer / déchiffrer un fichier (le mot de passe est demandé au clavier)
python coffre.py chiffrer notes.txt notes.txt.cfr
python coffre.py dechiffrer notes.txt.cfr notes.txt
```

Utilisation comme bibliothèque :

```python
from coffre import chiffrer, dechiffrer, rechiffrer

blob = chiffrer("mot de passe", "notes.txt", b"contenu")
assert dechiffrer("mot de passe", "notes.txt", blob) == b"contenu"
blob = rechiffrer("mot de passe", "nouveau mot de passe", "notes.txt", blob)
```

Un mauvais mot de passe, un octet modifié ou un nom de fichier différent lèvent tous la même exception
`InvalidTag` ; un en-tête invalide lève `FormatInconnu`.

---

## TP 2 — Infrastructure de gestion de clés

```
Racine TP (P-384, 10 ans, hors ligne, pathlen:1)
└── AC Intermédiaire TP (P-256, 5 ans, pathlen:0, nameConstraints tp.local)
    ├── www.tp.local      serveur, 90 jours
    ├── bob@tp.local      client, 90 jours
    ├── alice@tp.local    client, révoqué (keyCompromise)
    └── www.example.com   signé mais refusé à la validation (contrainte de nom)
```

Construire une IGC neuve (le script refuse d'écraser une AC existante) :

```bash
cd tp2
bash pki.sh                     # crée racine/, inter/, serveur.*, alice.*
```

> Les certificats fournis à la racine de `tp2/` sont ceux des rapports. `pki.sh` génère une IGC **nouvelle**
> (nouvelles clés) dans les sous-dossiers `racine/` et `inter/` : les commandes suivantes utilisent ces
> nouveaux fichiers.

Émettre le certificat client de Bob (utilisé au TP 3). La section `ext_client` de `inter.cnf` écrit en dur
l'adresse d'Alice : les extensions propres à Bob (section `ext_client_bob`, SAN `email:bob@tp.local`)
sont donc dans le fichier `bob.ext` fourni :

```bash
export MSYS_NO_PATHCONV=1       # Git Bash uniquement
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out bob.key
openssl req -new -key bob.key -subj "/CN=bob@tp.local" -out bob.csr
openssl ca -batch -config inter.cnf -extfile bob.ext -extensions ext_client_bob \
    -days 90 -in bob.csr -out bob.crt
```

Valider, puis révoquer :

```bash
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt \
    -verify_hostname www.tp.local serveur.crt                     # OK

openssl ca -config inter.cnf -revoke alice.crt -crl_reason keyCompromise
openssl ca -config inter.cnf  -gencrl -out inter/crl/inter.crl
openssl ca -config racine.cnf -gencrl -out racine/crl/racine.crl
cat inter/crl/inter.crl racine/crl/racine.crl > crls.pem
openssl verify -crl_check_all -CRLfile crls.pem -CAfile racine/racine.crt \
    -untrusted inter/inter.crt alice.crt                          # certificate revoked
```

---

## TP 3 — Canal TLS avec authentification mutuelle

### Déploiement avec Docker

Prérequis : avoir exécuté les commandes du TP 2 (IGC, certificat de Bob, `crls.pem`).

```bash
mkdir -p tp3/tls
cat tp2/serveur.crt tp2/inter/inter.crt > tp3/tls/serveur_chaine.crt
cp tp2/serveur.key tp2/racine/racine.crt tp2/crls.pem tp3/tls/

docker network create tpnet
docker run -d --name nginx-tp --network tpnet --network-alias www.tp.local -p 443:443 \
    -v "$PWD/tp3/tls:/etc/nginx/tls:ro" \
    -v "$PWD/tp3/tp.conf:/etc/nginx/conf.d/tp.conf:ro" nginx:alpine
docker exec nginx-tp nginx -t
```

Sous Linux sans Docker : copier les fichiers dans `/etc/nginx/tls/` (clé en mode 600), placer `tp.conf`
dans la configuration de nginx, ajouter `127.0.0.1 www.tp.local` à `/etc/hosts`, puis
`sudo nginx -t && sudo systemctl reload nginx`.

### Tests depuis un conteneur client

```bash
docker build -t tp-client - <<'EOF'
FROM alpine:3.20
RUN apk add --no-cache curl openssl nmap nmap-scripts tshark bash
EOF

docker run --rm --network tpnet -v "$PWD/tp2:/pki" -w /pki tp-client sh -c '
  cat bob.crt inter/inter.crt > /tmp/bob_chaine.crt
  curl --cacert racine/racine.crt --cert /tmp/bob_chaine.crt --key bob.key https://www.tp.local/
  nmap --script ssl-enum-ciphers -p 443 www.tp.local'
```

Réponse attendue : `Bonjour CN=bob@tp.local`. Le client doit envoyer **sa chaîne** (`bob.crt` + `inter.crt`) :
nginx ne fait confiance qu'à la racine.

### Supervision et renouvellement

```bash
# Codes de sortie : 0 = OK, 1 = ALERTE (< 30 jours), 2 = CRITIQUE (< 7 jours)
python tp3/surveiller.py tp3/tls --alerte 30 --critique 7

# Renouvelle seulement si le certificat expire dans moins de 30 jours (--force pour forcer)
PKI_DIR="$PWD/tp2" TLS_DIR="$PWD/tp3/tls" \
NGINX_TEST="docker exec nginx-tp nginx -t" \
NGINX_RELOAD="docker exec nginx-tp nginx -s reload" \
    bash tp3/renouveler.sh
```

Planification quotidienne (cron) :

```
17 3 * * *  PKI_DIR=/opt/pki TLS_DIR=/etc/nginx/tls /opt/pki/renouveler.sh >> /var/log/renouveler.log 2>&1
```

Nettoyage : `docker rm -f nginx-tp && docker network rm tpnet`

---

## Principaux résultats

| Mesure | Résultat |
|--------|----------|
| Tests du coffre | 13 / 13 réussis |
| Dérivation Argon2id (t = 3, m = 256 Mio, p = 4) | ≈ 0,49 s |
| Validations de l'IGC | OK, puis erreurs 62 (nom), 26 (usage), 47 (contrainte de nom), 25 (profondeur), 23 (révoqué) comme attendu |
| Suites TLS 1.2 après durcissement | 13 → 3 (ECDHE + AEAD uniquement) ; TLS 1.1 refusé |
| Poignée de main | TLS 1.3, TLS_AES_256_GCM_SHA384, X25519 ; certificats invisibles dans la capture |
| Renouvellement à chaud | 300 / 300 requêtes réussies, retour arrière automatique vérifié |

Le détail des étapes, des sorties de commandes et des réponses aux questions se trouve dans le rapport et
le fichier `Reponses_Questions_TPn.md` de chaque dossier.

---

## Notes pour Windows (Git Bash)

- Exporter `MSYS_NO_PATHCONV=1` avant les commandes OpenSSL : sinon `-subj "/CN=..."` est transformé en
  chemin Windows (`pki.sh` le fait déjà).
- `python3` s'appelle `python`.
- Le `curl` de Windows (Schannel) exige une vérification de révocation : ajouter `--ssl-no-revoke`, ou
  utiliser le conteneur client.
- Les fichiers PEM ont des fins de ligne CR+LF : un octet de plus par ligne que sous Linux.

---

## Sécurité

- **Aucune clé privée** (`*.key`) n'est versionnée ni fournie : `pki.sh` les régénère.
- Les clés d'AC sont créées sans phrase de passe (`-nodes`), ce qui n'est acceptable qu'en laboratoire.
  En production : racine hors ligne, HSM, phrase de passe forte.
- Toutes les manipulations portent sur des noms de laboratoire (`*.tp.local`) et sur sa propre machine.
  Ne scanner ou tester aucun système sans autorisation écrite.
