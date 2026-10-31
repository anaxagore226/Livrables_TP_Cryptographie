# Rapport de TP 3

## Déployer un canal sécurisé et gérer les certificats

**École Polytechnique de Ouagadougou** — IGIT 2 — Module EC1 : Ingénierie de la cryptographie

| | |
|---|---|
| **Étudiant** | TANKOANO Yamindi Martin |
| **Classe** | IGIT 2 |
| **Enseignant** | Dr. Zakaria Sawadogo |
| **Année universitaire** | 2026 – 2027 |
| **Date de remise** | 31 octobre 2026 |

**Livrables joints.** Dans ce dossier (`tp3/`) : `tp.conf` (configuration nginx finale),
`tp_initial_enonce.conf` (configuration de l'énoncé), `surveiller.py`, `renouveler.sh`, `capture.pcap`.

---

## Sommaire

1. [Introduction et objectifs](#1-introduction-et-objectifs)
2. [Environnement de travail](#2-environnement-de-travail)
3. [Préalable : observations de la série guidée](#3-préalable--observations-de-la-série-guidée)
4. [Étape 1 – Préparer les fichiers](#4-étape-1--préparer-les-fichiers)
5. [Étape 2 – Configurer nginx](#5-étape-2--configurer-nginx)
6. [Étape 3 – Observer la poignée de main](#6-étape-3--observer-la-poignée-de-main)
7. [Étape 4 – Vérifier et durcir la configuration](#7-étape-4--vérifier-et-durcir-la-configuration)
8. [Étape 5 – Superviser les expirations](#8-étape-5--superviser-les-expirations)
9. [Étape 6 – Automatiser le renouvellement](#9-étape-6--automatiser-le-renouvellement)
10. [Questions de réflexion](#10-questions-de-réflexion)
11. [Difficultés rencontrées et solutions](#11-difficultés-rencontrées-et-solutions)
12. [Conclusion](#12-conclusion)

---

## 1. Introduction et objectifs

Ce TP met en service l'infrastructure de gestion de clés construite au TP 2 : un serveur web protégé par
TLS, qui authentifie aussi ses clients par certificat, puis exploité dans la durée (supervision des
expirations, renouvellement automatique).

Objectifs du TP :

- configurer un serveur web en TLS 1.2 et 1.3 avec une configuration moderne ;
- mettre en place l'authentification mutuelle des clients par certificat (mTLS) ;
- analyser une connexion TLS avec les outils en ligne de commande ;
- superviser les dates d'expiration et automatiser le renouvellement.

---

## 2. Environnement de travail

Le TP demande une machine Linux avec nginx. Le poste étant sous Windows 11, le serveur et le client ont
été déployés dans des **conteneurs Docker Linux** (option « conteneur » prévue par l'énoncé), reliés par
un réseau privé `tpnet`. Dans ce réseau, le conteneur nginx porte l'alias DNS `www.tp.local`, ce qui
remplace la modification de `/etc/hosts`.

| Outil | Version | Rôle |
|---|---|---|
| Docker | 29.7.2 | conteneurs du serveur et du client |
| nginx (`nginx:alpine`) | 1.31.8, compilé avec OpenSSL 3.5.9 | serveur TLS |
| Conteneur client Alpine 3.20 | OpenSSL 3.3.7 · curl 8.14.1 · nmap 7.95 · TShark 4.2.5 | connexions, scan des suites, capture réseau |
| OpenSSL (hôte, Git Bash) | 3.2.1 | IGC du TP 2, renouvellement |
| Python | 3.14.7 | `surveiller.py` |

**Figure 1 – Architecture de test**

```
+---------------------------+   TLS 1.3 · X25519 · AES-256-GCM   +-------------------------------+
|     Conteneur client      | ---------------------------------> |      Conteneur nginx-tp       |
| Alpine 3.20 · OpenSSL 3.3 |                                    | nginx 1.31.8 · OpenSSL 3.5.9  |
| curl · nmap · tshark      | <--------------------------------- | www.tp.local:443              |
| bob.crt + inter.crt       |   certificat chiffré + demande     | ECDHE + AEAD · mTLS + CRL     |
+---------------------------+       (réseau Docker « tpnet »)    +-------------------------------+
                                                                                ^
                                                                                |
+---------------------------+   nouvelle chaîne, nginx -t, reload +-------------------------------+
|  Hôte Windows (Git Bash)  | ---------------------------------> |   tls/ (lecture seule)        |
| IGC pki/ : racine, inter, |                                    | serveur_chaine.crt            |
| CRL                       |                                    | serveur.key (600) · racine.crt|
| renouveler.sh             |                                    | crls.pem · archive/           |
| surveiller.py             |                                    |                               |
+---------------------------+                                    +-------------------------------+
```

**Règles suivies.** Seul notre serveur de laboratoire a été scanné ; aucune clé privée dans les
livrables ; chaque résultat cité provient d'une exécution réelle.

---

## 3. Préalable : observations de la série guidée

Le TP 3 de la série guidée (« Mon premier site web sécurisé ») a servi de première approche, avec un
serveur HTTPS en Python et le certificat de la mini-AC.

| Manipulation | Observation | Enseignement |
|---|---|---|
| Connexion sans indiquer l'AC | Refus : autorité inconnue | Le client doit faire confiance à l'autorité |
| Connexion avec l'AC | Page servie ; TLS 1.3, AES-256-GCM, X25519 | La chaîne aboutit à une ancre de confiance |
| Connexion sous un autre nom | Refus : nom absent du certificat | Le nom est vérifié dans le SAN |
| Option `curl -k` | Page servie même avec un faux nom | Désactiver la vérification supprime l'authentification |
| Contrôle d'expiration (`-checkend`) | Valable dans 30 jours, pas dans 100 | Surveiller l'échéance des certificats |

Ce TP passe à un vrai serveur (nginx), ajoute l'authentification des clients et la révocation, et
automatise l'exploitation.

---

## 4. Étape 1 – Préparer les fichiers

```bash
cat serveur.crt inter/inter.crt > serveur_chaine.crt       # feuille + intermédiaire (2 certificats)
# Énoncé :   sudo install -m 600 serveur.key /etc/nginx/tls/serveur.key
#            sudo install -m 644 serveur_chaine.crt racine/racine.crt crls.pem /etc/nginx/tls/
# Réalisé :  fichiers copiés dans tp3/tls/, monté en lecture seule dans le conteneur
docker network create tpnet
docker run -d --name nginx-tp --network tpnet --network-alias www.tp.local -p 443:443 \
    -v $PWD/tls:/etc/nginx/tls:ro -v $PWD/tp.conf:/etc/nginx/conf.d/tp.conf:ro nginx:alpine
```

Le serveur présente sa **chaîne** (son certificat suivi de l'intermédiaire), jamais la racine. La clé
privée est installée en mode 600 (lisible par root seul) ; les certificats et la CRL, publics, en 644.

---

## 5. Étape 2 – Configurer nginx

Configuration finale (celle de l'énoncé, plus la directive `ssl_ciphers` ajoutée à l'étape 4) :

```nginx
server {
    listen 443 ssl;
    server_name www.tp.local;

    ssl_certificate         /etc/nginx/tls/serveur_chaine.crt;
    ssl_certificate_key     /etc/nginx/tls/serveur.key;
    ssl_protocols           TLSv1.2 TLSv1.3;
    # TLS 1.2 : uniquement ECDHE (confidentialite persistante) + AEAD
    ssl_ciphers             ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;
    ssl_session_tickets     off;

    # Authentification mutuelle des clients
    ssl_client_certificate  /etc/nginx/tls/racine.crt;
    ssl_verify_client       on;
    ssl_verify_depth        2;
    ssl_crl                 /etc/nginx/tls/crls.pem;

    add_header Strict-Transport-Security "max-age=31536000" always;

    location / {
        return 200 "Bonjour $ssl_client_s_dn\n";
    }
}
```

```
$ nginx -t
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful
```

**Justification de chaque directive :**

| Directive | Justification |
|---|---|
| `listen 443 ssl` | Port HTTPS standard, TLS activé sur ce port. |
| `server_name www.tp.local` | Nom servi ; il correspond au SAN du certificat et au nom (SNI) envoyé par le client. |
| `ssl_certificate` | Chaîne envoyée au client : feuille + intermédiaire, pour qu'il remonte jusqu'à la racine qu'il possède. |
| `ssl_certificate_key` | Clé privée du serveur (mode 600), qui sert uniquement à signer la poignée de main. |
| `ssl_protocols TLSv1.2 TLSv1.3` | Interdit SSL, TLS 1.0 et 1.1 (attaques par repli, chiffrements faibles). |
| `ssl_ciphers ECDHE…GCM/CHACHA20` | **Ajouté** : en TLS 1.2, seulement ECDHE (confidentialité persistante) et des AEAD. Sans effet sur TLS 1.3, dont les suites sont toutes sûres. |
| `ssl_prefer_server_ciphers off` | Toutes les suites restantes sont sûres : on laisse le client choisir (ChaCha20 pour un mobile sans AES matériel). |
| `ssl_session_tickets off` | Pas de tickets de reprise chiffrés par une clé jamais renouvelée : préserve la confidentialité persistante. |
| `ssl_client_certificate racine.crt` | Ancre de confiance pour les certificats clients : seule notre racine. |
| `ssl_verify_client on` | Authentification mutuelle obligatoire : sans certificat client valide, la requête est refusée. |
| `ssl_verify_depth 2` | Profondeur maximale de la chaîne client : client → intermédiaire → racine. |
| `ssl_crl crls.pem` | Les deux CRL (intermédiaire et racine) : un client révoqué est refusé. À republier avant expiration. |
| `add_header Strict-Transport-Security … always` | HSTS : le navigateur n'utilisera plus que HTTPS pour ce domaine pendant un an, y compris sur les réponses d'erreur. |
| `return 200 "Bonjour $ssl_client_s_dn"` | Page de test qui affiche l'identité du client authentifié. |

---

## 6. Étape 3 – Observer la poignée de main

Le certificat d'Alice ayant été révoqué au TP 2, un certificat client a d'abord été émis pour Bob.

```
$ openssl s_client -connect www.tp.local:443 -servername www.tp.local -verify_hostname www.tp.local \
      -CAfile racine/racine.crt -cert bob.crt -key bob.key -cert_chain inter/inter.crt -brief
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer certificate: CN=www.tp.local
Hash used: SHA256
Signature type: ECDSA
Verification: OK
Verified peername: www.tp.local
Server Temp Key: X25519, 253 bits
--- requête HTTP dans la même connexion ---
HTTP/1.1 200 OK
Strict-Transport-Security: max-age=31536000
Bonjour CN=bob@tp.local
```

| Élément relevé | TLS 1.3 (par défaut) | TLS 1.2 (option `-tls1_2`) |
|---|---|---|
| Version | TLSv1.3 | TLSv1.2 |
| Suite de chiffrement | TLS_AES_256_GCM_SHA384 | ECDHE-ECDSA-AES256-GCM-SHA384 |
| Groupe d'échange de clés | X25519 (éphémère, 253 bits) | X25519 (ECDHE) |
| Signature du serveur | ECDSA P-256 / SHA-256 | ECDSA P-256 / SHA-256 |
| Vérification du serveur | OK, nom vérifié www.tp.local | OK, nom vérifié www.tp.local |
| Authentification du client | Bob accepté (200) | Bob accepté (200) |

**Cas d'échec** (réponses de nginx et journal d'erreurs) :

| Connexion | Résultat | Explication |
|---|---|---|
| Sans certificat client | 400 « No required SSL certificate was sent » | En TLS 1.3, la poignée de main aboutit, puis nginx refuse la requête |
| Alice, certificat révoqué | 400 ; journal : « 23 : certificate revoked » | Son numéro de série figure dans la CRL chargée par `ssl_crl` |
| Bob avec `bob.crt` seul (commande curl de l'énoncé) | 400 ; journal : « 21 : unable to verify the first certificate » | nginx ne connaît que la racine : le client doit envoyer sa chaîne |
| Bob avec `bob.crt` + `inter.crt` | 200 « Bonjour CN=bob@tp.local » | Chaîne complète |

**Capture réseau** (tshark, connexion de Bob) :

```
4  172.19.0.3 -> 172.19.0.2  TLSv1    583 Client Hello (SNI=www.tp.local)
6  172.19.0.2 -> 172.19.0.3  TLSv1.3 1670 Server Hello, Change Cipher Spec, Application Data, ...
8  172.19.0.3 -> 172.19.0.2  TLSv1.3 1324 Change Cipher Spec, Application Data, Application Data, ...
9-15                          TLSv1.3      Application Data
ClientHello : SNI www.tp.local ; suites TLS 1.3 (AES-128-GCM, AES-256-GCM, ChaCha20) ; key_share x25519
ServerHello : TLS_AES_256_GCM_SHA384 ; TLS 1.3 ; key_share x25519
Messages "Certificate" visibles dans la capture : 0
Occurrences du mot "Bonjour" dans la capture : 0
```

**Pourquoi le certificat du serveur n'est pas visible en TLS 1.3.** Dès le *ServerHello*, les deux
parties possèdent les parts Diffie-Hellman et calculent le secret commun, d'où elles dérivent les clés
de poignée de main. Tous les messages suivants (certificats du serveur et de Bob, signatures, messages
de fin) sont chiffrés en AES-256-GCM et n'apparaissent que comme « Application Data ». En TLS 1.2, au
contraire, le certificat passait en clair. Seuls le *ClientHello* et le *ServerHello* restent lisibles,
dont le nom du site (SNI). Le contenu de la page n'apparaît nulle part.

---

## 7. Étape 4 – Vérifier et durcir la configuration

**TLS 1.1 doit être refusé :**

```
$ openssl s_client -connect www.tp.local:443 -tls1_1 -cipher "DEFAULT:@SECLEVEL=0" -brief
error:0A00042E:SSL routines:ssl3_read_bytes:tlsv1 alert protocol version: SSL alert number 70
```

C'est bien le **serveur** qui refuse, par l'alerte TLS n° 70 « protocol_version ». Sans l'option
`@SECLEVEL=0`, le client OpenSSL 3 refuse déjà de proposer TLS 1.1.

**Suites acceptées (`nmap --script ssl-enum-ciphers`)** : avec la configuration de l'énoncé, toutes les
suites utilisaient ECDHE, mais **TLS 1.2 acceptait encore des suites CBC**, sans chiffrement authentifié
(sensibles aux oracles de bourrage). Conformément à la consigne, la configuration a été corrigée par la
directive `ssl_ciphers`, puis rechargée à chaud (`nginx -t` puis `nginx -s reload`).

| Version | Avant correction | Après correction |
|---|---|---|
| TLS 1.2 | 13 suites, dont AES-CBC et Camellia-CBC (sans AEAD), CCM, ARIA | 3 suites : ECDHE-ECDSA avec AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 (toutes notées A) |
| TLS 1.3 | AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 | inchangé (toutes les suites TLS 1.3 sont des AEAD) |
| TLS 1.1 | refusé (alerte n° 70) | refusé |

Remarque : le nginx déployé (OpenSSL 3.5) accepterait aussi l'échange hybride post-quantique
X25519MLKEM768 avec un client récent ; notre client OpenSSL 3.3 négocie X25519.

---

## 8. Étape 5 – Superviser les expirations

Le script `surveiller.py` lit tous les certificats PEM d'un dossier, y compris chacun des certificats
d'une chaîne (l'expiration de l'intermédiaire bloquerait autant le site), et affiche le nombre de jours
restants avec trois niveaux. Les fichiers qui ne sont pas des certificats (CRL, clés) sont ignorés. Son
code de sortie suit la convention des outils de supervision (Nagios, Zabbix).

Test avec des certificats émis pour 5 et 20 jours :

```
$ python surveiller.py surv3/
NIVEAU     JOURS  EXPIRATION (UTC)  FICHIER                      SUJET
OK          90.0  2027-01-26 15:38 bob.crt                      CN=bob@tp.local
OK        1825.0  2031-10-27 15:37 inter.crt                    CN=AC Intermediaire TP,O=Universite TP,C=BF
OK        3650.0  2036-10-25 15:37 racine.crt                   CN=Racine TP,O=Universite TP,C=BF
OK          90.0  2027-01-26 15:37 serveur_chaine.crt           CN=www.tp.local
OK        1825.0  2031-10-27 15:37 serveur_chaine.crt           CN=AC Intermediaire TP,O=Universite TP,C=BF
ALERTE      20.0  2026-11-17 15:42 test20.crt                   CN=test20.tp.local
CRITIQUE     5.0  2026-11-02 15:42 test5.crt                    CN=test5.tp.local
Etat global : CRITIQUE (7 certificats)
code de sortie : 2
```

| Contenu du dossier | État global | Code de sortie |
|---|---|---|
| Certificats à 90 jours et plus | OK | 0 |
| + un certificat à 20 jours | ALERTE (moins de 30 jours) | 1 |
| + un certificat à 5 jours | CRITIQUE (moins de 7 jours) | 2 |

---

## 9. Étape 6 – Automatiser le renouvellement

Le script `renouveler.sh` ne renouvelle le certificat du serveur que s'il expire dans moins de 30 jours
(ou toujours avec `--force`) :

1. il génère une nouvelle clé et une nouvelle demande, localement ;
2. il fait signer la demande par l'AC intermédiaire ;
3. il vérifie, **avant tout déploiement**, la chaîne, le nom, l'usage serverAuth et la correspondance
   entre la clé et le certificat ;
4. il installe les nouveaux fichiers par remplacement atomique, teste la configuration (`nginx -t`) et
   recharge nginx sans interruption ;
5. il archive l'ancien couple clé/certificat et revient automatiquement en arrière en cas d'échec.

| Essai | Résultat |
|---|---|
| Exécution normale (certificat à 90 jours) | « certificat valable encore plus de 30 jours : rien à faire », code 0 |
| Renouvellement forcé par le seuil (`SEUIL_JOURS=100`), avec 300 requêtes TLS mutuelles en parallèle | Nouveau certificat servi (série 2000 → 2007) ; **300 requêtes réussies sur 300** |
| Configuration invalide simulée (`NGINX_TEST=false`) | « ECHEC du test… retour à l'ancien certificat », code 1 ; la série 2007 est toujours servie |

**Planification quotidienne** (cron) :

```
17 3 * * *  PKI_DIR=/opt/pki TLS_DIR=/etc/nginx/tls /opt/pki/renouveler.sh >> /var/log/renouveler.log 2>&1
```

Une variante avec un minuteur systemd (`OnCalendar=daily`, `Persistent=true`) est fournie dans le
compte rendu détaillé. Amélioration possible : révoquer automatiquement (motif *superseded*) un
certificat émis puis abandonné lors d'un retour arrière.

---

## 10. Questions de réflexion

### Q1. Pourquoi le serveur ne doit-il pas envoyer le certificat racine ?

Parce que c’est **inutile** et que cela peut faire croire à une sécurité qui n’existe pas. La racine est l’ancre de confiance : le client doit **déjà** l’avoir dans son magasin de confiance, obtenue par un canal sûr. Une racine reçue du serveur pendant la connexion ne peut pas être crue, puisque n’importe quel attaquant peut envoyer sa propre « racine ». Le client l’ignore donc et utilise sa propre copie. L’envoyer ne fait que **gaspiller de la bande passante** à chaque poignée de main (un certificat de plus, avec une signature) et peut entraîner un découpage en paquets supplémentaires. C’est pourquoi `serveur_chaine.crt` ne contient que la feuille et l’intermédiaire (diapo 86).

### Q2. Quel est l’intérêt de désactiver les tickets de session lorsque les clés de tickets ne sont pas renouvelées ?

Un ticket de session contient l’état de la session (secret de reprise), **chiffré avec une clé de ticket** (STEK) connue du serveur seul, et stocké par le client. Par défaut, nginx tire cette clé au démarrage et ne la change **jamais** tant qu’il n’est pas redémarré, ce qui peut durer des mois. Un attaquant qui enregistre le trafic puis vole cette clé (fuite mémoire, sauvegarde) peut déchiffrer les tickets, en tirer les secrets de reprise, et donc déchiffrer toutes les sessions reprises (en TLS 1.2, même les sessions complètes). La **confidentialité persistante** apportée par ECDHE est alors annulée pour toute la durée de vie de la clé de ticket (diapos 102, 105).

Désactiver les tickets (`ssl_session_tickets off`) supprime ce secret à long terme ; le coût est une poignée de main complète de plus, négligeable ici. L’alternative est de faire tourner les clés de ticket fréquemment (`ssl_session_ticket_key` renouvelée toutes les quelques heures, partagée entre les serveurs d’une grappe).

### Q3. Que garantit l’en-tête HSTS ? Contre quelle attaque protège-t-il ?

Avec `Strict-Transport-Security: max-age=31536000`, reçu par HTTPS, le navigateur retient pendant **un an** que ce site ne doit être contacté **qu’en HTTPS** : il réécrit lui-même tout lien `http://` en `https://` avant d’envoyer quoi que ce soit, et transforme les erreurs de certificat en erreurs **bloquantes** (impossible de « continuer quand même »).

Il protège contre l’attaque par **retrait de TLS** (« SSL stripping », Moxie Marlinspike, 2009). Un homme du milieu sur un Wi-Fi public intercepte la première requête en HTTP en clair, garde lui-même la connexion HTTPS avec le site, et sert la victime en HTTP : identifiants et cookies passent en clair. Il protège aussi contre les utilisateurs qui ignoreraient un avertissement de certificat. Limite : la toute première visite reste vulnérable (avant d’avoir reçu l’en-tête). On y remédie avec `includeSubDomains; preload` et l’inscription dans la liste de préchargement intégrée aux navigateurs.

### Q4. La durée maximale des certificats publics passe à 100 jours en 2027 puis à 47 jours en 2029. Quelles conséquences pour une organisation qui renouvelle à la main ?

Le nombre de renouvellements explose : avec 47 jours, chaque certificat doit être renouvelé environ **8 fois par an** (dans la pratique tous les ~30 jours, pour garder une marge). Pour une organisation de 3 000 certificats, cela fait environ 3 000 × 365 / 47 ≈ **23 000 opérations par an, soit 60 à 100 par jour ouvré**. C’est impossible à la main sans erreurs. Chaque oubli est un certificat expiré, donc une panne de service (diapo 91 : « un certificat géré à la main est un incident programmé »).

- Il faut un **inventaire** complet (découverte réseau, journaux CT) avec un propriétaire par certificat.
- Il faut automatiser l’émission et le déploiement avec **ACME** (certbot, cert-manager), comme notre `renouveler.sh`, vérification et retour arrière compris.
- Il faut une **supervision** des échéances (alertes à 30, 14 et 7 jours), comme `surveiller.py`.
- Les équipements qui n’acceptent pas l’automatisation (appliances, anciens systèmes) doivent être remplacés ou placés derrière un proxy automatisé.

Le bénéfice est réel : une clé volée ou un certificat mal émis ne reste utilisable que quelques semaines, ce qui compense une révocation qui fonctionne mal sur le Web (diapo 89).

### Q5. Un serveur expose un certificat valide mais la chaîne est incomplète : pourquoi certains clients l’acceptent-ils et d’autres non ?

Si le serveur n’envoie que sa feuille, le client doit trouver **lui-même** l’intermédiaire pour remonter jusqu’à une racine de confiance. Certains clients compensent : les **navigateurs** gardent en cache les intermédiaires vus sur d’autres sites, Firefox embarque la liste de tous les intermédiaires publics, et Chrome et Windows vont télécharger l’intermédiaire à l’adresse indiquée dans l’extension *Authority Information Access* (caIssuers) du certificat. La page s’affiche donc chez l’administrateur, qui croit que tout va bien.

D’autres clients ne font rien de tout cela : `openssl`, `curl`, Python, Java, les applications mobiles, les objets connectés, les appels entre API. Ils échouent avec « unable to get local issuer certificate ». Nous l’avons reproduit dans l’autre sens à l’étape 3 : Bob qui envoie `bob.crt` sans l’intermédiaire est rejeté par nginx (« 21 : unable to verify the first certificate »), alors que la même identité avec sa chaîne est acceptée. Règle : toujours servir la **chaîne complète sans la racine** et la tester avec un client strict (`openssl s_client -showcerts`, SSL Labs).

### Q6. Proposer une procédure de réaction si la clé privée du serveur fuit.

| Phase | Actions |
|---|---|
| 1. Confirmer et contenir (heure 0) | Ouvrir un incident, identifier la clé et les certificats concernés (n° de série), couper l’accès de l’attaquant (correctif, mots de passe, accès au serveur). |
| 2. Remplacer (≤ 1 h) | `renouveler.sh --force` : **nouvelle clé** générée sur le serveur (jamais réutiliser l’ancienne), nouveau certificat, vérification, déploiement à chaud ; contrôler le numéro de série réellement servi. |
| 3. Révoquer (immédiatement après) | `openssl ca -revoke ancien.crt -crl_reason keyCompromise`, régénérer et publier la CRL, la recharger sur tous les serveurs qui vérifient (`ssl_crl`) ; pour un certificat public, demander la révocation à l’AC. |
| 4. Secrets dérivés | Renouveler les clés de tickets de session, les jetons et sessions applicatives, les autres certificats qui partageaient la clé ; détruire les copies de l’ancienne clé, y compris les archives. |
| 5. Évaluer l’impact | Grâce à ECDHE (confidentialité persistante), les échanges passés enregistrés restent protégés ; le risque porte sur l’usurpation du serveur entre la fuite et la révocation. Vérifier les journaux et surveiller les journaux CT pour détecter des certificats émis à notre nom. |
| 6. Clôturer | Informer les utilisateurs (et l’autorité compétente si des données personnelles sont touchées), analyser la cause, corriger (HSM, droits, sauvegardes chiffrées), mettre à jour la procédure. |

---

## 11. Difficultés rencontrées et solutions

| Difficulté | Cause | Solution retenue |
|---|---|---|
| nginx indisponible sous Windows | Logiciel prévu pour Linux | Conteneurs Docker `nginx:alpine` et Alpine (curl, nmap, tshark) |
| `/etc/hosts` non modifiable sans droits administrateur | Poste Windows | Alias DNS `www.tp.local` dans le réseau Docker |
| Messages d'erreur curl différents de l'énoncé | Le curl de Windows utilise Schannel | Client Linux dans un conteneur |
| `curl --cert bob.crt` refusé par nginx | Intermédiaire absent de la chaîne envoyée par le client | Envoyer `bob.crt` + `inter.crt` |
| Suites CBC acceptées en TLS 1.2 | Configuration de l'énoncé sans `ssl_ciphers` | Directive `ssl_ciphers` limitée à ECDHE + AEAD |
| `renouveler.sh` : « Can't open /tmp/… » | Chemin temporaire de Git Bash illisible par l'OpenSSL Windows | Conversion avec `cygpath` (sans effet sous Linux) |
| Raison précise d'un refus client invisible | Le journal nginx standard ne la donne pas | Conteneur de débogage avec `error_log … info` |

---

## 12. Conclusion

Le serveur nginx déployé n'accepte que TLS 1.2 et 1.3 avec ECDHE et des chiffrements authentifiés,
authentifie ses clients par certificat en appliquant les CRL du TP 2, et s'exploite sans interruption :
`surveiller.py` signale les échéances et `renouveler.sh` remplace le certificat à chaud, avec retour
arrière automatique. Les mesures le confirment : alerte n° 70 pour TLS 1.1, 13 suites TLS 1.2 réduites
à 3, certificats invisibles dans la capture, et 300 requêtes sur 300 servies pendant un renouvellement.

Deux défauts n'ont été détectés que parce qu'ils ont été **testés** : les suites CBC laissées actives par
la configuration de l'énoncé (vues par nmap) et la chaîne incomplète envoyée par le client (vue dans le
journal de nginx). Ce TP confirme le message du cours : la cryptographie est rarement cassée, elle est
contournée ou mal configurée.

**Perspectives** : émission automatique par ACME avec une AC interne, agrafage OCSP, en-tête HSTS avec
`includeSubDomains; preload`, et activation de l'échange hybride post-quantique X25519MLKEM768.
