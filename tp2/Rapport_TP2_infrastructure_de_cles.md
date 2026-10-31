# Rapport de TP 2

## Construire une infrastructure de gestion de clés

**École Polytechnique de Ouagadougou** — IGIT 2 — Module EC1 : Ingénierie de la cryptographie

| | |
|---|---|
| **Étudiant** | TANKOANO Yamindi Martin |
| **Classe** | IGIT 2 |
| **Enseignant** | Dr. Zakaria Sawadogo |
| **Année universitaire** | 2026 – 2027 |
| **Date de remise** | 31 octobre 2026 |

**Livrables joints.** Dans ce dossier (`tp2/`) : `pki.sh`, `racine.cnf`, `inter.cnf`, `bob.ext`,
certificats publics (`racine.crt`, `inter.crt`, `serveur.crt`, `alice.crt`, `bob.crt`, `example.crt`)
et listes de révocation (`racine.crl`, `inter.crl`, `crls.pem`). Conformément à la consigne, **aucune
clé privée** n'est jointe.

---

## Sommaire

1. [Introduction et objectifs](#1-introduction-et-objectifs)
2. [Environnement de travail](#2-environnement-de-travail)
3. [Préalable : observations de la série guidée](#3-préalable--observations-de-la-série-guidée)
4. [Architecture visée et réalisée](#4-architecture-visée-et-réalisée)
5. [Étape 1 – Préparer les autorités](#5-étape-1--préparer-les-autorités)
6. [Étapes 2 à 4 – Racine, intermédiaire et certificats finaux](#6-étapes-2-à-4--racine-intermédiaire-et-certificats-finaux)
7. [Étape 5 – Valider](#7-étape-5--valider)
8. [Étape 6 – Révoquer](#8-étape-6--révoquer)
9. [Étape 7 – Automatiser](#9-étape-7--automatiser)
10. [Défaut relevé dans la configuration fournie](#10-défaut-relevé-dans-la-configuration-fournie)
11. [Questions de réflexion](#11-questions-de-réflexion)
12. [Difficultés rencontrées et solutions](#12-difficultés-rencontrées-et-solutions)
13. [Conclusion](#13-conclusion)

---

## 1. Introduction et objectifs

La cryptographie à clé publique suppose que l'on connaît la **bonne** clé publique. Sans moyen de lier
une clé à une identité, un attaquant peut publier sa propre clé sous le nom d'un autre : c'est l'attaque
de l'homme du milieu, contre laquelle aucun algorithme ne protège. Une infrastructure de gestion de clés
(IGC) résout ce problème par des certificats signés par des autorités de confiance.

Objectifs du TP :

- créer une AC racine et une AC intermédiaire avec les bonnes extensions ;
- émettre des certificats de serveur et de client à partir de demandes de certificat (CSR) ;
- valider une chaîne de certificats et comprendre chaque contrôle ;
- révoquer un certificat et publier une liste de révocation (CRL) ;
- restreindre une AC intermédiaire par des contraintes de nom.

---

## 2. Environnement de travail

Les manipulations ont été faites sur un poste Windows 11, dans le terminal Git Bash, avec
**OpenSSL 3.2.1**. Une seule adaptation a été nécessaire : `export MSYS_NO_PATHCONV=1`, sans laquelle Git
Bash transforme l'argument `-subj "/CN=..."` en chemin Windows.

**Règles suivies.** Noms de domaine de laboratoire uniquement (`*.tp.local`) ; aucune clé privée dans les
livrables ; chaque résultat cité provient d'une exécution réelle. Les clés, numéros de série et dates
diffèrent d'une exécution à l'autre.

---

## 3. Préalable : observations de la série guidée

Le TP 2 de la série guidée (« Clés, signatures et certificats ») a introduit les notions utilisées ici.

| Manipulation | Observation | Enseignement |
|---|---|---|
| Paires RSA-3072 et Ed25519 | Clés publiques de 625 et 113 octets (Linux) | Courbes elliptiques : même sécurité, objets beaucoup plus petits |
| Signature Ed25519 d'un contrat, puis contrat modifié (100 → 900) | « Verified Successfully » puis « Verification Failure » ; contrat toujours lisible | Intégrité + origine + non-répudiation, mais pas de confidentialité |
| Chiffrement RSA-OAEP d'un secret de 22 octets | Chiffré de 384 octets ; deux chiffrés différents | OAEP est probabiliste ; pour de gros fichiers : chiffrement hybride |
| Certificat de www.wikipedia.org | CN `*.wikipedia.org`, émis par Let's Encrypt YE2, 90 jours, 41 noms, ECDSA P-256 | L'émetteur (AC) diffère du sujet ; chaîne jusqu'à une racine ISRG |
| Mini-AC « AC de la classe » et certificat monsite.tp.local | `verify` OK avec `-CAfile` ; « unable to get local issuer certificate » sans | La confiance vient du magasin de confiance, pas du certificat lui-même |

Ce TP prolonge la mini-AC de la série guidée en une hiérarchie réaliste à deux niveaux, avec
contraintes, révocation et automatisation.

---

## 4. Architecture visée et réalisée

| Élément | Clé et durée | Extensions essentielles |
|---|---|---|
| AC racine « Racine TP » | P-384, 10 ans, hors ligne | `CA:TRUE, pathlen:1` ; signature de certificats et de CRL |
| AC intermédiaire « AC Intermediaire TP » | P-256, 5 ans | `CA:TRUE, pathlen:0` ; contraintes de nom limitées à `tp.local` |
| Serveur `www.tp.local` | P-256, 90 jours | `CA:FALSE` ; usage « serveur TLS » ; noms alternatifs |
| Client `alice@tp.local` (et `bob@tp.local`) | P-256, 90 jours | `CA:FALSE` ; usage « client TLS » |

**Figure 1 – Hiérarchie de certification construite et état des certificats**

```
                    +--------------------------------------------+
                    |          Racine TP (auto-signée)           |
                    |  P-384 · 10 ans · hors ligne               |
                    |  CA:TRUE, pathlen:1                        |
                    +--------------------------------------------+
                                        |  signe (serial 0x1000) + CRL racine (30 j)
                                        v
                    +--------------------------------------------+
                    |           AC Intermédiaire TP              |
                    |  P-256 · 5 ans · CA:TRUE, pathlen:0        |
                    |  nameConstraints : .tp.local, tp.local,    |
                    |                    email:tp.local          |
                    +--------------------------------------------+
                         |              |             |             |   CRL inter : 7 jours
                         v              v             v             v
              +--------------+ +--------------+ +--------------+ +------------------+
              | www.tp.local | | bob@tp.local | |alice@tp.local| | www.example.com  |
              | serveur 90 j | | client 90 j  | |   RÉVOQUÉ    | | signé mais       |
              | serverAuth   | | clientAuth   | | keyCompromise| | REFUSÉ : permitted|
              | SAN DNS      | | SAN email    | |   (CRL)      | | subtree violation|
              +--------------+ +--------------+ +--------------+ +------------------+

  Toute vérification remonte jusqu'à la racine, seule ancre de confiance.
```

---

## 5. Étape 1 – Préparer les autorités

Les fichiers `racine.cnf` et `inter.cnf` sont ceux de l'annexe B de l'énoncé, recopiés à l'identique,
dans l'arborescence demandée : `racine/` et `inter/` contiennent chacun `index.txt` (vide), `serial`,
`crlnumber` (1000 pour la racine, 2000 pour l'intermédiaire) et les dossiers `certs/`, `crl/`,
`newcerts/`. Ces nombres sont **hexadécimaux** : le premier certificat signé par la racine porte le
numéro 0x1000 = 4096.

Un seul fichier a été ajouté à la base de chaque AC : `index.txt.attr` contenant `unique_subject = no`.
Il permet d'émettre un nouveau certificat pour un sujet qui en possède déjà un valide, ce qui est
indispensable au renouvellement du TP 3.

**Rôle de chaque ligne des sections d'extensions :**

| Ligne | Rôle |
|---|---|
| `[ext_inter] basicConstraints = critical,CA:TRUE,pathlen:0` | Le titulaire est une AC, mais aucune AC ne peut exister sous elle (seulement des certificats finaux). Critique : un logiciel qui ne la comprend pas doit rejeter le certificat. |
| `keyUsage = critical,keyCertSign,cRLSign` | La clé ne peut servir qu'à signer des certificats et des listes de révocation. |
| `nameConstraints = critical,permitted;DNS:.tp.local,permitted;DNS:tp.local,permitted;email:tp.local` | Limite ce que l'intermédiaire peut certifier : sous-domaines de `tp.local`, `tp.local` lui-même et les adresses `@tp.local`. Tout autre nom est refusé à la validation. |
| `subjectKeyIdentifier = hash` | Identifiant de la clé publique du titulaire : permet aux certificats signés par cette AC de la désigner. |
| `authorityKeyIdentifier = keyid` | Identifiant de la clé de l'émetteur : aide à construire la chaîne. |
| `[ext_serveur] basicConstraints = critical,CA:FALSE` | Certificat final : il ne peut pas signer d'autres certificats. |
| `keyUsage = critical,digitalSignature` | La clé sert uniquement à signer (signature de la poignée de main TLS). |
| `extendedKeyUsage = serverAuth` | Usage limité à l'authentification d'un serveur TLS. |
| (SAN du serveur) | Absent de la section : avec `copy_extensions = copy`, le SAN demandé dans la CSR (`DNS:www.tp.local,DNS:tp.local`) est recopié. |
| `[ext_client] extendedKeyUsage = clientAuth` | Usage limité à l'authentification d'un client TLS (TLS mutuel). |
| `subjectAltName = email:alice@tp.local` | Identité du client, contrôlée par la contrainte `email:tp.local`. **Écrite en dur** : voir la partie 10. |
| `copy_extensions = none / copy` | La racine n'accepte aucune extension de la CSR ; l'intermédiaire recopie celles qui ne sont pas déjà définies dans la section, si bien que `CA:FALSE` ou `keyUsage` ne peuvent pas être imposés par le demandeur. |

---

## 6. Étapes 2 à 4 – Racine, intermédiaire et certificats finaux

Les étapes 2 à 4 sont regroupées dans le script `pki.sh` (partie 9).

**Étape 2 – AC racine** (`openssl x509 -in racine/racine.crt -noout -text`, extrait) :

```
Signature Algorithm: ecdsa-with-SHA384
Issuer: C=BF, O=Universite TP, CN=Racine TP
Validity
    Not Before: Oct 28 15:37:38 2026 GMT
    Not After : Oct 25 15:37:38 2036 GMT
Subject: C=BF, O=Universite TP, CN=Racine TP
Public Key Algorithm: id-ecPublicKey   Public-Key: (384 bit)   NIST CURVE: P-384
X509v3 Basic Constraints: critical
    CA:TRUE, pathlen:1
X509v3 Key Usage: critical
    Certificate Sign, CRL Sign
X509v3 Subject Key Identifier: 7F:84:0E:79:79:C9:55:58:86:57:E6:CF:DE:96:52:59:C7:E2:9F:87
X509v3 Authority Key Identifier: 7F:84:0E:79:79:C9:55:58:86:57:E6:CF:DE:96:52:59:C7:E2:9F:87
```

Émetteur = sujet : le certificat racine est **auto-signé**, car personne ne le signe au-dessus. Son
identifiant de clé d'autorité est d'ailleurs égal à son propre identifiant de clé. Sa signature ne prouve
donc rien (n'importe qui peut fabriquer « Racine TP ») : la confiance vient de sa distribution par un
canal sûr et de son ajout dans le magasin de confiance des clients.

**Étape 3 – AC intermédiaire**, signée par la racine pour 5 ans :

```
Serial Number: 4096 (0x1000)
Issuer: C=BF, O=Universite TP, CN=Racine TP
Subject: C=BF, O=Universite TP, CN=AC Intermediaire TP
Public-Key: (256 bit)  NIST CURVE: P-256
X509v3 Basic Constraints: critical
    CA:TRUE, pathlen:0                                   <- présent
X509v3 Name Constraints: critical                        <- présent
    Permitted:
      DNS:.tp.local
      DNS:tp.local
      email:tp.local
```

**Étape 4 – Certificats finaux.** Chaque demandeur génère sa propre clé et sa demande ; l'intermédiaire
signe.

```
subject=CN=www.tp.local
issuer=C=BF, O=Universite TP, CN=AC Intermediaire TP
serial=2000          notBefore=Oct 28 2026   notAfter=Jan 26 2027   (90 jours)
X509v3 Basic Constraints: critical  CA:FALSE
X509v3 Key Usage: critical  Digital Signature
X509v3 Extended Key Usage: TLS Web Server Authentication
X509v3 Subject Alternative Name: DNS:www.tp.local, DNS:tp.local

subject=CN=alice@tp.local      serial=2001
X509v3 Extended Key Usage: TLS Web Client Authentication
X509v3 Subject Alternative Name: email:alice@tp.local
```

---

## 7. Étape 5 – Valider

| Cas testé | Résultat obtenu | Contrôle de validation concerné |
|---|---|---|
| `serveur.crt` pour www.tp.local | OK | Signatures, dates, nom dans le SAN, chaîne jusqu'à la racine |
| `serveur.crt` pour autre.example | erreur 62 : hostname mismatch | Nom attendu absent du SAN |
| `alice.crt` comme client | OK | Usage étendu clientAuth |
| `alice.crt` comme serveur (test supplémentaire) | erreur 26 : unsuitable certificate purpose | Usage étendu inadapté |
| Certificat www.example.com signé par l'intermédiaire | erreur 47 : permitted subtree violation | Contraintes de nom de l'intermédiaire |
| Sous-AC créée sous l'intermédiaire (test supplémentaire) | erreur 25 : path length constraint exceeded (×2) | pathlen:0 de l'intermédiaire et pathlen:1 de la racine |

**Pourquoi l'AC a-t-elle pu signer un certificat refusé ensuite ?** `openssl ca` est un outil de
signature : il applique sa politique (ici seulement « commonName fourni ») et signe ce qu'on lui présente.
Il ne relit pas les contraintes de nom inscrites dans le certificat de l'AC qui signe. Les contraintes
de nom ne sont pas une règle d'émission mais une **règle de validation** : elles sont écrites, et signées
par la racine, dans le certificat de l'intermédiaire, et c'est le **vérificateur** (navigateur,
`openssl verify`, nginx) qui les applique. La protection ne dépend donc pas du bon comportement de
l'intermédiaire : même si sa clé est volée, tout certificat hors de `tp.local` qu'il signerait sera
refusé partout. Le certificat `example.crt` a ensuite été révoqué (motif *cessationOfOperation*).

---

## 8. Étape 6 – Révoquer

On suppose que la clé d'Alice a été compromise.

```
$ openssl ca -config inter.cnf -revoke alice.crt -crl_reason keyCompromise
Revoking Certificate 2001.
$ openssl ca -config inter.cnf -gencrl -out inter/crl/inter.crl
$ openssl ca -config racine.cnf -gencrl -out racine/crl/racine.crl
$ cat inter/crl/inter.crl racine/crl/racine.crl > crls.pem
$ openssl verify -crl_check_all -CRLfile crls.pem -CAfile racine/racine.crt -untrusted inter/inter.crt alice.crt
error 23 at 0 depth lookup: certificate revoked
$ openssl verify -crl_check_all ... serveur.crt                     # contrôle : non révoqué
serveur.crt: OK
$ openssl crl -in inter/crl/inter.crl -noout -text
    Issuer: C=BF, O=Universite TP, CN=AC Intermediaire TP
    Last Update: Oct 28 15:37:54 2026 GMT
    Next Update: Nov  4 15:37:54 2026 GMT                (default_crl_days = 7)
    X509v3 CRL Number: 8192                              (0x2000)
Revoked Certificates:
    Serial Number: 2001
        X509v3 CRL Reason Code: Key Compromise
```

La CRL est signée par l'intermédiaire, numérotée et datée : elle n'est valable que jusqu'à *Next Update*,
ce qui oblige à la republier au moins chaque semaine. L'option `-crl_check_all` impose une CRL à
**chaque** niveau, d'où la concaténation des deux CRL dans `crls.pem`, qui sert aussi à nginx au TP 3.

---

## 9. Étape 7 – Automatiser

Le script `pki.sh` regroupe les étapes 1 à 4. Choix de conception :

- `set -euo pipefail` : arrêt à la première erreur, à toute variable non définie ou à tout échec dans
  un enchaînement de commandes ;
- `umask 077` : les clés privées sont créées lisibles par leur seul propriétaire ;
- refus de réinitialiser une AC existante, pour ne jamais perdre une base ;
- vérification finale des deux chaînes avant d'annoncer le succès.

```
$ bash pki.sh
...
serveur.crt: OK
alice.crt: OK
IGC construite avec succes.          (code de sortie 0)
```

---

## 10. Défaut relevé dans la configuration fournie

> **La section `ext_client` fige l'identité d'Alice.**
>
> La section `ext_client` de `inter.cnf` définit `subjectAltName = email:alice@tp.local`. Les extensions
> de la section ayant priorité sur celles de la demande, un certificat client émis pour Bob avec cette
> section porte **l'adresse d'Alice**. Nous l'avons vérifié :
>
> ```
> subject=CN=bob@tp.local
> X509v3 Subject Alternative Name: email:alice@tp.local      <- identité d'Alice
> ```
>
> Un serveur qui identifie ses clients par le SAN donnerait à Bob les droits d'Alice. Ce certificat de
> test a été révoqué immédiatement (motif *superseded*). Le certificat de Bob utilisé au TP 3 a été émis
> avec une section dédiée (`bob.ext`, même contenu mais `email:bob@tp.local`). **Correction
> proposée** : retirer le SAN de `ext_client` et reprendre celui de la demande, après vérification de
> l'adresse par l'autorité d'enregistrement.

Deux autres limites de la configuration ont été notées : les certificats n'ont pas d'extension
`crlDistributionPoints` (un client ne sait pas où trouver la CRL), et les clés d'AC sont créées sans
phrase de passe (`-nodes`), ce qui n'est acceptable qu'en laboratoire.

---

## 11. Questions de réflexion

### Q1. Pourquoi la clé de la racine doit-elle rester hors ligne ? Que faut-il faire si l’intermédiaire est compromis ? Et la racine ?

La clé racine est l’ancre de toute la confiance : quiconque la détient peut créer des intermédiaires et donc des certificats pour n’importe quel nom, acceptés par tous les clients. Or elle ne sert presque jamais : signer un intermédiaire tous les cinq ans et une CRL de la racine par mois. La garder **hors ligne** (machine déconnectée, HSM, coffre, cérémonie de clés à plusieurs personnes, partage de secret pour la sauvegarde) supprime la surface d’attaque réseau sans gêner l’exploitation quotidienne, assurée par l’intermédiaire (diapo 86).

**Intermédiaire compromis :** la racine le **révoque** (CRL de la racine republiée aussitôt) ; on crée un nouvel intermédiaire avec une nouvelle clé, on réémet et redéploie tous les certificats finaux, et on cherche la cause. Le dégât est limité grâce aux contraintes de nom (seulement `tp.local`) et à `pathlen:0`. **Racine compromise :** personne au-dessus ne peut la révoquer. Il faut la retirer de **tous** les magasins de confiance, créer une nouvelle racine, la distribuer à tous les clients par un canal sûr, puis reconstruire toute la hiérarchie (cas DigiNotar, diapo 94). C’est un incident majeur, d’où l’importance de la garder hors ligne.

### Q2. À quoi sert pathlen:0 sur l’intermédiaire ? Quel risque si on l’oublie ?

`pathlen:0` signifie : « cette AC peut signer des certificats, mais aucun des certificats qu’elle signe ne peut être une AC ». Elle ne peut émettre que des certificats finaux. Si on l’oublie, l’intermédiaire, ou un attaquant qui a volé sa clé, peut créer des **sous-AC**. Celles-ci échappent à l’inventaire et aux audits, et peuvent elles-mêmes émettre des certificats, voire être confiées à des tiers. La surface de confiance grandit sans contrôle.

Nous l’avons testé en créant une « Sous-AC pirate » (CA:TRUE) signée avec la clé de l’intermédiaire, puis un certificat `faux.tp.local` signé par elle :

```
$ openssl verify -CAfile racine/racine.crt -untrusted chaine.pem f.crt
error 25 at 2 depth lookup: path length constraint exceeded     <- pathlen:0 de l'intermediaire
error 25 at 3 depth lookup: path length constraint exceeded     <- pathlen:1 de la racine
error f.crt: verification failed
```

Les deux contraintes se déclenchent : le `pathlen:1` de la racine suffirait à lui seul dans notre hiérarchie. Le `pathlen:0` de l’intermédiaire est une **défense en profondeur** : il reste valable même si la racine signe un jour d’autres intermédiaires ou est réémise sans cette limite. Il exprime aussi explicitement la politique à l’endroit où elle s’applique.

### Q3. Pourquoi la clé privée du serveur est-elle générée par le serveur et non par l’AC ?

Parce qu’une clé privée ne doit **jamais circuler**. Le serveur la génère, ne transmet que sa CSR (clé publique et nom) signée avec cette clé, ce qui prouve qu’il la possède, et l’AC signe sans jamais voir la clé (diapo 85). Si l’AC générait la clé : il faudrait la lui envoyer, ou qu’elle la renvoie, ce qui l’expose en transit et dans les sauvegardes ; l’AC (ou quiconque la pirate) pourrait se faire passer pour le serveur et déchiffrer ce qui lui est destiné, et toute notion de non-répudiation disparaîtrait. L’AC deviendrait aussi un réservoir de clés de tous ses clients, une cible de grande valeur. Ce n’est pas le rôle d’une AC : elle atteste un lien entre une clé publique et un nom, elle n’a pas besoin du secret. C’est pourquoi `pki.sh` et `renouveler.sh` génèrent la clé du côté du demandeur.

### Q4. Le CN et le SAN contiennent tous deux www.tp.local. Lequel les clients modernes vérifient-ils ?

Le **SAN** (noms alternatifs du sujet). Depuis la RFC 6125 (2011), remplacée par la RFC 9525 (2023), et les exigences du CA/Browser Forum, le nom du serveur doit être cherché dans l’extension SAN. Le CN n’est plus qu’un libellé : Chrome (depuis la version 58), Firefox, la bibliothèque `ssl` de Python (depuis 3.7), Go et d’autres l’ignorent complètement, et OpenSSL ne s’en sert pas dès qu’un SAN DNS existe. C’est pourquoi notre CSR place les noms dans le SAN. Le contrôle `-verify_hostname` de l’étape 5 et les contraintes de nom portent sur le SAN. Vérifier le CN est d’ailleurs une erreur classique (diapo 84).

### Q5. Quelles sont les limites des CRL ? Comparer avec OCSP et avec des certificats de très courte durée.

| Critère | CRL | OCSP (avec agrafage) | Certificats très courts (jours, heures) |
|---|---|---|---|
| Fraîcheur | Retard jusqu’à la publication suivante (ici 7 jours) | Réponse récente (quelques heures à jours) | Pas de révocation : la fenêtre d’exposition est la durée de vie |
| Taille / coût | Grandit avec le nombre de révocations, téléchargée en entier | Petite réponse par certificat | Rien à consulter ; émission très fréquente |
| Disponibilité | Point de distribution indisponible → échec ouvert ou fermé | Répondeur indisponible → idem (agrafage : le serveur porte la réponse) | Dépend de l’automatisation de l’émission (ACME) |
| Vie privée | Bonne (téléchargement global) | Mauvaise sans agrafage : le répondeur voit les sites visités | Bonne |
| Usage actuel | Revenue en force (Let’s Encrypt, CRL agrégées des navigateurs) | Let’s Encrypt a arrêté OCSP en 2025 | Tendance : 47 jours en 2029, quelques heures dans les maillages de services |

Limites constatées dans notre IGC : (1) les certificats de l’annexe B n’ont pas d’extension `crlDistributionPoints`, donc un client ne sait pas où trouver la CRL ; nous l’avons fournie à la main (`-CRLfile`, `ssl_crl`) ; (2) la CRL expire au bout de 7 jours : si on oublie de la régénérer, nginx rejettera tous les clients (« CRL has expired ») ; (3) entre la compromission et la publication suivante, la clé volée reste acceptée. La révocation est donc imparfaite, d’où la tendance aux durées courtes et à l’automatisation (diapo 89).

### Q6. Rédiger en dix lignes une politique de certification minimale pour cette infrastructure.

> **Politique de certification – IGC « Université TP » (v1.0)**
>
> 1. **Périmètre** : certificats de serveurs TLS en `*.tp.local` et de clients TLS en `@tp.local`, à usage interne au laboratoire uniquement.  
> 2. **Demandeurs** : administrateurs système (serveurs) et membres inscrits de l’université (clients), via le formulaire de l’autorité d’enregistrement (AE).  
> 3. **Vérification d’identité** : client = présentation de la carte d’étudiant ou d’agent et contrôle de l’adresse @tp.local ; serveur = ticket validé par le responsable du domaine.  
> 4. **Clés** : générées par le demandeur sur son équipement (ECDSA P-256 minimum) ; l’AC ne génère ni ne conserve aucune clé privée de titulaire.  
> 5. **Durées** : racine 10 ans, intermédiaire 5 ans, certificats finaux 90 jours au plus, renouvellement automatique à J−30.  
> 6. **Protection des AC** : racine hors ligne (HSM ou support chiffré au coffre, cérémonie à deux personnes) ; intermédiaire sur un serveur dédié à accès restreint et journalisé.  
> 7. **Révocation** : sur demande du titulaire ou de l’AE, ou d’office en cas de compromission, de départ ou d’erreur, dans les 24 h ; motif obligatoire.  
> 8. **Publication** : CRL de l’intermédiaire tous les 7 jours (et immédiatement après chaque révocation), CRL de la racine tous les 30 jours.  
> 9. **Journalisation et audit** : toute émission ou révocation est inscrite dans la base de l’AC et archivée ; revue mensuelle de l’inventaire des certificats.  
> 10. **Obligations du titulaire** : protéger sa clé, signaler sans délai toute compromission, ne pas utiliser le certificat hors de l’usage prévu.

---

## 12. Difficultés rencontrées et solutions

| Difficulté | Cause | Solution retenue |
|---|---|---|
| Option `-subj "/CN=…"` abîmée | Git Bash convertit les arguments commençant par « / » en chemins Windows | `export MSYS_NO_PATHCONV=1` (intégré à `pki.sh`) |
| Fichiers de configuration absents au départ | Annexe B non incluse dans le sujet | Annexe B obtenue et appliquée à l'identique |
| Renouvellement du TP 3 bloqué par avance (anticipé) | `unique_subject` est activé par défaut : un sujet ne peut avoir qu'un certificat valide | `index.txt.attr` avec `unique_subject = no` |
| Certificat de Bob portant l'adresse d'Alice | SAN écrit en dur dans `ext_client` | Section dédiée `bob.ext`, certificat erroné révoqué |
| Numéros de série inattendus (4096) | Fichiers `serial` lus en hexadécimal | Interprétation documentée : 1000 = 0x1000 |

---

## 13. Conclusion

L'IGC construite comporte une racine P-384 hors ligne, une AC intermédiaire limitée par `pathlen:0` et
par des contraintes de nom sur `tp.local`, et des certificats finaux de serveur et de client. Chaque
contrôle de validation a été mis à l'épreuve et a produit l'erreur attendue : nom (62), usage (26),
contrainte de nom (47), profondeur de chaîne (25) et révocation (23).

Ce TP montre que la confiance dans une IGC repose autant sur sa **configuration** que sur la
cryptographie : une seule ligne écrite en dur dans une section d'extensions suffisait à donner à un
utilisateur l'identité d'un autre. Les contraintes de nom et de profondeur illustrent le principe de
défense en profondeur : elles protègent les clients même si une autorité commet une erreur ou se fait
voler sa clé.

**Perspectives** : protéger les clés d'AC dans un HSM, publier les CRL par HTTP avec l'extension
`crlDistributionPoints`, ajouter un répondeur OCSP et automatiser l'émission par ACME avec une AC
interne. L'IGC construite ici sert de base au TP 3.
