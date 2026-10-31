# Rapport de TP 1

## Chiffrement authentifié et dérivation de clés : un coffre de fichiers

**École Polytechnique de Ouagadougou** — IGIT 2 — Module EC1 : Ingénierie de la cryptographie

| | |
|---|---|
| **Étudiant** | TANKOANO Yamindi Martin |
| **Classe** | IGIT 2 |
| **Enseignant** | Dr. Zakaria Sawadogo |
| **Année universitaire** | 2026 – 2027 |
| **Date de remise** | 31 octobre 2026 |

**Livrables joints.** Dans ce dossier (`tp1/`) : `coffre.py`, `test_coffre.py`, `mesure_argon2.py`.

---

## Sommaire

1. [Introduction et objectifs](#1-introduction-et-objectifs)
2. [Environnement de travail](#2-environnement-de-travail)
3. [Préalable : observations de la série guidée](#3-préalable--observations-de-la-série-guidée)
4. [Conception du coffre](#4-conception-du-coffre)
5. [Étape 1 – Dérivation des clés et réglage d'Argon2id](#5-étape-1--dérivation-des-clés-et-réglage-dargon2id)
6. [Étape 2 – Chiffrer et déchiffrer](#6-étape-2--chiffrer-et-déchiffrer)
7. [Étape 3 – Prouver les propriétés par des tests](#7-étape-3--prouver-les-propriétés-par-des-tests)
8. [Étape 4 – Évolution des paramètres](#8-étape-4--évolution-des-paramètres)
9. [Analyse de sécurité](#9-analyse-de-sécurité)
10. [Questions de réflexion](#10-questions-de-réflexion)
11. [Difficultés rencontrées et solutions](#11-difficultés-rencontrées-et-solutions)
12. [Conclusion](#12-conclusion)

---

## 1. Introduction et objectifs

Un mot de passe ne peut pas servir directement de clé de chiffrement : il est court, prévisible et sans
structure. Un chiffrement qui cache le contenu sans en contrôler l'intégrité est, lui, dangereux, comme
l'a montré la série guidée. Ce TP consistait à construire un petit outil réel, un **coffre de fichiers**
protégé par mot de passe, en assemblant correctement des primitives standard, sans en réimplémenter
aucune.

Objectifs du TP :

- chiffrer des données avec un mode **AEAD** (AES en mode GCM), en gérant correctement le nonce et les
  données associées ;
- dériver une clé d'un mot de passe avec **Argon2id**, puis des sous-clés avec **HKDF** ;
- concevoir un **format de fichier chiffré versionné** ;
- démontrer par des **tests automatiques** que le chiffrement protège la confidentialité *et*
  l'intégrité.

---

## 2. Environnement de travail

Les manipulations ont été faites sur un poste Windows 11, dans le terminal Git Bash.

| Outil | Version | Rôle |
|---|---|---|
| Python | 3.14.7 | module `coffre.py`, tests, mesures |
| cryptography | 50.0.2 | AES-256-GCM (`AESGCM`), HKDF-SHA256 |
| argon2-cffi | 25.1.0 | dérivation Argon2id |
| pytest | 9.2.0 | tests automatiques |
| OpenSSL | 3.2.1 | manipulations de la série guidée |

**Règles suivies.** Aucun algorithme maison ; aucun mot de passe réel dans le code ou le rapport ;
chaque résultat cité provient d'une exécution réelle. Les sels, nonces et chiffrés sont aléatoires et
diffèrent d'une exécution à l'autre.

---

## 3. Préalable : observations de la série guidée

Le TP 1 de la série guidée (« Empreintes et chiffrement d'un fichier ») a permis de constater les
propriétés que le coffre devait ensuite garantir.

| Manipulation | Observation | Enseignement |
|---|---|---|
| SHA-256 de deux messages ne différant que d'un caractère (« 8 h » / « 9 h ») | `83f72919…fce59c` et `e6c855b7…4ef135` : aucun lien ; recalcul identique | Effet avalanche et déterminisme ; une empreinte ne prouve l'intégrité que si la référence est sûre |
| HMAC-SHA256 du même fichier avec deux clés | `2ddfb602…317c` et `9a5cd27d…cc00` | Le code dépend de la clé : authenticité entre détenteurs de la clé, sans non-répudiation |
| AES-256-CBC + PBKDF2 (600 000 itérations), deux fois le même fichier | Deux chiffrés différents commençant par « Salted__ » | Chiffrement probabiliste grâce au sel ; KDF lente contre le dictionnaire |
| Un bit inversé dans le chiffré CBC | Déchiffrement « réussi » (code 0) : 16 octets illisibles, « cryptographie » devient « togr\`phie » | CBC est malléable : aucune intégrité, danger réel (ordre de virement) |
| Un bit inversé dans un chiffré AES-GCM | Refus : `InvalidTag` ; chiffré = message + 16 octets | Le chiffrement authentifié détecte toute modification |

La conclusion de cette série a directement orienté la conception : **le coffre doit utiliser un mode
AEAD**, jamais CBC seul, et une **dérivation lente** du mot de passe.

---

## 4. Conception du coffre

Le module `coffre.py` assemble trois primitives standard, chacune à sa place :

- **Argon2id** transforme le mot de passe (faible entropie) en une clé maîtresse de 256 bits, avec un
  sel aléatoire propre à chaque fichier ;
- **HKDF-SHA256** dérive de cette clé maîtresse une sous-clé par usage
  (`info = "coffre-v1|chiffrement"`) : une clé ne sert jamais à deux usages ;
- **AES-256-GCM** chiffre et authentifie les données ; l'en-tête complet et le nom du fichier sont
  passés en **données associées** (authentifiés, non chiffrés).

**Figure 1 – Format CFR1 d'un fichier chiffré et chaîne de dérivation de la clé**

```
+--------+---------------+----------+------------+------------------+----------------+
|  CFR1  |   t, m, p     |   sel    |   nonce    |     chiffré      | étiquette GCM  |
|  4 o   |    12 o       |   16 o   |    12 o    |       n o        |      16 o      |
+--------+---------------+----------+------------+------------------+----------------+
|<------------------ en-tête : 44 octets ------->|<-- protégé par AES-256-GCM ------>|
     authentifié (données associées, avec le nom du fichier)

Clé AES = HKDF-SHA256( Argon2id(mot de passe, sel, t=3, m=256 Mio, p=4),
                       info = "coffre-v1|chiffrement" )
```

| Champ | Taille | Rôle |
|---|---|---|
| Identifiant de format `CFR1` | 4 octets | Reconnaître le format et sa version |
| Paramètres Argon2id (t, m, p) | 12 octets | Redériver la clé et pouvoir durcir plus tard |
| Sel | 16 octets | Rendre la dérivation unique pour ce fichier |
| Nonce | 12 octets | Unique pour ce chiffrement |
| Chiffré + étiquette | variable | Données protégées par AES-GCM |

---

## 5. Étape 1 – Dérivation des clés et réglage d'Argon2id

```python
def cle_maitresse(mot_de_passe: str, sel: bytes, t: int = T, m: int = M, p: int = P) -> bytes:
    """Argon2id -> 32 octets."""
    return hash_secret_raw(secret=mot_de_passe.encode("utf-8"), salt=sel,
                           time_cost=t, memory_cost=m, parallelism=p,
                           hash_len=32, type=Type.ID)

def sous_cle(maitresse: bytes, usage: bytes) -> bytes:
    """HKDF-SHA256 avec info = b"coffre-v1|" + usage -> 32 octets."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"coffre-v1|" + usage).derive(maitresse)
```

La clé de chiffrement est `sous_cle(maitresse, b"chiffrement")` : la clé maîtresse Argon2id n'est
jamais utilisée directement. Ajouter un autre usage plus tard ne demanderait qu'une autre étiquette,
avec une garantie d'indépendance des clés.

L'énoncé demandait de viser environ 0,5 s par dérivation. Les mesures (`mesure_argon2.py`, meilleur de
trois essais) ont été faites deux fois :

| t | m | p | Machine chargée | Machine au repos |
|---|---|---|---|---|
| 1 | 64 Mio | 4 | 0,081 s | 0,039 s |
| 3 | 64 Mio | 4 | 0,300 s | 0,096 s |
| 3 | 128 Mio | 4 | 0,525 s | 0,172 s |
| 2 | 256 Mio | 4 | 0,598 s | 0,247 s |
| **3** | **256 Mio** | **4** | 0,723 s | **0,487 s** |
| 4 | 256 Mio | 4 | 0,891 s | 0,737 s |

La première série a été perturbée par le démarrage d'un autre logiciel : une mesure de performance doit
se faire au repos et sur la machine qui chiffrera réellement. Les paramètres de l'énoncé
(m = 64 Mio) ne coûtaient que 0,1 s ; nous avons **augmenté la mémoire** plutôt que le nombre de passes,
car c'est la mémoire qui pénalise le plus un attaquant équipé de processeurs graphiques.

**Paramètres retenus : t = 3, m = 256 Mio, p = 4.** Pour un mot de passe de huit lettres minuscules
(2 × 10¹¹ possibilités), une recherche exhaustive passe ainsi de quelques jours à plusieurs milliers
d'années de calcul sur une machine.

---

## 6. Étape 2 – Chiffrer et déchiffrer

Les fonctions `chiffrer(mot_de_passe, nom, donnees)` et `dechiffrer(mot_de_passe, nom, blob)` respectent
le format CFR1 :

- un sel (16 octets) et un nonce (12 octets) **neufs** sont tirés par `os.urandom` à chaque appel ;
- le chiffrement utilise `AESGCM` de la bibliothèque `cryptography` ;
- les données associées sont l'en-tête complet (44 octets) suivi du nom du fichier ;
- au déchiffrement, `lire_entete` refuse un identifiant inconnu (≠ CFR1), un fichier trop court et des
  paramètres Argon2id hors bornes, **avant** toute dérivation coûteuse ;
- mauvais mot de passe, octet modifié ou nom différent produisent la même exception `InvalidTag` ;
  l'interface en ligne de commande n'affiche que « Échec du déchiffrement. ».

**Exemple réel** : le fichier `notes.txt` (17 octets) donne un fichier chiffré de 77 octets.

```
43465231 | 000000030004000000000004 | 440e1da93a7fb3a4e39a48547247cb94 | 89a5b0725f5689b51518ce48 | ...
 "CFR1"  |  t=3  m=262144  p=4      |  sel (16 octets)                 |  nonce (12 octets)       |
... | 3109299b3afc340a6248303141c4eafd6f | 6a0843124df52a820cc4484017aabbde
    |  chiffré (17 octets = taille du clair) | étiquette GCM (16 octets)

dechiffrer("MonMotDePasse", "notes.txt", blob) -> b'Note EC1 : 17/20\n'
dechiffrer("mauvais", "notes.txt", blob)       -> InvalidTag
dechiffrer("MonMotDePasse", "autre.txt", blob) -> InvalidTag
```

77 = 44 (en-tête) + 17 (chiffré, GCM ne bourre pas) + 16 (étiquette).

---

## 7. Étape 3 – Prouver les propriétés par des tests

Chaque propriété de sécurité attendue a été traduite en test pytest. Les cinq tests demandés ont été
complétés par huit autres, qui couvrent les risques identifiés pendant l'analyse.

| Test | Attendu | Propriété vérifiée | Résultat |
|---|---|---|---|
| Aller-retour | données identiques | Correction | réussi |
| Deux chiffrements du même fichier | blobs, sels et nonces différents | Chiffrement probabiliste | réussi |
| Mauvais mot de passe | `InvalidTag` | Authentification de la clé | réussi |
| Un bit modifié (début, milieu, étiquette) | `InvalidTag` (3 cas) | Intégrité | réussi |
| Fichier renommé | `InvalidTag` | Liaison au contexte | réussi |
| Sel ou nonce de l'en-tête modifié | `InvalidTag` | Intégrité de l'en-tête | réussi |
| Paramètre t abaissé à 1 | `InvalidTag` | Pas d'affaiblissement | réussi |
| m = 4 Gio dans l'en-tête | refus avant dérivation | Anti-déni de service | réussi |
| Identifiant « CFR2 » ou fichier tronqué | `FormatInconnu` | Versionnement | réussi |
| Sous-clés de deux usages | différentes | Séparation des domaines | réussi |
| Ancien fichier rechiffré avec des paramètres plus forts | lisible, puis (4, 256 Mio, 4) | Évolutivité | réussi |

```
$ python -m pytest -v test_coffre.py
platform win32 -- Python 3.14.7, pytest-9.2.0, pluggy-1.7.0
collected 13 items
test_coffre.py::test_aller_retour PASSED                                 [  7%]
test_coffre.py::test_chiffrement_probabiliste PASSED                     [ 15%]
test_coffre.py::test_mauvais_mot_de_passe PASSED                         [ 23%]
test_coffre.py::test_octet_modifie[44] PASSED                            [ 30%]
test_coffre.py::test_octet_modifie[60] PASSED                            [ 38%]
test_coffre.py::test_octet_modifie[-1] PASSED                            [ 46%]
test_coffre.py::test_fichier_renomme PASSED                              [ 53%]
test_coffre.py::test_entete_authentifie PASSED                           [ 61%]
test_coffre.py::test_parametres_affaiblis_rejetes PASSED                 [ 69%]
test_coffre.py::test_parametres_absurdes_refuses PASSED                  [ 76%]
test_coffre.py::test_format_inconnu PASSED                               [ 84%]
test_coffre.py::test_separation_des_usages PASSED                        [ 92%]
test_coffre.py::test_evolution_des_parametres PASSED                     [100%]
============================= 13 passed in 5.56s ==============================
```

---

## 8. Étape 4 – Évolution des paramètres

**Pourquoi le format le permet.** Chaque fichier transporte *ses propres* paramètres (t, m, p) et son sel
dans l'en-tête : pour le relire, on redérive la clé avec les paramètres *du fichier*, quels que soient
les paramètres par défaut actuels du logiciel. On peut donc durcir T, M, P à tout moment : les anciens
fichiers restent lisibles, les nouveaux utilisent les nouveaux paramètres. L'identifiant `CFR1` permet
en plus de changer un jour la structure elle-même (autre KDF, autre AEAD) en gardant un lecteur pour
CFR1 : c'est l'agilité cryptographique. Comme l'en-tête est authentifié, ces paramètres ne peuvent pas
être falsifiés sans être détectés.

```python
def rechiffrer(ancien_mdp: str, nouveau_mdp: str, nom: str, blob: bytes) -> bytes:
    """Change le mot de passe ; le nouveau fichier utilise les parametres
    Argon2id actuels (T, M, P), eventuellement plus forts que les anciens."""
    return chiffrer(nouveau_mdp, nom, dechiffrer(ancien_mdp, nom, blob))
```

Le rechiffrement tire un nouveau sel et un nouveau nonce, donc une nouvelle clé. Le test
`test_evolution_des_parametres` crée un fichier avec t = 2, m = 19 Mio, p = 1, durcit les paramètres du
module à t = 4, m = 256 Mio, puis vérifie que le fichier rechiffré porte (4, 262144, 4), s'ouvre avec le
nouveau mot de passe et refuse l'ancien. En production, il faudrait écrire le nouveau fichier à côté,
vérifier qu'il se déchiffre, puis seulement remplacer l'ancien.

---

## 9. Analyse de sécurité

| Menace | Contre-mesure dans le coffre | Justification |
|---|---|---|
| Attaque par dictionnaire hors ligne | Argon2id 256 Mio, sel unique | Chaque essai coûte ≈ 0,5 s et 256 Mio, par fichier |
| Réutilisation d'un couple (clé, nonce) GCM | Clé différente pour chaque fichier | Chaque clé chiffre un seul message |
| Échange ou renommage de fichiers chiffrés | Nom dans les données associées | Le contenu est lié à son contexte |
| Paramètres falsifiés (affaiblis ou énormes) | En-tête authentifié + bornes avant dérivation | L'étiquette n'est vérifiable qu'après la dérivation |
| Oracle d'erreurs | Une seule exception, un seul message | L'attaquant n'apprend rien de la cause de l'échec |

| Propriété | Mécanisme | Preuve expérimentale |
|---|---|---|
| Confidentialité | AES-256-GCM | Chiffré illisible, probabiliste |
| Intégrité | Étiquette GCM de 128 bits | Un bit modifié → `InvalidTag` (CBC : code 0) |
| Résistance aux mots de passe faibles | Argon2id 256 Mio + sel | ≈ 0,49 s par essai |
| Liaison au contexte | Données associées = en-tête + nom | Fichier renommé → `InvalidTag` |
| Séparation des usages | HKDF avec étiquette de contexte | Sous-clés différentes par usage |

Une limite subsiste : un attaquant qui contrôle le stockage peut remettre une *ancienne version* du même
fichier. Il faudrait ajouter un numéro de version dans les données associées et le mémoriser côté
utilisateur.

---

## 10. Questions de réflexion

### Q1. Pourquoi le sel est-il stocké en clair ? Sa publication affaiblit-elle la sécurité ?

Le sel est indispensable pour **redériver la même clé** au déchiffrement : il doit donc être stocké avec le fichier, et rien ne permet de le cacher (il faudrait une autre clé pour le chiffrer). Il n’a pas vocation à être secret : son rôle est l’**unicité**. Deux fichiers chiffrés avec le même mot de passe ont des clés différentes, et l’attaquant ne peut pas utiliser de tables précalculées (empreintes de dictionnaires calculées à l’avance) ni attaquer tous les fichiers d’un coup.

Sa publication n’affaiblit pas la sécurité : connaissant le sel, l’attaquant doit toujours exécuter Argon2id (0,5 s, 256 Mio) pour **chaque** mot de passe candidat et **chaque** fichier. La sécurité repose sur l’entropie du mot de passe et le coût de la dérivation, pas sur le secret du sel (principe de Kerckhoffs appliqué aux paramètres).

### Q2. Le nonce est tiré au hasard sur 96 bits. Pourquoi n’y a-t-il ici aucun risque de répétition, même pour des millions de fichiers ?

Le danger de GCM est la réutilisation d’un même couple **(clé, nonce)** : fuite de m₁ XOR m₂ et récupération de la clé d’authentification H (diapo 56). La limite de 2³² messages concerne *une même clé*. Or ici la clé change à chaque fichier : elle dérive d’un sel aléatoire de 128 bits tiré à chaque chiffrement (y compris lors d’un rechiffrement). Chaque clé ne chiffre donc qu’**un seul** message, et un nonce répété entre deux fichiers différents est sans conséquence, car les clés sont différentes.

Pour qu’un couple (clé, nonce) se répète, il faudrait que deux fichiers aient à la fois le même mot de passe et le même sel : par le paradoxe des anniversaires, la probabilité est de l’ordre de n²/2¹²⁹, soit environ 10⁻²⁷ pour un million de fichiers. Le nonce aléatoire est même une sécurité supplémentaire. Cette analyse changerait si l’on chiffrait plusieurs morceaux d’un gros fichier sous la même clé : il faudrait alors un nonce compteur.

### Q3. Que se passerait-il si le nom du fichier n’était pas dans les données associées ? Scénario concret.

Le chiffré resterait valide sous un autre nom : rien ne lierait le contenu à son emplacement. **Scénario :** un étudiant stocke dans un espace partagé (nuage, serveur de l’école) `autorisation_examen.pdf.cfr` et `refus_examen.pdf.cfr`, chiffrés avec le même mot de passe. Un attaquant qui a accès en écriture au stockage (administrateur malveillant, pirate, logiciel de synchronisation compromis), mais pas au mot de passe, **échange les deux fichiers**. Sans le nom dans les données associées, l’utilisateur ouvre « autorisation_examen » sans aucune erreur et lit en réalité le refus, ou l’inverse. De même, il pourrait remplacer `rib_fournisseur.cfr` par un autre RIB chiffré par la même personne. Le chiffrement est intact, mais l’**intégrité du contexte** est violée.

Avec le nom dans les données associées, l’étiquette ne correspond plus : `InvalidTag` (test `test_fichier_renomme`). Limite : cela n’empêche pas de remettre une *ancienne version* du même fichier (rejeu). Il faudrait ajouter un numéro de version ou une date dans les données associées.

### Q4. Pourquoi l’en-tête lui-même est-il authentifié ? Que pourrait faire un attaquant sinon avec les paramètres Argon2id ?

L’en-tête décide de **comment** le fichier est traité : version du format, coût de la dérivation, sel, nonce. Comme il est authentifié par GCM, toute modification est détectée au même endroit et de la même façon (`InvalidTag`) : on n’a pas à raisonner au cas par cas sur les effets d’une modification. Sans cette authentification, un attaquant pourrait :

- **abaisser les paramètres** (t = 1, m = 8 Mio) d’un fichier, ou forger un fichier à paramètres faibles, qu’un outil relirait puis **réécrirait** avec ces mêmes paramètres (par exemple un `rechiffrer` qui réutiliserait les paramètres lus). Les copies volées seraient alors des milliers de fois plus faciles à attaquer par dictionnaire ;
- **gonfler les paramètres** (m = 4 Gio, t énorme) pour provoquer un déni de service : la machine qui tente d’ouvrir le fichier sature sa mémoire. Point important : l’étiquette ne peut être vérifiée qu’*après* la dérivation. L’authentification ne suffit donc pas contre ce cas : c’est pourquoi `lire_entete` borne t, m et p **avant** de dériver (test `test_parametres_absurdes_refuses`) ;
- jouer sur l’**identifiant de format** pour faire interpréter le fichier selon une autre version (confusion de format, attaque par repli).

Dans notre format, modifier t, m, p ou le sel change de toute façon la clé dérivée, ce qui fait échouer le déchiffrement. Mais l’authentification explicite de l’en-tête en fait une garantie voulue, et non un effet de bord dont on pourrait se priver lors d’une future évolution.

### Q5. Pourquoi ne doit-on jamais afficher à l’utilisateur la raison précise d’un échec de déchiffrement ?

Parce qu’un message d’erreur détaillé devient un **oracle** pour l’attaquant. S’il peut distinguer « mot de passe incorrect », « fichier modifié », « nom incorrect » ou « bourrage invalide », il apprend un peu d’information à chaque essai. C’est exactement le mécanisme des oracles de bourrage (Vaudenay, POODLE, Lucky Thirteen) et de Bleichenbacher sur RSA, où une simple différence de message ou de délai a permis de déchiffrer sans la clé (diapos 51 et 132). Ici, il pourrait par exemple tester quel nom de fichier est le bon ou si une modification ciblée « passe ».

Règle du cours : **un seul message d’erreur**, en temps constant, **aucune donnée partielle** rendue. C’est ce que fait `coffre.py` : toutes les causes cryptographiques lèvent `InvalidTag` et l’interface affiche seulement « Échec du déchiffrement. ». Le détail peut être écrit dans un journal protégé, réservé à l’administrateur.

---

## 11. Difficultés rencontrées et solutions

| Difficulté | Cause | Solution retenue |
|---|---|---|
| Mesures Argon2id incohérentes | Machine chargée lors de la première série | Nouvelle série au repos, paramètres choisis sur celle-ci |
| Paramètres de l'énoncé trop rapides (0,1 s) | Machine récente | Mémoire portée à 256 Mio pour atteindre ≈ 0,5 s |
| Paramètres par défaut figés au moment de la définition de la fonction | Valeurs par défaut Python évaluées une seule fois | Paramètres lus à l'appel (`t or T`), ce qui rend `rechiffrer` évolutif |
| `python3` introuvable | Sous Windows, l'exécutable s'appelle `python` | Commandes adaptées |

---

## 12. Conclusion

Le coffre réalisé assemble Argon2id, HKDF et AES-256-GCM dans un format versionné dont l'en-tête et le
nom du fichier sont authentifiés. Les 13 tests automatiques démontrent la correction, le caractère
probabiliste du chiffrement, l'authentification de la clé, l'intégrité, la liaison au contexte et
l'évolutivité des paramètres.

Le principal enseignement est qu'un chiffrement sûr ne se résume pas au choix d'un bon algorithme : la
sécurité vient de l'**assemblage** (une clé par usage, un nonce jamais réutilisé, un contexte
authentifié, un seul message d'erreur) et de la **preuve par les tests**. La série guidée l'a montré a
contrario : AES-CBC, un algorithme sûr, laissait passer un message modifié sans aucune erreur.

**Perspectives** : ajouter un numéro de version dans les données associées contre la restauration
d'anciennes versions, et chiffrer les gros fichiers par blocs avec un nonce compteur.
