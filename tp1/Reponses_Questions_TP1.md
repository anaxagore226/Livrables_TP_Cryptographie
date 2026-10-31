# Questions de réflexion du TP 1

**TP 1 – Chiffrement authentifié et dérivation de clés**

Module EC1 – Ingénierie de la cryptographie · TANKOANO Yamindi Martin · Enseignant : Dr. Zakaria Sawadogo · 2026–2027  
Extrait du compte rendu `Corrige_TP_EC1_complet.pdf`.

---

## Q1. Pourquoi le sel est-il stocké en clair ? Sa publication affaiblit-elle la sécurité ?

Le sel est indispensable pour **redériver la même clé** au déchiffrement : il doit donc être stocké avec le fichier, et rien ne permet de le cacher (il faudrait une autre clé pour le chiffrer). Il n’a pas vocation à être secret : son rôle est l’**unicité**. Deux fichiers chiffrés avec le même mot de passe ont des clés différentes, et l’attaquant ne peut pas utiliser de tables précalculées (empreintes de dictionnaires calculées à l’avance) ni attaquer tous les fichiers d’un coup.

Sa publication n’affaiblit pas la sécurité : connaissant le sel, l’attaquant doit toujours exécuter Argon2id (0,5 s, 256 Mio) pour **chaque** mot de passe candidat et **chaque** fichier. La sécurité repose sur l’entropie du mot de passe et le coût de la dérivation, pas sur le secret du sel (principe de Kerckhoffs appliqué aux paramètres).

---

## Q2. Le nonce est tiré au hasard sur 96 bits. Pourquoi n’y a-t-il ici aucun risque de répétition, même pour des millions de fichiers ?

Le danger de GCM est la réutilisation d’un même couple **(clé, nonce)** : fuite de m₁ XOR m₂ et récupération de la clé d’authentification H (diapo 56). La limite de 2³² messages concerne *une même clé*. Or ici la clé change à chaque fichier : elle dérive d’un sel aléatoire de 128 bits tiré à chaque chiffrement (y compris lors d’un rechiffrement). Chaque clé ne chiffre donc qu’**un seul** message, et un nonce répété entre deux fichiers différents est sans conséquence, car les clés sont différentes.

Pour qu’un couple (clé, nonce) se répète, il faudrait que deux fichiers aient à la fois le même mot de passe et le même sel : par le paradoxe des anniversaires, la probabilité est de l’ordre de n²/2¹²⁹, soit environ 10⁻²⁷ pour un million de fichiers. Le nonce aléatoire est même une sécurité supplémentaire. Cette analyse changerait si l’on chiffrait plusieurs morceaux d’un gros fichier sous la même clé : il faudrait alors un nonce compteur.

---

## Q3. Que se passerait-il si le nom du fichier n’était pas dans les données associées ? Scénario concret.

Le chiffré resterait valide sous un autre nom : rien ne lierait le contenu à son emplacement. **Scénario :** un étudiant stocke dans un espace partagé (nuage, serveur de l’école) `autorisation_examen.pdf.cfr` et `refus_examen.pdf.cfr`, chiffrés avec le même mot de passe. Un attaquant qui a accès en écriture au stockage (administrateur malveillant, pirate, logiciel de synchronisation compromis), mais pas au mot de passe, **échange les deux fichiers**. Sans le nom dans les données associées, l’utilisateur ouvre « autorisation_examen » sans aucune erreur et lit en réalité le refus, ou l’inverse. De même, il pourrait remplacer `rib_fournisseur.cfr` par un autre RIB chiffré par la même personne. Le chiffrement est intact, mais l’**intégrité du contexte** est violée.

Avec le nom dans les données associées, l’étiquette ne correspond plus : `InvalidTag` (test `test_fichier_renomme`). Limite : cela n’empêche pas de remettre une *ancienne version* du même fichier (rejeu). Il faudrait ajouter un numéro de version ou une date dans les données associées.

---

## Q4. Pourquoi l’en-tête lui-même est-il authentifié ? Que pourrait faire un attaquant sinon avec les paramètres Argon2id ?

L’en-tête décide de **comment** le fichier est traité : version du format, coût de la dérivation, sel, nonce. Comme il est authentifié par GCM, toute modification est détectée au même endroit et de la même façon (`InvalidTag`) : on n’a pas à raisonner au cas par cas sur les effets d’une modification. Sans cette authentification, un attaquant pourrait :

- **abaisser les paramètres** (t = 1, m = 8 Mio) d’un fichier, ou forger un fichier à paramètres faibles, qu’un outil relirait puis **réécrirait** avec ces mêmes paramètres (par exemple un `rechiffrer` qui réutiliserait les paramètres lus). Les copies volées seraient alors des milliers de fois plus faciles à attaquer par dictionnaire ;
- **gonfler les paramètres** (m = 4 Gio, t énorme) pour provoquer un déni de service : la machine qui tente d’ouvrir le fichier sature sa mémoire. Point important : l’étiquette ne peut être vérifiée qu’*après* la dérivation. L’authentification ne suffit donc pas contre ce cas : c’est pourquoi `lire_entete` borne t, m et p **avant** de dériver (test `test_parametres_absurdes_refuses`) ;
- jouer sur l’**identifiant de format** pour faire interpréter le fichier selon une autre version (confusion de format, attaque par repli).

Dans notre format, modifier t, m, p ou le sel change de toute façon la clé dérivée, ce qui fait échouer le déchiffrement. Mais l’authentification explicite de l’en-tête en fait une garantie voulue, et non un effet de bord dont on pourrait se priver lors d’une future évolution.

---

## Q5. Pourquoi ne doit-on jamais afficher à l’utilisateur la raison précise d’un échec de déchiffrement ?

Parce qu’un message d’erreur détaillé devient un **oracle** pour l’attaquant. S’il peut distinguer « mot de passe incorrect », « fichier modifié », « nom incorrect » ou « bourrage invalide », il apprend un peu d’information à chaque essai. C’est exactement le mécanisme des oracles de bourrage (Vaudenay, POODLE, Lucky Thirteen) et de Bleichenbacher sur RSA, où une simple différence de message ou de délai a permis de déchiffrer sans la clé (diapos 51 et 132). Ici, il pourrait par exemple tester quel nom de fichier est le bon ou si une modification ciblée « passe ».

Règle du cours : **un seul message d’erreur**, en temps constant, **aucune donnée partielle** rendue. C’est ce que fait `coffre.py` : toutes les causes cryptographiques lèvent `InvalidTag` et l’interface affiche seulement « Échec du déchiffrement. ». Le détail peut être écrit dans un journal protégé, réservé à l’administrateur.
