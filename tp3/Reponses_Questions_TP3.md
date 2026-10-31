# Questions de réflexion du TP 3

**TP 3 – Déployer un canal sécurisé et gérer les certificats**

Module EC1 – Ingénierie de la cryptographie · TANKOANO Yamindi Martin · Enseignant : Dr. Zakaria Sawadogo · 2026–2027  
Extrait du compte rendu `Corrige_TP_EC1_complet.pdf`.

---

## Q1. Pourquoi le serveur ne doit-il pas envoyer le certificat racine ?

Parce que c’est **inutile** et que cela peut faire croire à une sécurité qui n’existe pas. La racine est l’ancre de confiance : le client doit **déjà** l’avoir dans son magasin de confiance, obtenue par un canal sûr. Une racine reçue du serveur pendant la connexion ne peut pas être crue, puisque n’importe quel attaquant peut envoyer sa propre « racine ». Le client l’ignore donc et utilise sa propre copie. L’envoyer ne fait que **gaspiller de la bande passante** à chaque poignée de main (un certificat de plus, avec une signature) et peut entraîner un découpage en paquets supplémentaires. C’est pourquoi `serveur_chaine.crt` ne contient que la feuille et l’intermédiaire (diapo 86).

---

## Q2. Quel est l’intérêt de désactiver les tickets de session lorsque les clés de tickets ne sont pas renouvelées ?

Un ticket de session contient l’état de la session (secret de reprise), **chiffré avec une clé de ticket** (STEK) connue du serveur seul, et stocké par le client. Par défaut, nginx tire cette clé au démarrage et ne la change **jamais** tant qu’il n’est pas redémarré, ce qui peut durer des mois. Un attaquant qui enregistre le trafic puis vole cette clé (fuite mémoire, sauvegarde) peut déchiffrer les tickets, en tirer les secrets de reprise, et donc déchiffrer toutes les sessions reprises (en TLS 1.2, même les sessions complètes). La **confidentialité persistante** apportée par ECDHE est alors annulée pour toute la durée de vie de la clé de ticket (diapos 102, 105).

Désactiver les tickets (`ssl_session_tickets off`) supprime ce secret à long terme ; le coût est une poignée de main complète de plus, négligeable ici. L’alternative est de faire tourner les clés de ticket fréquemment (`ssl_session_ticket_key` renouvelée toutes les quelques heures, partagée entre les serveurs d’une grappe).

---

## Q3. Que garantit l’en-tête HSTS ? Contre quelle attaque protège-t-il ?

Avec `Strict-Transport-Security: max-age=31536000`, reçu par HTTPS, le navigateur retient pendant **un an** que ce site ne doit être contacté **qu’en HTTPS** : il réécrit lui-même tout lien `http://` en `https://` avant d’envoyer quoi que ce soit, et transforme les erreurs de certificat en erreurs **bloquantes** (impossible de « continuer quand même »).

Il protège contre l’attaque par **retrait de TLS** (« SSL stripping », Moxie Marlinspike, 2009). Un homme du milieu sur un Wi-Fi public intercepte la première requête en HTTP en clair, garde lui-même la connexion HTTPS avec le site, et sert la victime en HTTP : identifiants et cookies passent en clair. Il protège aussi contre les utilisateurs qui ignoreraient un avertissement de certificat. Limite : la toute première visite reste vulnérable (avant d’avoir reçu l’en-tête). On y remédie avec `includeSubDomains; preload` et l’inscription dans la liste de préchargement intégrée aux navigateurs.

---

## Q4. La durée maximale des certificats publics passe à 100 jours en 2027 puis à 47 jours en 2029. Quelles conséquences pour une organisation qui renouvelle à la main ?

Le nombre de renouvellements explose : avec 47 jours, chaque certificat doit être renouvelé environ **8 fois par an** (dans la pratique tous les ~30 jours, pour garder une marge). Pour une organisation de 3 000 certificats, cela fait environ 3 000 × 365 / 47 ≈ **23 000 opérations par an, soit 60 à 100 par jour ouvré**. C’est impossible à la main sans erreurs. Chaque oubli est un certificat expiré, donc une panne de service (diapo 91 : « un certificat géré à la main est un incident programmé »).

- Il faut un **inventaire** complet (découverte réseau, journaux CT) avec un propriétaire par certificat.
- Il faut automatiser l’émission et le déploiement avec **ACME** (certbot, cert-manager), comme notre `renouveler.sh`, vérification et retour arrière compris.
- Il faut une **supervision** des échéances (alertes à 30, 14 et 7 jours), comme `surveiller.py`.
- Les équipements qui n’acceptent pas l’automatisation (appliances, anciens systèmes) doivent être remplacés ou placés derrière un proxy automatisé.

Le bénéfice est réel : une clé volée ou un certificat mal émis ne reste utilisable que quelques semaines, ce qui compense une révocation qui fonctionne mal sur le Web (diapo 89).

---

## Q5. Un serveur expose un certificat valide mais la chaîne est incomplète : pourquoi certains clients l’acceptent-ils et d’autres non ?

Si le serveur n’envoie que sa feuille, le client doit trouver **lui-même** l’intermédiaire pour remonter jusqu’à une racine de confiance. Certains clients compensent : les **navigateurs** gardent en cache les intermédiaires vus sur d’autres sites, Firefox embarque la liste de tous les intermédiaires publics, et Chrome et Windows vont télécharger l’intermédiaire à l’adresse indiquée dans l’extension *Authority Information Access* (caIssuers) du certificat. La page s’affiche donc chez l’administrateur, qui croit que tout va bien.

D’autres clients ne font rien de tout cela : `openssl`, `curl`, Python, Java, les applications mobiles, les objets connectés, les appels entre API. Ils échouent avec « unable to get local issuer certificate ». Nous l’avons reproduit dans l’autre sens à l’étape 3 : Bob qui envoie `bob.crt` sans l’intermédiaire est rejeté par nginx (« 21 : unable to verify the first certificate »), alors que la même identité avec sa chaîne est acceptée. Règle : toujours servir la **chaîne complète sans la racine** et la tester avec un client strict (`openssl s_client -showcerts`, SSL Labs).

---

## Q6. Proposer une procédure de réaction si la clé privée du serveur fuit.

| Phase | Actions |
|---|---|
| 1. Confirmer et contenir (heure 0) | Ouvrir un incident, identifier la clé et les certificats concernés (n° de série), couper l’accès de l’attaquant (correctif, mots de passe, accès au serveur). |
| 2. Remplacer (≤ 1 h) | `renouveler.sh --force` : **nouvelle clé** générée sur le serveur (jamais réutiliser l’ancienne), nouveau certificat, vérification, déploiement à chaud ; contrôler le numéro de série réellement servi. |
| 3. Révoquer (immédiatement après) | `openssl ca -revoke ancien.crt -crl_reason keyCompromise`, régénérer et publier la CRL, la recharger sur tous les serveurs qui vérifient (`ssl_crl`) ; pour un certificat public, demander la révocation à l’AC. |
| 4. Secrets dérivés | Renouveler les clés de tickets de session, les jetons et sessions applicatives, les autres certificats qui partageaient la clé ; détruire les copies de l’ancienne clé, y compris les archives. |
| 5. Évaluer l’impact | Grâce à ECDHE (confidentialité persistante), les échanges passés enregistrés restent protégés ; le risque porte sur l’usurpation du serveur entre la fuite et la révocation. Vérifier les journaux et surveiller les journaux CT pour détecter des certificats émis à notre nom. |
| 6. Clôturer | Informer les utilisateurs (et l’autorité compétente si des données personnelles sont touchées), analyser la cause, corriger (HSM, droits, sauvegardes chiffrées), mettre à jour la procédure. |
