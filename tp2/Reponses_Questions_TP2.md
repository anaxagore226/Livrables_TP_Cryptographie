# Questions de réflexion du TP 2

**TP 2 – Construire une infrastructure de gestion de clés**

Module EC1 – Ingénierie de la cryptographie · TANKOANO Yamindi Martin · Enseignant : Dr. Zakaria Sawadogo · 2026–2027  
Extrait du compte rendu `Corrige_TP_EC1_complet.pdf`.

---

## Q1. Pourquoi la clé de la racine doit-elle rester hors ligne ? Que faut-il faire si l’intermédiaire est compromis ? Et la racine ?

La clé racine est l’ancre de toute la confiance : quiconque la détient peut créer des intermédiaires et donc des certificats pour n’importe quel nom, acceptés par tous les clients. Or elle ne sert presque jamais : signer un intermédiaire tous les cinq ans et une CRL de la racine par mois. La garder **hors ligne** (machine déconnectée, HSM, coffre, cérémonie de clés à plusieurs personnes, partage de secret pour la sauvegarde) supprime la surface d’attaque réseau sans gêner l’exploitation quotidienne, assurée par l’intermédiaire (diapo 86).

**Intermédiaire compromis :** la racine le **révoque** (CRL de la racine republiée aussitôt) ; on crée un nouvel intermédiaire avec une nouvelle clé, on réémet et redéploie tous les certificats finaux, et on cherche la cause. Le dégât est limité grâce aux contraintes de nom (seulement `tp.local`) et à `pathlen:0`. **Racine compromise :** personne au-dessus ne peut la révoquer. Il faut la retirer de **tous** les magasins de confiance, créer une nouvelle racine, la distribuer à tous les clients par un canal sûr, puis reconstruire toute la hiérarchie (cas DigiNotar, diapo 94). C’est un incident majeur, d’où l’importance de la garder hors ligne.

---

## Q2. À quoi sert pathlen:0 sur l’intermédiaire ? Quel risque si on l’oublie ?

`pathlen:0` signifie : « cette AC peut signer des certificats, mais aucun des certificats qu’elle signe ne peut être une AC ». Elle ne peut émettre que des certificats finaux. Si on l’oublie, l’intermédiaire, ou un attaquant qui a volé sa clé, peut créer des **sous-AC**. Celles-ci échappent à l’inventaire et aux audits, et peuvent elles-mêmes émettre des certificats, voire être confiées à des tiers. La surface de confiance grandit sans contrôle.

Nous l’avons testé en créant une « Sous-AC pirate » (CA:TRUE) signée avec la clé de l’intermédiaire, puis un certificat `faux.tp.local` signé par elle :

```
$ openssl verify -CAfile racine/racine.crt -untrusted chaine.pem f.crt
error 25 at 2 depth lookup: path length constraint exceeded     <- pathlen:0 de l'intermediaire
error 25 at 3 depth lookup: path length constraint exceeded     <- pathlen:1 de la racine
error f.crt: verification failed
```

Les deux contraintes se déclenchent : le `pathlen:1` de la racine suffirait à lui seul dans notre hiérarchie. Le `pathlen:0` de l’intermédiaire est une **défense en profondeur** : il reste valable même si la racine signe un jour d’autres intermédiaires ou est réémise sans cette limite. Il exprime aussi explicitement la politique à l’endroit où elle s’applique.

---

## Q3. Pourquoi la clé privée du serveur est-elle générée par le serveur et non par l’AC ?

Parce qu’une clé privée ne doit **jamais circuler**. Le serveur la génère, ne transmet que sa CSR (clé publique et nom) signée avec cette clé, ce qui prouve qu’il la possède, et l’AC signe sans jamais voir la clé (diapo 85). Si l’AC générait la clé : il faudrait la lui envoyer, ou qu’elle la renvoie, ce qui l’expose en transit et dans les sauvegardes ; l’AC (ou quiconque la pirate) pourrait se faire passer pour le serveur et déchiffrer ce qui lui est destiné, et toute notion de non-répudiation disparaîtrait. L’AC deviendrait aussi un réservoir de clés de tous ses clients, une cible de grande valeur. Ce n’est pas le rôle d’une AC : elle atteste un lien entre une clé publique et un nom, elle n’a pas besoin du secret. C’est pourquoi `pki.sh` et `renouveler.sh` génèrent la clé du côté du demandeur.

---

## Q4. Le CN et le SAN contiennent tous deux www.tp.local. Lequel les clients modernes vérifient-ils ?

Le **SAN** (noms alternatifs du sujet). Depuis la RFC 6125 (2011), remplacée par la RFC 9525 (2023), et les exigences du CA/Browser Forum, le nom du serveur doit être cherché dans l’extension SAN. Le CN n’est plus qu’un libellé : Chrome (depuis la version 58), Firefox, la bibliothèque `ssl` de Python (depuis 3.7), Go et d’autres l’ignorent complètement, et OpenSSL ne s’en sert pas dès qu’un SAN DNS existe. C’est pourquoi notre CSR place les noms dans le SAN. Le contrôle `-verify_hostname` de l’étape 5 et les contraintes de nom portent sur le SAN. Vérifier le CN est d’ailleurs une erreur classique (diapo 84).

---

## Q5. Quelles sont les limites des CRL ? Comparer avec OCSP et avec des certificats de très courte durée.

| Critère | CRL | OCSP (avec agrafage) | Certificats très courts (jours, heures) |
|---|---|---|---|
| Fraîcheur | Retard jusqu’à la publication suivante (ici 7 jours) | Réponse récente (quelques heures à jours) | Pas de révocation : la fenêtre d’exposition est la durée de vie |
| Taille / coût | Grandit avec le nombre de révocations, téléchargée en entier | Petite réponse par certificat | Rien à consulter ; émission très fréquente |
| Disponibilité | Point de distribution indisponible → échec ouvert ou fermé | Répondeur indisponible → idem (agrafage : le serveur porte la réponse) | Dépend de l’automatisation de l’émission (ACME) |
| Vie privée | Bonne (téléchargement global) | Mauvaise sans agrafage : le répondeur voit les sites visités | Bonne |
| Usage actuel | Revenue en force (Let’s Encrypt, CRL agrégées des navigateurs) | Let’s Encrypt a arrêté OCSP en 2025 | Tendance : 47 jours en 2029, quelques heures dans les maillages de services |

Limites constatées dans notre IGC : (1) les certificats de l’annexe B n’ont pas d’extension `crlDistributionPoints`, donc un client ne sait pas où trouver la CRL ; nous l’avons fournie à la main (`-CRLfile`, `ssl_crl`) ; (2) la CRL expire au bout de 7 jours : si on oublie de la régénérer, nginx rejettera tous les clients (« CRL has expired ») ; (3) entre la compromission et la publication suivante, la clé volée reste acceptée. La révocation est donc imparfaite, d’où la tendance aux durées courtes et à l’automatisation (diapo 89).

---

## Q6. Rédiger en dix lignes une politique de certification minimale pour cette infrastructure.

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
