"""coffre.py - mini-coffre de fichiers (TP 1, EC1 Ingenierie de la cryptographie).

Format d'un fichier chiffre (version CFR1) :

    +--------+----------------------+---------+----------+----------------------+
    | "CFR1" | t | m | p (3 x 4 o)  | sel 16o | nonce 12o| chiffre + etiquette  |
    +--------+----------------------+---------+----------+----------------------+
    <------------------ en-tete : 44 octets ------------->

Donnees associees (authentifiees, non chiffrees) = en-tete complet || nom du fichier.
Cle maitresse = Argon2id(mot de passe, sel, t, m, p) ; cle de chiffrement =
HKDF-SHA256(cle maitresse, info = b"coffre-v1|chiffrement").
"""
import os
import struct

from argon2.low_level import hash_secret_raw, Type
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

T, M, P = 3, 256 * 1024, 4         # temps, memoire (Kio), parallelisme : ~0,5 s mesure

MAGIC = b"CFR1"
PARAMS = struct.Struct(">III")     # t, m, p : 3 entiers non signes de 4 octets
TAILLE_SEL, TAILLE_NONCE, TAILLE_TAG = 16, 12, 16
TAILLE_ENTETE = len(MAGIC) + PARAMS.size + TAILLE_SEL + TAILLE_NONCE   # 44 octets

# Bornes acceptees a la relecture : un en-tete forge ne doit pas pouvoir
# imposer une derivation gigantesque (deni de service) ou ridiculement faible.
T_MIN, T_MAX = 1, 20
M_MIN, M_MAX = 8 * 1024, 2 * 1024 * 1024        # 8 Mio .. 2 Gio
P_MIN, P_MAX = 1, 16


class FormatInconnu(ValueError):
    """Le fichier n'est pas un coffre CFR1 valide."""


def cle_maitresse(mot_de_passe: str, sel: bytes, t: int = T, m: int = M, p: int = P) -> bytes:
    """Argon2id -> 32 octets."""
    return hash_secret_raw(secret=mot_de_passe.encode("utf-8"), salt=sel,
                           time_cost=t, memory_cost=m, parallelism=p,
                           hash_len=32, type=Type.ID)


def sous_cle(maitresse: bytes, usage: bytes) -> bytes:
    """HKDF-SHA256 avec info = b"coffre-v1|" + usage -> 32 octets."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"coffre-v1|" + usage).derive(maitresse)


def _donnees_associees(entete: bytes, nom: str) -> bytes:
    return entete + nom.encode("utf-8")


def chiffrer(mot_de_passe: str, nom: str, donnees: bytes,
             t: int = None, m: int = None, p: int = None) -> bytes:
    # parametres actuels du module par defaut (lus a l'appel : les durcir
    # plus tard dans T, M, P s'applique aux nouveaux fichiers)
    t, m, p = t or T, m or M, p or P
    sel = os.urandom(TAILLE_SEL)          # neuf a chaque appel
    nonce = os.urandom(TAILLE_NONCE)      # neuf a chaque appel
    entete = MAGIC + PARAMS.pack(t, m, p) + sel + nonce
    cle = sous_cle(cle_maitresse(mot_de_passe, sel, t, m, p), b"chiffrement")
    return entete + AESGCM(cle).encrypt(nonce, donnees, _donnees_associees(entete, nom))


def lire_entete(blob: bytes):
    """Decoupe et controle l'en-tete ; renvoie (entete, t, m, p, sel, nonce, chiffre)."""
    if len(blob) < TAILLE_ENTETE + TAILLE_TAG or blob[:4] != MAGIC:
        raise FormatInconnu("format de fichier inconnu")
    t, m, p = PARAMS.unpack_from(blob, 4)
    if not (T_MIN <= t <= T_MAX and M_MIN <= m <= M_MAX and P_MIN <= p <= P_MAX):
        raise FormatInconnu("parametres Argon2id hors limites")
    sel = blob[16:32]
    nonce = blob[32:44]
    return blob[:TAILLE_ENTETE], t, m, p, sel, nonce, blob[TAILLE_ENTETE:]


def dechiffrer(mot_de_passe: str, nom: str, blob: bytes) -> bytes:
    """Rend les donnees, ou leve InvalidTag (mot de passe faux, fichier modifie,
    nom different) - sans jamais distinguer ces cas."""
    entete, t, m, p, sel, nonce, chiffre = lire_entete(blob)
    cle = sous_cle(cle_maitresse(mot_de_passe, sel, t, m, p), b"chiffrement")
    return AESGCM(cle).decrypt(nonce, chiffre, _donnees_associees(entete, nom))


def rechiffrer(ancien_mdp: str, nouveau_mdp: str, nom: str, blob: bytes) -> bytes:
    """Change le mot de passe ; le nouveau fichier utilise les parametres
    Argon2id actuels (T, M, P), eventuellement plus forts que les anciens."""
    return chiffrer(nouveau_mdp, nom, dechiffrer(ancien_mdp, nom, blob))


if __name__ == "__main__":
    import argparse, getpass, sys
    ap = argparse.ArgumentParser(description="Mini-coffre de fichiers (AES-256-GCM + Argon2id)")
    ap.add_argument("action", choices=["chiffrer", "dechiffrer"])
    ap.add_argument("entree")
    ap.add_argument("sortie")
    a = ap.parse_args()
    mdp = getpass.getpass("Mot de passe : ")
    nom = os.path.basename(a.entree if a.action == "chiffrer" else a.sortie)
    with open(a.entree, "rb") as f:
        contenu = f.read()
    try:
        res = chiffrer(mdp, nom, contenu) if a.action == "chiffrer" else dechiffrer(mdp, nom, contenu)
    except (InvalidTag, FormatInconnu):
        sys.exit("Echec du dechiffrement.")      # message unique, volontairement vague
    with open(a.sortie, "wb") as f:
        f.write(res)
