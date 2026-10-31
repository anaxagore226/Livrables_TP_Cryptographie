"""Tests de securite du mini-coffre (pytest -v test_coffre.py)."""
import struct

import pytest
from cryptography.exceptions import InvalidTag

import coffre
from coffre import chiffrer, dechiffrer, rechiffrer, sous_cle, FormatInconnu

MDP = "correct horse battery staple"
NOM = "notes.txt"
DONNEES = b"Releve de notes - EC1 : 17/20\n" * 10


@pytest.fixture(scope="module")
def blob():
    return chiffrer(MDP, NOM, DONNEES)


# --- les cinq tests demandes -----------------------------------------------
def test_aller_retour(blob):
    """Correction : on retrouve exactement les donnees."""
    assert dechiffrer(MDP, NOM, blob) == DONNEES


def test_chiffrement_probabiliste(blob):
    """Deux chiffrements du meme fichier different (sel et nonce neufs)."""
    autre = chiffrer(MDP, NOM, DONNEES)
    assert autre != blob
    assert autre[16:32] != blob[16:32]      # sel different
    assert autre[32:44] != blob[32:44]      # nonce different


def test_mauvais_mot_de_passe(blob):
    """Authentification de la cle : un mauvais mot de passe est rejete."""
    with pytest.raises(InvalidTag):
        dechiffrer("mauvais mot de passe", NOM, blob)


@pytest.mark.parametrize("position", [44, 60, -1])
def test_octet_modifie(blob, position):
    """Integrite : un seul bit modifie dans le chiffre ou l'etiquette."""
    b = bytearray(blob)
    b[position] ^= 0x01
    with pytest.raises(InvalidTag):
        dechiffrer(MDP, NOM, bytes(b))


def test_fichier_renomme(blob):
    """Liaison au contexte : le nom fait partie des donnees associees."""
    with pytest.raises(InvalidTag):
        dechiffrer(MDP, "notes_admin.txt", blob)


# --- tests complementaires -------------------------------------------------
def test_entete_authentifie(blob):
    """Modifier le sel ou le nonce de l'en-tete est detecte."""
    for pos in (20, 40):
        b = bytearray(blob)
        b[pos] ^= 0x01
        with pytest.raises(InvalidTag):
            dechiffrer(MDP, NOM, bytes(b))


def test_parametres_affaiblis_rejetes(blob):
    """Un attaquant qui baisse t dans l'en-tete n'obtient qu'un rejet."""
    b = bytearray(blob)
    b[4:8] = struct.pack(">I", 1)
    with pytest.raises(InvalidTag):
        dechiffrer(MDP, NOM, bytes(b))


def test_parametres_absurdes_refuses(blob):
    """m = 4 Gio : refuse avant toute derivation (pas de deni de service)."""
    b = bytearray(blob)
    b[8:12] = struct.pack(">I", 0xFFFFFFFF)
    with pytest.raises(FormatInconnu):
        dechiffrer(MDP, NOM, bytes(b))


def test_format_inconnu(blob):
    with pytest.raises(FormatInconnu):
        dechiffrer(MDP, NOM, b"CFR2" + blob[4:])
    with pytest.raises(FormatInconnu):
        dechiffrer(MDP, NOM, b"trop court")


def test_separation_des_usages():
    k = bytes(32)
    assert sous_cle(k, b"chiffrement") != sous_cle(k, b"mac")
    assert len(sous_cle(k, b"chiffrement")) == 32


def test_evolution_des_parametres(monkeypatch):
    """Un ancien fichier (parametres faibles) reste lisible, puis est
    rechiffre avec les nouveaux parametres et un nouveau mot de passe."""
    ancien = chiffrer(MDP, NOM, DONNEES, t=2, m=19 * 1024, p=1)
    monkeypatch.setattr(coffre, "T", 4)
    monkeypatch.setattr(coffre, "M", 256 * 1024)
    nouveau = rechiffrer(MDP, "nouveau-mdp", NOM, ancien)
    assert struct.unpack(">III", nouveau[4:16]) == (4, 256 * 1024, 4)
    assert dechiffrer("nouveau-mdp", NOM, nouveau) == DONNEES
    with pytest.raises(InvalidTag):
        dechiffrer(MDP, NOM, nouveau)
