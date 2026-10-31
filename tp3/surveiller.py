#!/usr/bin/env python3
"""surveiller.py - supervision des dates d'expiration des certificats d'un dossier.

Usage : surveiller.py [dossier] [--alerte 30] [--critique 7]

Pour chaque certificat PEM trouve (fichiers .crt, .pem, .cer ; une chaine peut
contenir plusieurs certificats), affiche le nombre de jours restants et un niveau :
    OK        plus de 30 jours
    ALERTE    moins de 30 jours
    CRITIQUE  moins de 7 jours, ou deja expire
Code de sortie (convention des outils de supervision type Nagios) :
    0 = tout est OK, 1 = au moins une ALERTE, 2 = au moins un CRITIQUE.
"""
import argparse
import datetime as dt
import pathlib
import sys

from cryptography import x509

NIVEAUX = {0: "OK", 1: "ALERTE", 2: "CRITIQUE"}


def certificats(dossier: pathlib.Path):
    for f in sorted(dossier.rglob("*")):
        if f.suffix.lower() not in (".crt", ".pem", ".cer") or not f.is_file():
            continue
        try:
            for c in x509.load_pem_x509_certificates(f.read_bytes()):
                yield f, c
        except ValueError:
            continue            # fichier sans certificat (CRL, cle...) : ignore


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("dossier", nargs="?", default=".")
    ap.add_argument("--alerte", type=int, default=30, help="seuil ALERTE en jours")
    ap.add_argument("--critique", type=int, default=7, help="seuil CRITIQUE en jours")
    a = ap.parse_args()

    maintenant = dt.datetime.now(dt.timezone.utc)
    pire, vus = 0, 0
    print(f"{'NIVEAU':<9} {'JOURS':>6}  {'EXPIRATION (UTC)':<17} {'FICHIER':<28} SUJET")
    for f, c in certificats(pathlib.Path(a.dossier)):
        vus += 1
        restant = c.not_valid_after_utc - maintenant
        jours = restant.total_seconds() / 86400
        niveau = 2 if jours < a.critique else 1 if jours < a.alerte else 0
        pire = max(pire, niveau)
        print(f"{NIVEAUX[niveau]:<9} {jours:>6.1f}  "
              f"{c.not_valid_after_utc:%Y-%m-%d %H:%M} {f.name:<28} {c.subject.rfc4514_string()}")
    if vus == 0:
        print("Aucun certificat trouve.", file=sys.stderr)
        return 2                 # un dossier vide est anormal : on alerte
    print(f"Etat global : {NIVEAUX[pire]} ({vus} certificats)")
    return pire


if __name__ == "__main__":
    sys.exit(main())
