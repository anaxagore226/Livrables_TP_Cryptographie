"""Mesure du temps d'une derivation Argon2id pour plusieurs reglages (t, m)."""
import os, time
from coffre import cle_maitresse

sel = os.urandom(16)
print(f"{'t':>3} {'m (Mio)':>8} {'p':>2} {'temps (s)':>10}")
for t, m in [(1, 64), (2, 64), (3, 64), (4, 64), (3, 128), (2, 256), (3, 256), (4, 256)]:
    mesures = []
    for _ in range(3):
        d = time.perf_counter()
        cle_maitresse("MonMotDePasse", sel, t, m * 1024, 4)
        mesures.append(time.perf_counter() - d)
    print(f"{t:>3} {m:>8} {4:>2} {min(mesures):>10.3f}")
