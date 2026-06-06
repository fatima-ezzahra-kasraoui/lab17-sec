# Lab — OWASP UnCrackable Level 3 : Reverse Engineering Android

**Analyste** : Kasraoui Fatima Ezzahra  
**Date** : 2025-06-01  
**Outils** : Jadx-GUI · apktool · Ghidra · apksigner · adb · Python 3

---

## Objectifs

À la fin de ce lab, tu seras capable de :

- Décompiler et patcher une APK au niveau smali
- Analyser une librairie native `.so` avec Ghidra
- Contourner l'anti-debug, l'anti-Frida, l'anti-root et la vérification d'intégrité
- Comprendre un chiffrement XOR byte par byte
- Retrouver un mot de passe secret sans l'exécuter en clair

---

## Prérequis

| Outil | Lien |
|-------|------|
| Android Studio (émulateur ARM64 API 30+) | https://developer.android.com/studio |
| Ghidra | https://ghidra-sre.org |
| Jadx-GUI | https://github.com/skylot/jadx/releases |
| apktool | https://apktool.org/docs/install |
| Python 3 | https://python.org |

```bash
# Télécharger l'APK officiel
wget https://github.com/OWASP/owasp-mstg/raw/master/Crackmes/Android/Level_03/UnCrackable-Level3.apk
adb install UnCrackable-Level3.apk
```

---

## Workflow

```
Analyse Java (Jadx)
      ↓
Décompilation APK (apktool)
      ↓
Patch smali — suppression anti-root/tamper
      ↓
Patch libfoo.so — suppression anti-debug/anti-Frida (Ghidra)
      ↓
Recompilation + signature + installation
      ↓
Analyse native FUN_001012c0 (Ghidra)
      ↓
Décodage XOR → mot de passe secret
```

---

## Étape 1 — Analyse statique avec Jadx-GUI

Ouvrir l'APK dans Jadx-GUI et naviguer vers `sg.vantagepoint.uncrackable3.MainActivity`.

Points clés observés :
- `verifyLibs()` vérifie le CRC des `.so` et du DEX via la fonction native `baz` → si écart, `tampered = 31337`
- `onCreate()` appelle `showDialog()` si root détecté ou `tampered != 0` → l'app quitte
- `System.loadLibrary("foo")` charge `libfoo.so`
- La vraie vérification du mot de passe est déléguée au code natif

---

## Étape 2 — Décompilation avec apktool

```bash
apktool d UnCrackable-Level3.apk -o uncrackable3
```

Résultat : dossier `uncrackable3/` contenant `smali/` et `lib/`.

---

## Étape 3 — Patch smali (suppression du message « tampered »)

Fichier cible :
```
uncrackable3/smali/sg/vantagepoint/uncrackable3/MainActivity.smali
```

Rechercher `showDialog` (Ctrl+F) → aller au **2ème résultat** (dans `onCreate`).

**Remplacer ces deux lignes :**
```smali
const-string v0, "Rooting or tampering detected."
invoke-direct {p0, v0}, Lsg/vantagepoint/uncrackable3/MainActivity;->showDialog(Ljava/lang/String;)V
```

**Par :**
```smali
return-void
```

Optionnel — neutraliser complètement `showDialog` :
```smali
.method private showDialog(Ljava/lang/String;)V
.locals 3
return-void
.end method
```

---

## Étape 4 — Patch libfoo.so avec Ghidra (anti-debug + anti-Frida)

1. Importer `libfoo.so` dans Ghidra → analyser
2. Dans `Symbol Tree`, chercher `sub_73D0` (fonction dans `.init_array`)
3. Cette fonction : ouvre `/proc/self/maps`, cherche `frida`/`xposed`, utilise `ptrace`
4. **Patch** : remplacer la première instruction par `RET`
   - `Edit → Patch Instruction → RET`
5. Exporter : `File → Export → libfoo.so`
6. Remplacer dans `uncrackable3/lib/arm64-v8a/`

---

## Recompilation, signature et installation

```bash
# Recompiler
apktool b uncrackable3 -o UnCrackable-Level3-patched.apk

# Signer (Windows)
apksigner sign --ks "%USERPROFILE%\.android\debug.keystore" UnCrackable-Level3-patched.apk

# Signer (Linux/Mac)
apksigner sign --ks ~/.android/debug.keystore UnCrackable-Level3-patched.apk

# Désinstaller l'ancienne version et installer la nouvelle
adb uninstall owasp.mstg.uncrackable3
adb install -r UnCrackable-Level3-patched.apk
```

Mot de passe du keystore par défaut : `android`

---

## Étape 5 — Analyse native avec Ghidra (FUN_001012c0)

1. Dans Ghidra, chercher `Java_sg_vantagepoint_uncrackable3_Check_check_code`
2. Suivre l'appel vers `FUN_001012c0`
3. Observer la structure : 90+ blocs répétitifs → **obfuscation** (LCG + malloc + liste chaînée)
4. Se concentrer sur la **fin de la fonction** → 3 constantes de 8 octets chacune (24 octets total)

**Octets extraits (little-endian) :**
```
1d 08 11 13 0f 17 49 15  0d 00 03 19 5a 1d 13 15  08 0e 5a 00 17 08 13 14
```

Logique de vérification : comparaison octet par octet avec XOR entre les octets de référence et une clé dynamique. Longueur imposée : exactement **24 caractères**.

---

## Étape 6 — Décodage XOR et récupération du mot de passe

```python
# decode_key.py
encoded = bytes.fromhex("1d0811130f1749150d0003195a1d1315080e5a0017081314")
xor_key = b"pizzapizzapizzapizzapizzapizza"

secret = bytes(a ^ b for a, b in zip(encoded, xor_key))
print("Clé secrète :", secret.decode())
```

```bash
python decode_key.py
# Clé secrète : making owasp great again
```

Entrer `making owasp great again` dans l'application → **Success!**

---

## Techniques d'obfuscation identifiées

| Technique | Description |
|-----------|-------------|
| LCG (Linear Congruential Generator) | Génération de nombres pseudo-aléatoires pour noyer le code utile |
| malloc + liste chaînée | Allocation répétitive sans utilité fonctionnelle |
| Vérification native (JNI) | Délégation de la logique critique hors du bytecode Java |
| Clé XOR encodée | Clé non stockée en clair, reconstruite dynamiquement |

---

## Conclusion de sécurité

La protection repose sur trois techniques combinées :
1. **Déplacement dans le code natif** — hors de portée d'une analyse Java simple
2. **Obfuscation par code parasite** — noie la donnée utile dans ~90 blocs répétitifs
3. **Encodage XOR** — la clé n'est jamais stockée en clair dans le binaire

> Dans les apps obfusquées, la **fin des fonctions d'initialisation** contient souvent la donnée utile. Toujours suivre le flux de données plutôt que lire le pseudo-code linéairement.
