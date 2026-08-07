# 🔐 Crypto Educational Suite — Ing3 Cybersécurité

> Application pédagogique interactive couvrant les **TP1 à TP6** de cryptographie appliquée.  
> Interface graphique **Cyberpunk Neon** (CustomTkinter) avec logs détaillés étape par étape.

---

## 📹 Démonstration vidéo

🎬 **Lien Google Drive :** `[https://drive.google.com/file/d/13t7UUiBDCWHKYrtKSJapcSPKEWQzIWZC/view?usp=sharing]`.
** `[https://drive.google.com/file/d/1ZpQYCGmsX41t36749Pz9NU1cpBlDoQYQ/view?usp=drive_link]`.

---

## 📁 Structure du projet


```
CRYPTO_EDUCATIONAL_APP/
│
├── main.py # Point d'entrée — Interface graphique principale
├── secure_chat.py # TP6 — Communications sécurisées (SSL/BT/UDP/Vote)
│
├── algorithms/
│ ├── init.py # Export de tous les algorithmes
│ │
│ ├── ── TP1 : Chiffrement Classique ──
│ ├── caesar.py # César : force brute + IC
│ ├── vigenere.py # Vigenère : Kasiski + analyse IC
│ ├── affine.py # Affine : E(x) = (ax+b) mod 26
│ ├── hill.py # Hill 2×2 / 3×3 + attaque clair connu
│ ├── playfair.py # Playfair : grille 5×5
│ ├── Otp.py # OTP Vernam : XOR + crib dragging
│ │
│ ├── ── TP2 : Cryptographie Symétrique ──
│ ├── rc4.py # RC4 : KSA + PRGA + vulnérabilité WEP
│ ├── des.py # DES-ECB/CBC + 3DES + benchmark
│ ├── aes.py # AES-128/192/256 : ECB/CBC/CTR + avalanche
│ ├── twofish.py # Twofish (finaliste NIST — 2e)
│ ├── serpent.py # Serpent (finaliste NIST — 4e)
│ ├── rc6.py # RC6 (finaliste NIST)
│ ├── mars.py # MARS (finaliste NIST — IBM)
│ │
│ ├── ── TP3 : Cryptographie Asymétrique ──
│ ├── rsa.py # RSA-512/1024/2048 + OAEP + hybride AES
│ ├── Dh.py # Diffie-Hellman + MITM + contre-mesure ECDSA
│ ├── ecc.py # ECC y²=x³+7 + ECDH P-256 + ECIES
│ ├── elgamal.py # ElGamal + non-déterminisme + malléabilité
│ │
│ ├── ── TP4 : Fonctions de Hachage ──
│ ├── md5.py # MD5 : avalanche + biais
│ ├── sha256.py # SHA-256 from scratch + validation hashlib
│ ├── sha512.py # SHA-512 + benchmark MD5/SHA2/SHA3
│ │
│ ├── ── TP5 : Signatures Numériques ──
│ ├── rsa_signature.py # RSA-PSS / PKCS#1 v1.5 + attaques
│ ├── elgamal_signature.py # Signature ElGamal + attaque nonce
│ └── dsa_ecdsa.py # DSA + ECDSA + Ed25519 + attaque nonce réutilisé
│
└── ── TP6 : Communications Sécurisées ──
└── secure_chat.py # Application chat sécurisé multi-protocole
```

---

## ⚙️ Installation

### Prérequis

- Python **3.10+**
- pip

### Dépendances

```bash
pip install customtkinter cryptography pycryptodome sympy numpy pillow bleak qrcode
```

Pour Linux/WSL (Bluetooth RFCOMM) :
sudo apt install bluetooth libbluetooth-dev
pip install pybluez

| Package | Utilisation |
|---|---|
| `customtkinter` | Interface graphique principale |
| `cryptography` | ECDH, ECDSA, Ed25519, RSA-PSS |
| `pycryptodome` | RSA signature PKCS#1 / PSS |
| `sympy` | Génération de grands nombres premiers (RSA) |
| `numpy` | Opérations matricielles (AES, visualisation) |
| `pillow` | Démonstration ECB sur images |
| `bleak`	| Bluetooth LE (Windows/macOS/Linux moderne)|
| `qrcode`	| Génération QR codes pour échange de clés| 
| `pybluez`|	Bluetooth RFCOMM (Linux/WSL uniquement)| 


### Lancement

```bash
python main.py
python secure_chat.py

```

---

## 🖥️ Interface

L'application se compose de :

- **Sidebar** — navigation par catégorie (TP1 à TP5), 21 algorithmes disponibles
- **Zone centrale** — description de l'algorithme, saisie du texte et de la clé
- **Fenêtre de traitement** — logs pédagogiques détaillés étape par étape, barre de progression
- **Fenêtre de résultat** — résultat final avec animation et copie presse-papiers

---

## 🔐 Algorithmes disponibles

### TP1 — Chiffrement Classique

| Algorithme | Clé | Fonctionnalités spéciales |
|---|---|---|
| **César** | Entier 0–25 | Force brute, analyse IC, détection auto français |
| **Vigenère** | Mot alphabétique | `kasiski` → test Kasiski, `ic` → attaque IC automatique |
| **Affine** | `a,b` (ex: `5,8`) | Vérif. coprimalité, inverse mod 26 |
| **Hill** | 4 ou 9 entiers | Hill 2×2 et 3×3, `known_plain:P:C` → attaque clair connu |
| **Playfair** | Mot-clé | Grille 5×5, règles digraphe |
| **OTP Vernam** | `genkey` ou hex | `reuse:<msg2>` → vulnérabilité, `crib:<msg2>` → crib dragging |

### TP2 — Cryptographie Symétrique

| Algorithme | Clé | Fonctionnalités spéciales |
|---|---|---|
| **RC4** | Texte libre | `wep` → démonstration vulnérabilité IV faibles (attaque FMS) |
| **DES / 3DES** | Texte libre | ECB, CBC, 3DES, faiblesse ECB sur image |
| **AES** | Texte libre | ECB/CBC/CTR, avalanche sur IV, nonce-reuse CTR, benchmark 10 Mo |
| **Twofish** | Texte libre | Feistel 4 branches, MDS, PHT, 16 tours |
| **Serpent** | Texte libre | SPN, 32 tours, 8 S-boxes officielles |
| **RC6** | Texte libre | Rotations data-dependent, 20 tours |
| **MARS** | Texte libre | Structure hybride 3 phases, IBM 1998 |

### TP3 — Cryptographie Asymétrique

| Algorithme | Clé | Fonctionnalités spéciales |
|---|---|---|
| **RSA** | Texte libre | 512/1024/2048 bits, OAEP, hybride RSA+AES |
| **Diffie-Hellman** | Texte libre | DH 512 bits, simulation MITM, contre-mesure ECDSA |
| **ECC / ECDH** | Texte libre | Courbe y²=x³+7, ECDH P-256, ECIES hybride AES-256 |
| **ElGamal** | Texte libre | Non-déterminisme, malléabilité, comparaison RSA |

### TP4 — Fonctions de Hachage

| Algorithme | Mode | Fonctionnalités spéciales |
|---|---|---|
| **MD5** | Hash uniquement | `avalanche` → démonstration effet avalanche (≈50%) |
| **SHA-256** | Hash uniquement | Implémentation from-scratch + validation hashlib |
| **SHA-512** | Hash uniquement | Benchmark MD5 / SHA-256 / SHA-512 / SHA-3 |

### TP5 — Signatures Numériques

| Algorithme | Clé | Fonctionnalités spéciales |
|---|---|---|
| **RSA Signature** | Texte libre | PKCS#1 v1.5 + PSS, falsification existentielle |
| **ElGamal Signature** | Texte libre | Signature + attaque nonce réutilisé |
| **DSA / ECDSA** | Texte libre | DSA from scratch + ECDSA P-256/P-384 + Ed25519 + attaque nonce |

### TP6 — Communications Sécurisées
| Protocole	| Fonctionnalités| 
|---|---|---|
| TCP/IP + SSL/TLS| 	Serveur SSL avec certificats auto-signés, chiffrement AES-256| 
| Bluetooth RFCOMM| 	Découverte et connexion RFCOMM (Linux/WSL via PyBluez)| 
| Bluetooth BLE| 	Découverte BLE moderne (Windows via Bleak)| 
| UDP/Wi-Fi| 	Chat UDP chiffré avec maintien de présence (ping)| 
| Vote Homomorphique| 	Paillier - addition de votes chiffrés, dépouillement sans déchiffrement individuel| 

---

Sécurité implémentée dans TP6:
AES-256-CFB — chiffrement symétrique des messages

RSA-2048-OAEP — échange de clés sécurisé

RSA-PSS-SHA256 — signatures numériques

QR Code — échange de clés publiques hors-bandes

Certificats SSL auto-signés — pour les connexions TLS

## 🧪 Exemples d'utilisation

### César
```
Texte  : bonjour le monde
Clé    : 3
→      : ERQMRXU OH PRQGH
```

### Vigenère — Attaque automatique
```
Texte  : <cryptogramme>
Clé    : kasiski       ← estime la longueur de la clé
Clé    : ic            ← récupère la clé complète automatiquement
```

### Hill — Attaque clair connu
```
Texte  : <ignoré>
Clé    : known_plain:HELP:HIAT
→ Récupère la matrice K = P⁻¹ × C mod 26
```

### OTP — Vulnérabilité réutilisation
```
Texte  : Premier message secret
Clé    : reuse:Deuxieme message
→ Montre C1 XOR C2 = M1 XOR M2 (la clé disparaît)
```

### RC4 — WEP
```
Texte  : <ignoré>
Clé    : wep
→ Corrélations FMS sur 16 IV faibles
```

### MD5 — Avalanche
```
Texte  : Hello World
Clé    : avalanche
→ Affiche taux de bits différents ≈ 50%
```

---

## ⚠️ Remarques importantes

- L'application est **pédagogique uniquement** — les implémentations from-scratch (Hill, SHA-256, RC4, MARS...) ne sont pas destinées à un usage en production.
- **MD5, RC4, DES** sont présentés avec leurs vulnérabilités connues pour illustration.
- Les algorithmes asymétriques (RSA, ElGamal) utilisent des clés de taille réduite par défaut pour la démonstration — augmenter la taille pour un usage réel.
- `winsound` (bips sonores) fonctionne uniquement sur Windows. L'application reste pleinement fonctionnelle sans son sur Linux/macOS.
- Bluetooth TP6:

Sur Windows: utilisez bleak (BLE moderne)

Sur Linux/WSL: utilisez pybluez (RFCOMM)

Sur macOS: bleak est recommandé

---

## 👥 Auteurs

Projet réalisé dans le cadre des TPs de Cryptographie Appliquée — **Ing3 Cybersécurité 2025–2026**
- BENSLIMANE Salima Lamia
- YOUNSI Anfel
- KAMIRI Lilia

---

## 📄 Licence

Usage académique uniquement.
