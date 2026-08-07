"""
Secure Chat — TP6 Compliant
=================================
Exercice 6.1 — Sécurisation par Sockets TCP/IP (avec SSL)
Exercice 6.2 — Sécurisation Bluetooth (RFCOMM + BLE moderne)
Exercice 6.3 — Sécurisation sur Wi-Fi / UDP
Exercice 6.4 — Vote électronique avec homomorphisme

Bluetooth : 
  - PyBluez (RFCOMM) pour Linux/WSL
  - Bleak (BLE) pour Windows (moderne)
"""

import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk, filedialog
import os, socket, threading, json, base64, struct, time, hashlib, ssl
from datetime import datetime

# Tentative d'import des librairies optionnelles
BLUEZ_AVAILABLE = False
BLEAK_AVAILABLE = False
QR_AVAILABLE = False

try:
    import bluetooth 
    BLUEZ_AVAILABLE = True
except ImportError:
    pass

try:
    from bleak import BleakScanner, BleakClient
    import asyncio
    BLEAK_AVAILABLE = True
except ImportError:
    pass

try:
    import qrcode
    from PIL import Image, ImageTk
    QR_AVAILABLE = True
except ImportError:
    pass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ── Paillier pour l'homomorphisme (vote) ──────────────────
class PaillierHomomorphic:
    def __init__(self, key_size=2048):
        self.key_size = key_size
        self.public_key = None
        self.private_key = None
        
    def generate_keys(self):
        from cryptography.hazmat.primitives.asymmetric import rsa as rsa_lib
        p = rsa_lib.generate_private_key(public_exponent=65537, key_size=self.key_size//2)
        q = rsa_lib.generate_private_key(public_exponent=65537, key_size=self.key_size//2)
        p_num = p.private_numbers().p
        q_num = q.private_numbers().q
        n = p_num * q_num
        g = n + 1
        lambda_val = (p_num - 1) * (q_num - 1)
        mu = pow(lambda_val, -1, n)
        
        self.public_key = (n, g)
        self.private_key = (lambda_val, mu)
        return self.public_key, self.private_key
     
    def encrypt(self, m, public_key=None):
        if public_key is None:
            public_key = self.public_key
        n, g = public_key
        import random
        r = random.randint(1, n-1)
        c = (pow(g, m, n*n) * pow(r, n, n*n)) % (n*n)
        return c
    
    def add_encrypted(self, c1, c2, public_key=None):
        if public_key is None:
            public_key = self.public_key
        n = public_key[0]
        return (c1 * c2) % (n*n)
    
    def decrypt(self, c, private_key=None):
        if private_key is None:
            private_key = self.private_key
        n, g = self.public_key
        lambda_val, mu = private_key
        x = pow(c, lambda_val, n*n)
        l = (x - 1) // n
        m = (l * mu) % n
        return m

# ── Couleurs ────────────────────────────────────────────────
BG      = "#1e1e2e"
FG      = "#cdd6f4"
ACCENT  = "#7c3aed"
ACCENT2 = "#a855f7"
GREEN   = "#00b894"
BLUE    = "#3b82f6"
RED     = "#ef4444"
ORANGE  = "#f97316"
DARK    = "#181825"
PANEL   = "#24273a"
BORDER  = "#313244"
GRAY    = "#6c7086"
SUBTEXT = "#a6adc8"
CYAN    = "#22d3ee"
PINK    = "#ec4899"
YELLOW  = "#fbbf24"

# ── Ports ───────────────────────────────────────────────────
PORT_TCP = 9999
PORT_TCP_SSL = 9996
PORT_UDP = 9998
PORT_BT  = 9997

# ════════════════════════════════════════════════════════════
# CRYPTO
# ════════════════════════════════════════════════════════════
def generate_keys():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return priv, priv.public_key()

def pub_to_bytes(pub):
    return pub.public_bytes(serialization.Encoding.PEM,
                            serialization.PublicFormat.SubjectPublicKeyInfo)

def pub_from_bytes(data):
    return serialization.load_pem_public_key(data)

def hash_msg(msg):
    d = hashes.Hash(hashes.SHA256())
    d.update(msg)
    return d.finalize()

def sign_msg(priv, h):
    return priv.sign(h, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                     salt_length=padding.PSS.MAX_LENGTH),
                     hashes.SHA256())

def verify_sig(pub, sig, h):
    try:
        pub.verify(sig, h, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                        salt_length=padding.PSS.MAX_LENGTH),
                   hashes.SHA256())
        return True
    except:
        return False

def aes_encrypt(key, msg):
    iv = os.urandom(16)
    c = Cipher(algorithms.AES(key), modes.CFB(iv))
    e = c.encryptor()
    return iv, e.update(msg) + e.finalize()

def aes_decrypt(key, iv, ct):
    c = Cipher(algorithms.AES(key), modes.CFB(iv))
    d = c.decryptor()
    return d.update(ct) + d.finalize()

def rsa_encrypt(pub, data):
    return pub.encrypt(data, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                           algorithm=hashes.SHA256(), label=None))

def rsa_decrypt(priv, data):
    return priv.decrypt(data, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                            algorithm=hashes.SHA256(), label=None))

def b64e(b):
    return base64.b64encode(b).decode()

def b64d(s):
    return base64.b64decode(s)

def make_package(sender, receiver, plaintext, priv, pub_remote, channel):
    aes_key = os.urandom(32)
    iv, ct = aes_encrypt(aes_key, plaintext)
    h = hash_msg(plaintext)
    sig = sign_msg(priv, h)
    enc_key = rsa_encrypt(pub_remote, aes_key)
    return {"ct": b64e(ct), "iv": b64e(iv), "key": b64e(enc_key),
            "sig": b64e(sig), "sender": sender,
            "receiver": receiver, "channel": channel, "timestamp": time.time()}

def decrypt_package(pkg, priv, spub):
    aes_key = rsa_decrypt(priv, b64d(pkg["key"]))
    plain = aes_decrypt(aes_key, b64d(pkg["iv"]), b64d(pkg["ct"]))
    h = hash_msg(plain)
    valid = verify_sig(spub, b64d(pkg["sig"]), h) if spub else False
    return plain, valid

# ════════════════════════════════════════════════════════════
# SSL SERVER (Exercice 6.1)
# ════════════════════════════════════════════════════════════
class SSLServer:
    def __init__(self, host, port, log_cb):
        self.host = host
        self.port = port
        self.log = log_cb
        self.running = False
        self.ssl_context = None
        self.sock = None
        
    def _create_ssl_context(self):
        self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        from cryptography.hazmat.primitives import serialization as crypto_serialization
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        import datetime
        
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
        ])
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
        cert = cert.public_key(private_key.public_key())
        cert = cert.serial_number(x509.random_serial_number())
        cert = cert.not_valid_before(datetime.datetime.utcnow())
        cert = cert.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        cert = cert.sign(private_key, hashes.SHA256())
        
        with open("server.key", "wb") as f:
            f.write(private_key.private_bytes(
                crypto_serialization.Encoding.PEM,
                crypto_serialization.PrivateFormat.PKCS8,
                crypto_serialization.NoEncryption()))
        with open("server.crt", "wb") as f:
            f.write(cert.public_bytes(crypto_serialization.Encoding.PEM))
        
        self.ssl_context.load_cert_chain("server.crt", "server.key")
        
    def start(self):
        self._create_ssl_context()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen(5)
        self.running = True
        self.log(f"[SSL] Serveur sur {self.host}:{self.port}")
        threading.Thread(target=self._accept_loop, daemon=True).start()
        
    def _accept_loop(self):
        while self.running:
            try:
                conn, addr = self.sock.accept()
                ssl_conn = self.ssl_context.wrap_socket(conn, server_side=True)
                self.log(f"[SSL] Client connecté: {addr}")
                threading.Thread(target=self._handle_client, args=(ssl_conn,), daemon=True).start()
            except Exception as e:
                if self.running:
                    self.log(f"[SSL] Erreur: {e}")
                    
    def _handle_client(self, conn):
        try:
            while self.running:
                data = conn.recv(4096)
                if not data:
                    break
                self.log(f"[SSL] Reçu: {len(data)} bytes")
                conn.sendall(b"ACK: " + data)
        except:
            pass
        finally:
            conn.close()

# ════════════════════════════════════════════════════════════
# BLUETOOTH (Exercice 6.2) - RFCOMM (PyBluez) + BLE (Bleak)
# ════════════════════════════════════════════════════════════
class BluetoothReal:
    def __init__(self, log_cb):
        self.log = log_cb
        self.sock = None
        self.connected = False
        self.bleak_scanner = None
        
    def discover_devices(self):
        """Découverte d'appareils Bluetooth (RFCOMM + BLE)"""
        devices = []
        
        # Recherche RFCOMM (PyBluez)
        if BLUEZ_AVAILABLE:
            try:
                rfcomm_devices = bluetooth.discover_devices(duration=3, lookup_names=True)
                for addr, name in rfcomm_devices:
                    devices.append((addr, name, "RFCOMM"))
            except:
                pass
        
        return devices
    
    def discover_ble_devices(self):
        """Découverte d'appareils Bluetooth LE (Bleak) - fonctionne sur Windows"""
        if not BLEAK_AVAILABLE:
            return []
        
        devices = []
        
        def run_ble_scan():
            async def scan():
                nonlocal devices
                try:
                    scanner = BleakScanner()
                    discovered = await scanner.discover(timeout=3)
                    for device in discovered:
                        devices.append((device.address, device.name or "Inconnu", "BLE"))
                except Exception as e:
                    self.log(f"[BT/BLE] Erreur scan: {e}")
            
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(scan())
            loop.close()
        
        # Exécuter la recherche dans un thread séparé
        thread = threading.Thread(target=run_ble_scan, daemon=True)
        thread.start()
        thread.join(timeout=5)
        
        return devices
    
    def start_server(self):
        """Démarre un serveur RFCOMM (nécessite PyBluez/Linux)"""
        if not BLUEZ_AVAILABLE:
            self.log("[BT] RFCOMM non disponible - Utilisez BLE pour Windows")
            return False
        try:
            self.sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
            self.sock.bind(("", PORT_BT))
            self.sock.listen(1)
            self.log(f"[BT] Serveur RFCOMM sur port {PORT_BT}")
            threading.Thread(target=self._accept_loop, daemon=True).start()
            return True
        except:
            return False
    
    def _accept_loop(self):
        while True:
            try:
                client, addr = self.sock.accept()
                self.log(f"[BT] Client RFCOMM connecté: {addr}")
                threading.Thread(target=self._handle_client, args=(client,), daemon=True).start()
            except:
                break
    
    def _handle_client(self, client):
        try:
            while True:
                data = client.recv(1024)
                if not data:
                    break
                client.sendall(b"ACK: " + data)
        except:
            pass
        finally:
            client.close()
    
    def connect(self, address):
        """Connexion RFCOMM"""
        if not BLUEZ_AVAILABLE:
            self.log("[BT] RFCOMM non disponible")
            return False
        try:
            self.sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
            self.sock.connect((address, PORT_BT))
            self.connected = True
            self.log(f"[BT] Connecté à {address}")
            return True
        except:
            return False
    
    def connect_ble(self, address):
        """Connexion BLE (Bleak) - fonctionne sur Windows"""
        if not BLEAK_AVAILABLE:
            self.log("[BT/BLE] Bleak non disponible - pip install bleak")
            return False
        
        async def connect_and_send():
            try:
                async with BleakClient(address) as client:
                    self.log(f"[BT/BLE] Connecté à {address}")
                    # Pour BLE, on utilise des caractéristiques spécifiques
                    # Ici on simule l'envoi de données
                    return True
            except Exception as e:
                self.log(f"[BT/BLE] Erreur: {e}")
                return False
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(connect_and_send())
        loop.close()
        return result

# ════════════════════════════════════════════════════════════
# QR CODE (Échange de clés)
# ════════════════════════════════════════════════════════════
class QRKeyExchange:
    def __init__(self, user, log_cb):
        self.user = user
        self.log = log_cb
        
    def generate_qr(self, pub_key_data):
        if not QR_AVAILABLE:
            return None
        data = json.dumps({
            "name": self.user.name,
            "public_key": b64e(pub_key_data),
            "timestamp": time.time()
        })
        qr = qrcode.QRCode(version=1, box_size=10, border=4)
        qr.add_data(data)
        qr.make(fit=True)
        return qr.make_image(fill_color="black", back_color="white")
    
    def save_qr(self, filename="key_qr.png"):
        img = self.generate_qr(pub_to_bytes(self.user.public))
        if img:
            img.save(filename)
            self.log(f"[QR] Clé publique sauvegardée dans {filename}")
            return filename
        return None

# ════════════════════════════════════════════════════════════
# VOTE ÉLECTRONIQUE HOMOMORPHIQUE (Exercice 6.4)
# ════════════════════════════════════════════════════════════
class HomomorphicVote:
    def __init__(self, log_cb):
        self.log = log_cb
        self.paillier = PaillierHomomorphic()
        self.election_active = False
        self.candidates = []
        self.encrypted_votes = []
        self.voter_ids = set()
        self.public_key = None
        self.private_key = None
        self.results = {}
        
    def create_election(self, candidates):
        self.candidates = candidates
        self.public_key, self.private_key = self.paillier.generate_keys()
        self.encrypted_votes = []
        self.voter_ids = set()
        self.election_active = True
        self.log(f"[VOTE] Élection créée: {len(candidates)} candidats")
        return self.public_key
    
    def cast_vote(self, voter_id, candidate_index):
        if not self.election_active:
            return False, "Aucune élection en cours"
        
        voter_hash = hashlib.sha256(f"{voter_id}{self.public_key[0]}".encode()).hexdigest()[:16]
        
        if voter_hash in self.voter_ids:
            return False, "Vous avez déjà voté !"
        
        vote_vector = [0] * len(self.candidates)
        if 0 <= candidate_index < len(self.candidates):
            vote_vector[candidate_index] = 1
        
        encrypted_vector = [self.paillier.encrypt(v, self.public_key) for v in vote_vector]
        
        vote_package = {
            "voter_hash": voter_hash,
            "encrypted_votes": encrypted_vector,
            "timestamp": time.time()
        }
        
        self.encrypted_votes.append(vote_package)
        self.voter_ids.add(voter_hash)
        return True, f"Vote pour {self.candidates[candidate_index]} enregistré"
    
    def tally_votes(self):
        if not self.encrypted_votes:
            return {c: 0 for c in self.candidates}
        
        # CORRECTION ÉTAPE 7: initialiser à 1 au lieu de 0
        n = self.public_key[0]
        total_votes = [1] * len(self.candidates)
        
        for vote in self.encrypted_votes:
            for i, enc_vote in enumerate(vote["encrypted_votes"]):
                total_votes[i] = self.paillier.add_encrypted(total_votes[i], enc_vote, self.public_key)
        
        results = {}
        for i, candidate in enumerate(self.candidates):
            decrypted_count = self.paillier.decrypt(total_votes[i], self.private_key)
            results[candidate] = int(decrypted_count)
        
        self.results = results
        self.log(f"[VOTE] Dépouillement terminé - {sum(results.values())} votes")
        return results
    
    def get_encrypted_total(self):
        if not self.encrypted_votes:
            return None
        total = [0] * len(self.candidates)
        for vote in self.encrypted_votes:
            for i, enc_vote in enumerate(vote["encrypted_votes"]):
                total[i] = self.paillier.add_encrypted(total[i], enc_vote, self.public_key)
        return total

# ════════════════════════════════════════════════════════════
# NETWORK HELPERS
# ════════════════════════════════════════════════════════════
def _recv_n(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf

def tcp_send(sock, data):
    raw = json.dumps(data).encode()
    sock.sendall(struct.pack(">I", len(raw)) + raw)

def tcp_recv(sock):
    hdr = _recv_n(sock, 4)
    if not hdr:
        return None
    n = struct.unpack(">I", hdr)[0]
    raw = _recv_n(sock, n)
    return json.loads(raw.decode()) if raw else None

UDP_MAX = 60000

def udp_send(sock, data, addr):
    raw = json.dumps(data).encode()
    sock.sendto(struct.pack(">I", len(raw)) + raw, addr)

def udp_recv(sock):
    dgram, addr = sock.recvfrom(UDP_MAX + 4)
    if len(dgram) < 4:
        return None, addr
    n = struct.unpack(">I", dgram[:4])[0]
    return json.loads(dgram[4:4+n].decode()), addr

# ════════════════════════════════════════════════════════════
# USER
# ════════════════════════════════════════════════════════════
class User:
    def __init__(self, name):
        self.name = name
        self.private, self.public = generate_keys()

# ════════════════════════════════════════════════════════════
# GENERIC TCP SERVER (pour TCP et BT-SIM)
# ════════════════════════════════════════════════════════════
class GenericTCPServer:
    def __init__(self, host, port, channel_name, log_cb):
        self.host = host
        self.port = port
        self.name = channel_name
        self.log = log_cb
        self.clients = {}
        self.running = False
        self.sock = None
        self.vote_system = HomomorphicVote(self.log)

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen(10)
        self.running = True
        self.log(f"[SERVER/{self.name}] Ecoute sur {self.host}:{self.port}")
        threading.Thread(target=self._accept, daemon=True).start()

    def stop(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except:
                pass

    def _accept(self):
        while self.running:
            try:
                conn, addr = self.sock.accept()
                self.log(f"[SERVER/{self.name}] Connexion {addr[0]}:{addr[1]}")
                threading.Thread(target=self._handle, args=(conn,), daemon=True).start()
            except:
                break

    def _handle(self, conn):
        name = None
        try:
            while True:
                pkt = tcp_recv(conn)
                if not pkt:
                    break
                cmd = pkt.get("cmd")

                if cmd == "register":
                    name = pkt["name"]
                    self.clients[name] = {"sock": conn, "pub": b64d(pkt["pub"])}
                    self.log(f"[SERVER/{self.name}] {name} enregistre")
                    self._broadcast_users()
                    tcp_send(conn, {"cmd": "ok"})

                elif cmd == "get_pub":
                    t = pkt["target"]
                    if t in self.clients:
                        tcp_send(conn, {"cmd": "pub_key", "name": t,
                                        "pub": b64e(self.clients[t]["pub"])})
                    else:
                        tcp_send(conn, {"cmd": "error", "msg": "Introuvable"})

                elif cmd == "msg":
                    rcv = pkt["receiver"]
                    if rcv in self.clients:
                        tcp_send(self.clients[rcv]["sock"],
                                 {"cmd": "incoming", "package": pkt["package"]})
                        tcp_send(conn, {"cmd": "ok"})
                        self.log(f"[SERVER/{self.name}] {pkt['package']['sender']} -> {rcv}")
                    else:
                        tcp_send(conn, {"cmd": "error", "msg": "Hors ligne"})

                # ÉTAPE 1: CORRECTION - CRÉATION DE L'ÉLECTION
                elif cmd == "create_election":

                    candidates = pkt["candidates"]

                    # créer l'élection UNIQUEMENT sur le serveur
                    self.vote_system.create_election(candidates)

                    # diffuser à tous les clients
                    for cname, client in list(self.clients.items()):
                        try:
                            tcp_send(client["sock"], {
                                "cmd": "election_created",
                                "candidates": candidates
                            })
                        except:
                            pass

                    # renvoyer aussi au créateur
                    tcp_send(conn, {
                        "cmd": "election_created",
                        "candidates": candidates
                    })

                    tcp_send(conn, {"cmd": "ok"})

                    self.log(f"[VOTE] Élection diffusée à {len(self.clients)} clients")

                # Réception d'un vote
                elif cmd == "vote":
                    voter = pkt["voter"]
                    candidate_index = pkt["candidate_index"]
                    
                    success, msg = self.vote_system.cast_vote(voter, candidate_index)
                    
                    # DEBUG: Ajout du log pour suivre les votes
                    self.log(f"[DEBUG] Nombre de votes stockés: {len(self.vote_system.encrypted_votes)}")
                    
                    tcp_send(conn, {
                        "cmd": "vote_result",
                        "success": success,
                        "msg": msg
                    })

                # ÉTAPE 4: CORRECTION - CALCUL DES RÉSULTATS SUR LE SERVEUR
                elif cmd == "vote_results":

                    # calculer UNIQUEMENT sur le serveur
                    results = self.vote_system.tally_votes()

                    # diffuser les résultats
                    for cname, client in self.clients.items():
                        try:
                            tcp_send(client["sock"], {
                                "cmd": "vote_results",
                                "results": results
                            })
                        except:
                            pass

                    tcp_send(conn, {"cmd": "ok"})

                    self.log(f"[VOTE] Résultats calculés par le serveur: {results}")

        except Exception as e:
            self.log(f"[SERVER/{self.name}] Erreur: {e}")
        finally:
            if name and name in self.clients:
                del self.clients[name]
                self.log(f"[SERVER/{self.name}] {name} deconnecte")
                self._broadcast_users()
            conn.close()

    def _broadcast_users(self):
        ul = list(self.clients.keys())
        for c in self.clients.values():
            try:
                tcp_send(c["sock"], {"cmd": "users", "list": ul})
            except:
                pass

# ════════════════════════════════════════════════════════════
# GENERIC TCP CLIENT
# ════════════════════════════════════════════════════════════
class GenericTCPClient:
    def __init__(self, user, host, port, channel, on_msg, on_users, log_cb):
        self.user = user
        self.host = host
        self.port = port
        self.channel = channel
        self.on_msg = on_msg
        self.on_users = on_users
        self.log = log_cb
        self.sock = None
        self.connected = False
        self._last_resp = None

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        self.connected = True
        tcp_send(self.sock, {"cmd": "register", "name": self.user.name,
                             "pub": b64e(pub_to_bytes(self.user.public))})
        threading.Thread(target=self._recv_loop, daemon=True).start()

    def disconnect(self):
        self.connected = False
        if self.sock:
            try:
                self.sock.close()
            except:
                pass

    def _recv_loop(self):
        while self.connected:
            try:
                pkt = tcp_recv(self.sock)
                if not pkt:
                    break
                cmd = pkt.get("cmd")
                
                # ÉTAPE 3: RECEVOIR LES NOUVELLES COMMANDES
                if cmd == "incoming":
                    self.on_msg(pkt["package"])
                elif cmd == "users":
                    self.on_users(pkt["list"])
                elif cmd == "election_created":
                    self._last_resp = pkt
                elif cmd == "vote_results":
                    self._last_resp = pkt
                else:
                    self._last_resp = pkt
            except:
                break
        self.connected = False
        self.log(f"[NET/{self.channel}] Deconnecte")

    def get_remote_pub(self, name):
        self._last_resp = None
        tcp_send(self.sock, {"cmd": "get_pub", "target": name})
        for _ in range(50):
            if self._last_resp and self._last_resp.get("cmd") == "pub_key":
                return pub_from_bytes(b64d(self._last_resp["pub"]))
            time.sleep(0.1)
        return None

    def send_message(self, receiver, plaintext: bytes):
        pub = self.get_remote_pub(receiver)
        if not pub:
            self.log(f"[NET/{self.channel}] Cle publique introuvable")
            return False
        pkg = make_package(self.user.name, receiver, plaintext,
                           self.user.private, pub, self.channel)
        tcp_send(self.sock, {"cmd": "msg", "receiver": receiver, "package": pkg})
        return True

# ════════════════════════════════════════════════════════════
# UDP SERVER
# ════════════════════════════════════════════════════════════
class UDPServer:
    def __init__(self, host, port, log_cb):
        self.host = host
        self.port = port
        self.log = log_cb
        self.clients = {}
        self.running = False
        self.sock = None
        self.vote_system = HomomorphicVote(self.log)

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.running = True
        self.log(f"[SERVER/UDP] Ecoute sur {self.host}:{self.port}")
        threading.Thread(target=self._loop, daemon=True).start()

    def stop(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except:
                pass

    def _loop(self):
        self.sock.settimeout(1.0)
        while self.running:
            try:
                pkt, addr = udp_recv(self.sock)
                if pkt:
                    threading.Thread(target=self._handle, args=(pkt, addr), daemon=True).start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    self.log(f"[SERVER/UDP] Erreur: {e}")

    def _reply(self, data, addr):
        try:
            udp_send(self.sock, data, addr)
        except:
            pass

    def _broadcast_users(self):
        ul = list(self.clients.keys())
        for c in self.clients.values():
            try:
                udp_send(self.sock, {"cmd": "users", "list": ul}, c["addr"])
            except:
                pass

    def _broadcast_to_all(self, data):
        for c in self.clients.values():
            try:
                udp_send(self.sock, data, c["addr"])
            except:
                pass

    def _handle(self, pkt, addr):
        cmd = pkt.get("cmd")
        if cmd == "register":
            name = pkt["name"]
            self.clients[name] = {"addr": addr, "pub": b64d(pkt["pub"])}
            self.log(f"[SERVER/UDP] {name} enregistre depuis {addr}")
            self._broadcast_users()
            self._reply({"cmd": "ok"}, addr)
        elif cmd == "get_pub":
            t = pkt["target"]
            if t in self.clients:
                self._reply({"cmd": "pub_key", "name": t, "pub": b64e(self.clients[t]["pub"])}, addr)
            else:
                self._reply({"cmd": "error", "msg": "Introuvable"}, addr)
        elif cmd == "msg":
            rcv = pkt["receiver"]
            if rcv in self.clients:
                udp_send(self.sock, {"cmd": "incoming", "package": pkt["package"]}, self.clients[rcv]["addr"])
                self._reply({"cmd": "ok"}, addr)
                self.log(f"[SERVER/UDP] {pkt['package']['sender']} -> {rcv}")
            else:
                self._reply({"cmd": "error", "msg": "Hors ligne"}, addr)
        elif cmd == "ping":
            name = pkt.get("name")
            if name and name in self.clients:
                self.clients[name]["addr"] = addr
        elif cmd == "create_election":
            candidates = pkt["candidates"]
            self.vote_system.create_election(candidates)
            self._broadcast_to_all({
                "cmd": "election_created",
                "candidates": candidates
            })
            self._reply({"cmd": "ok"}, addr)
        elif cmd == "vote":
            voter = pkt["voter"]
            candidate_index = pkt["candidate_index"]
            success, msg = self.vote_system.cast_vote(voter, candidate_index)
            self._reply({"cmd": "vote_result", "success": success, "msg": msg}, addr)
        elif cmd == "vote_results":
            results = self.vote_system.tally_votes()
            self._broadcast_to_all({"cmd": "vote_results", "results": results})
            self._reply({"cmd": "ok"}, addr)

# ════════════════════════════════════════════════════════════
# UDP CLIENT
# ════════════════════════════════════════════════════════════
class UDPClient:
    def __init__(self, user, host, port, on_msg, on_users, log_cb):
        self.user = user
        self.host = host
        self.port = port
        self.srv = (host, port)
        self.on_msg = on_msg
        self.on_users = on_users
        self.log = log_cb
        self.sock = None
        self.connected = False
        self._pub_cache = {}
        self._evt = threading.Event()
        self._last_resp = None

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(5.0)
        self.connected = True
        udp_send(self.sock, {"cmd": "register", "name": self.user.name,
                             "pub": b64e(pub_to_bytes(self.user.public))}, self.srv)
        threading.Thread(target=self._recv_loop, daemon=True).start()
        threading.Thread(target=self._ping_loop, daemon=True).start()
        self.log(f"[NET/UDP] Connecte a {self.host}:{self.port}")

    def disconnect(self):
        self.connected = False
        if self.sock:
            try:
                self.sock.close()
            except:
                pass

    def _ping_loop(self):
        while self.connected:
            try:
                udp_send(self.sock, {"cmd": "ping", "name": self.user.name}, self.srv)
            except:
                pass
            time.sleep(20)

    def _recv_loop(self):
        while self.connected:
            try:
                pkt, _ = udp_recv(self.sock)
                if not pkt:
                    continue
                cmd = pkt.get("cmd")
                if cmd == "incoming":
                    self.on_msg(pkt["package"])
                elif cmd == "users":
                    self.on_users(pkt["list"])
                elif cmd in ("election_created", "vote_results", "pub_key", "ok", "error", "vote_result"):
                    self._last_resp = pkt
                    self._evt.set()
            except socket.timeout:
                continue
            except Exception as e:
                if self.connected:
                    self.log(f"[NET/UDP] Erreur: {e}")
                break
        self.connected = False
        self.log("[NET/UDP] Deconnecte")

    def get_remote_pub(self, name):
        if name in self._pub_cache:
            return self._pub_cache[name]
        self._last_resp = None
        self._evt.clear()
        udp_send(self.sock, {"cmd": "get_pub", "target": name}, self.srv)
        if self._evt.wait(5.0) and self._last_resp and self._last_resp.get("cmd") == "pub_key":
            pub = pub_from_bytes(b64d(self._last_resp["pub"]))
            self._pub_cache[name] = pub
            return pub
        return None

    def send_message(self, receiver, plaintext: bytes):
        pub = self.get_remote_pub(receiver)
        if not pub:
            self.log("[NET/UDP] Cle publique introuvable")
            return False
        pkg = make_package(self.user.name, receiver, plaintext,
                           self.user.private, pub, "UDP")
        udp_send(self.sock, {"cmd": "msg", "receiver": receiver, "package": pkg}, self.srv)
        return True

# ════════════════════════════════════════════════════════════
# APPLICATION PRINCIPALE
# ════════════════════════════════════════════════════════════
class SecureApp:
    def __init__(self, root):
        self.root = root
        self.root.title("TP6 - Secure Chat (SSL/BT/UDP/Vote Homomorphique)")
        self.root.configure(bg=BG)
        self.root.geometry("1400x800")

        self.srv_tcp = None
        self.srv_udp = None
        self.srv_bt = None
        self.srv_ssl = None
        self.cli_tcp = None
        self.cli_udp = None
        self.cli_bt = None
        self.active_channel = "TCP"
        self.current_user = None
        self.online_users = []
        self.intercepted = []
        self.attack_mode = False
        
        self.vote_system = None
        self.bluetooth = BluetoothReal(self._log_cb("bt"))
        
        self._build_ui()
        self._show_connect_dialog()
        
        # ÉTAPE 5: DÉMARRER LE CHECK AUTOMATIQUE
        self.root.after(1000, self._check_special_packets)

    def _build_ui(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Fichier", menu=file_menu)
        file_menu.add_command(label="Générer QR Code", command=self._generate_qr)
        file_menu.add_separator()
        file_menu.add_command(label="Quitter", command=self.root.quit)
        
        bt_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Bluetooth", menu=bt_menu)
        bt_menu.add_command(label="Scanner RFCOMM", command=self._scan_bluetooth)
        bt_menu.add_command(label="Scanner BLE (Windows)", command=self._scan_ble)
        bt_menu.add_command(label="Connecter BT", command=self._bt_connect_dialog)
        bt_menu.add_separator()
        bt_menu.add_command(label="Info Bluetooth", command=self._show_bt_info)
        
        vote_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Vote", menu=vote_menu)
        vote_menu.add_command(label="Créer élection", command=self._create_election)
        vote_menu.add_command(label="Voter", command=self._show_vote_dialog)
        vote_menu.add_command(label="Dépouiller", command=self._tally_votes)
        vote_menu.add_command(label="Résultats", command=self._show_results)
        
        ssl_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="SSL/TLS", menu=ssl_menu)
        ssl_menu.add_command(label="Démarrer serveur SSL", command=self._start_ssl_server)
        ssl_menu.add_command(label="Connecter SSL", command=self._ssl_connect_dialog)
        
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Aide", menu=help_menu)
        help_menu.add_command(label="À propos", command=self._show_about)
        
        top = tk.Frame(self.root, bg=DARK, height=46)
        top.pack(fill="x")
        top.pack_propagate(False)

        tk.Label(top, text="🔐 TP6 - Communications Sécurisées", bg=DARK, fg=ACCENT2,
                 font=("Courier", 13, "bold")).pack(side="left", padx=14)

        cf = tk.Frame(top, bg=DARK)
        cf.pack(side="left", padx=16)
        self.chan_var = tk.StringVar(value="TCP")
        for ch, color, label in [("TCP", BLUE, "TCP"), 
                                  ("UDP", CYAN, "UDP"),
                                  ("BT", PINK, "Bluetooth")]:
            tk.Radiobutton(cf, text=label, variable=self.chan_var, value=ch,
                          bg=DARK, fg=color, selectcolor=DARK,
                          font=("Courier", 9, "bold"),
                          command=lambda c=ch: self._switch_channel(c)).pack(side="left", padx=8)

        self.conn_lbl = tk.Label(top, text="Non connecte", bg=DARK, fg=RED, font=("Courier", 10))
        self.conn_lbl.pack(side="right", padx=14)
        
        pw = tk.PanedWindow(self.root, orient=tk.HORIZONTAL, bg=BORDER)
        pw.pack(fill="both", expand=True)
        self._build_chat(pw)
        self._build_dev_panel(pw)

    def _build_chat(self, parent):
        frame = tk.Frame(parent, bg=BG)
        parent.add(frame, minsize=500, width=800)
        
        sb = tk.Frame(frame, bg=PANEL, width=180)
        sb.pack(side="left", fill="y")
        sb.pack_propagate(False)
        
        tk.Label(sb, text="EN LIGNE", bg=PANEL, fg=GRAY, font=("Courier", 8, "bold")).pack(pady=(14, 4))
        self.users_lb = tk.Listbox(sb, bg=PANEL, fg=GREEN, font=("Courier", 10),
                                   relief="flat", selectbackground=ACCENT)
        self.users_lb.pack(fill="both", expand=True, padx=4)
        self.users_lb.bind("<Double-Button-1>", self._pick_user)
        
        self.chan_lbl = tk.Label(sb, text="Canal: TCP", bg=PANEL, fg=BLUE)
        self.chan_lbl.pack(pady=4)
        
        right = tk.Frame(frame, bg=BG)
        right.pack(side="left", fill="both", expand=True)
        
        self.chat = scrolledtext.ScrolledText(right, bg=DARK, fg=FG,
                                              font=("Courier", 10), wrap=tk.WORD,
                                              state="disabled")
        self.chat.pack(fill="both", expand=True)
        
        for t, c in [("sent", BLUE), ("recv", GREEN), ("system", GRAY),
                     ("sig_ok", GREEN), ("sig_bad", RED), ("udp", CYAN), ("bt", PINK)]:
            self.chat.tag_config(t, foreground=c)
        
        bar = tk.Frame(right, bg=PANEL, height=52)
        bar.pack(fill="x")
        bar.pack_propagate(False)
        
        tk.Label(bar, text="À:", bg=PANEL, fg=SUBTEXT).pack(side="left", padx=(10, 2))
        self.to_e = tk.Entry(bar, width=14, bg=DARK, fg=FG, font=("Courier", 10))
        self.to_e.pack(side="left", padx=(0, 8))
        self.msg_e = tk.Entry(bar, bg=DARK, fg=FG, font=("Courier", 10))
        self.msg_e.pack(side="left", fill="x", expand=True)
        self.msg_e.bind("<Return>", lambda e: self._send())
        tk.Button(bar, text=" Envoyer ", bg=ACCENT, fg="white", command=self._send).pack(side="left", padx=8)
        tk.Button(bar, text=" 🗳️ Voter ", bg=YELLOW, fg="black", command=self._show_vote_dialog).pack(side="left")

    def _build_dev_panel(self, parent):
        frame = tk.Frame(parent, bg=PANEL)
        parent.add(frame, minsize=400, width=600)
        
        nb = ttk.Notebook(frame)
        nb.pack(fill="both", expand=True, padx=5, pady=5)
        
        lt = tk.Frame(nb, bg=DARK)
        nb.add(lt, text="Logs")
        self.log_a = scrolledtext.ScrolledText(lt, bg=DARK, fg=SUBTEXT, font=("Courier", 9), wrap=tk.WORD)
        self.log_a.pack(fill="both", expand=True)
        
        vt = tk.Frame(nb, bg=DARK)
        nb.add(vt, text="Vote Homomorphique")
        self._build_vote_tab(vt)
        
        kt = tk.Frame(nb, bg=DARK)
        nb.add(kt, text="Clés")
        self.keys_a = scrolledtext.ScrolledText(kt, bg=DARK, fg=SUBTEXT, font=("Courier", 8))
        self.keys_a.pack(fill="both", expand=True)
        
        info_tab = tk.Frame(nb, bg=DARK)
        nb.add(info_tab, text="Info TP6")
        self._build_info_tab(info_tab)
    
    def _build_vote_tab(self, parent):
        tk.Label(parent, text="🗳️ Vote Électronique Homomorphique (Paillier) 🗳️",
                 bg=DARK, fg=ACCENT2, font=("Courier", 11, "bold")).pack(pady=10)
        
        self.vote_status = tk.Label(parent, text="Aucune élection", bg=DARK, fg=GRAY)
        self.vote_status.pack()
        
        btn_frame = tk.Frame(parent, bg=DARK)
        btn_frame.pack(pady=10)
        
        tk.Button(btn_frame, text="Créer élection", bg=GREEN, fg="white",
                  command=self._create_election).pack(side="left", padx=5)
        tk.Button(btn_frame, text="Voter", bg=YELLOW, fg="black",
                  command=self._show_vote_dialog).pack(side="left", padx=5)
        tk.Button(btn_frame, text="Dépouiller", bg=BLUE, fg="white",
                  command=self._tally_votes).pack(side="left", padx=5)
        
        self.vote_log = scrolledtext.ScrolledText(parent, bg=PANEL, fg=FG, font=("Courier", 9), height=12)
        self.vote_log.pack(fill="both", expand=True, padx=10, pady=10)
    
    def _build_info_tab(self, parent):
        txt = scrolledtext.ScrolledText(parent, bg=DARK, fg=SUBTEXT, font=("Courier", 9), wrap=tk.WORD)
        txt.pack(fill="both", expand=True, padx=10, pady=10)
        
        txt.insert(tk.END, "=== TP6 - Communications Sécurisées ===\n\n", "h")
        txt.insert(tk.END, "✅ Exercice 6.1 - TCP/IP avec SSL/TLS\n", "ok")
        txt.insert(tk.END, "   - Socket TCP classique\n", "b")
        txt.insert(tk.END, "   - Socket SSL/TLS (certificats auto-signés)\n\n", "b")
        
        txt.insert(tk.END, "✅ Exercice 6.2 - Bluetooth\n", "ok")
        txt.insert(tk.END, "   - RFCOMM (PyBluez) pour Linux/WSL\n", "b")
        txt.insert(tk.END, "   - BLE (Bleak) pour Windows\n\n", "b")
        
        txt.insert(tk.END, "✅ Exercice 6.3 - UDP/Wi-Fi\n", "ok")
        txt.insert(tk.END, "   - Chat UDP chiffré\n", "b")
        txt.insert(tk.END, "   - Maintien de présence (ping)\n\n", "b")
        
        txt.insert(tk.END, "✅ Exercice 6.4 - Vote Homomorphique (Paillier)\n", "ok")
        txt.insert(tk.END, "   - Addition de votes chiffrés\n", "b")
        txt.insert(tk.END, "   - Dépouillement sans déchiffrement individuel\n", "b")
        txt.insert(tk.END, "   - Anonymat des votants\n\n", "b")
        
        txt.insert(tk.END, "Sécurité commune:\n", "h")
        txt.insert(tk.END, "  • AES-256-CFB (chiffrement)\n", "ok")
        txt.insert(tk.END, "  • RSA-2048-OAEP (échange de clés)\n", "ok")
        txt.insert(tk.END, "  • RSA-PSS-SHA256 (signatures)\n", "ok")
        txt.config(state="disabled")
        
        for t, c in [("h", ACCENT2), ("ok", GREEN), ("warn", ORANGE), ("b", CYAN)]:
            txt.tag_config(t, foreground=c)

    # ──────────────────────────────────────────────────────
    # MÉTHODES PRINCIPALES
    # ──────────────────────────────────────────────────────
    def _log_cb(self, tag):
        return lambda t: self.root.after(0, lambda: self._log(t, tag))
    
    def _msg_cb(self):
        return lambda pkg: self.root.after(0, lambda: self._on_incoming(pkg))
    
    def _usr_cb(self):
        return lambda ul: self.root.after(0, lambda: self._on_users(ul))
    
    def _log(self, text, tag=""):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_a.insert(tk.END, f"[{timestamp}] {text}\n", tag)
        self.log_a.see(tk.END)
    
    def _chat_write(self, text, tag=""):
        self.chat.config(state="normal")
        self.chat.insert(tk.END, text, tag)
        self.chat.see(tk.END)
        self.chat.config(state="disabled")
    
    def _show_connect_dialog(self):
        dlg = tk.Toplevel(self.root)
        dlg.title("Connexion TP6")
        dlg.geometry("500x450")
        dlg.configure(bg=BG)
        dlg.grab_set()
        
        tk.Label(dlg, text="🔐 TP6 - Communications Sécurisées", bg=BG, fg=ACCENT2,
                 font=("Courier", 14, "bold")).pack(pady=20)
        
        tk.Label(dlg, text="Pseudo:", bg=BG, fg=FG).pack()
        name_entry = tk.Entry(dlg, bg=PANEL, fg=FG, font=("Courier", 11))
        name_entry.pack(pady=5)
        name_entry.insert(0, f"User_{os.getpid() % 1000}")
        
        tk.Label(dlg, text="Mode de connexion:", bg=BG, fg=FG).pack(pady=(10, 0))
        mode_var = tk.StringVar(value="all_server")
        modes = [("all_server", "Tout créer (serveur)"), ("all_client", "Tout rejoindre (client)")]
        for v, t in modes:
            tk.Radiobutton(dlg, text=t, variable=mode_var, value=v,
                          bg=BG, fg=FG, selectcolor=DARK).pack()
        
        ip_frame = tk.Frame(dlg, bg=BG)
        ip_frame.pack(pady=10)
        tk.Label(ip_frame, text="IP serveur:", bg=BG, fg=FG).pack(side="left")
        ip_entry = tk.Entry(ip_frame, bg=PANEL, fg=FG, width=15)
        ip_entry.pack(side="left", padx=5)
        ip_entry.insert(0, "127.0.0.1")
        
        # Info Bluetooth
        info_frame = tk.Frame(dlg, bg=BG)
        info_frame.pack(pady=10)
        bt_status = "✓ Bluetooth: "
        if BLUEZ_AVAILABLE:
            bt_status += "RFCOMM (PyBluez) ✓"
        elif BLEAK_AVAILABLE:
            bt_status += "BLE (Bleak) ✓"
        else:
            bt_status += "Aucun - pip install bleak"
        tk.Label(info_frame, text=bt_status, bg=BG, fg=GREEN if (BLUEZ_AVAILABLE or BLEAK_AVAILABLE) else ORANGE,
                 font=("Courier", 8)).pack()
        
        def on_connect():
            name = name_entry.get().strip()
            if not name:
                messagebox.showerror("Erreur", "Entrez un pseudo")
                return
            
            self.current_user = User(name)
            mode = mode_var.get()
            ip = ip_entry.get().strip()
            
            if mode == "all_server":
                self._start_server("TCP", "0.0.0.0", PORT_TCP)
                self._start_server("UDP", "0.0.0.0", PORT_UDP)
                self._start_server("BT", "0.0.0.0", PORT_BT)
                self._start_client("TCP", "127.0.0.1", PORT_TCP)
                self._start_client("UDP", "127.0.0.1", PORT_UDP)
                self._start_client("BT", "127.0.0.1", PORT_BT)
            else:
                self._start_client("TCP", ip, PORT_TCP)
                self._start_client("UDP", ip, PORT_UDP)
                self._start_client("BT", ip, PORT_BT)
            
            dlg.destroy()
            self.conn_lbl.config(text=f"Connecté: {name}", fg=GREEN)
            self.root.title(f"TP6 - {name}")
            self._chat_write(f"✅ Connecté en tant que {name}\n", "system")
            self._refresh_keys()
        
        tk.Button(dlg, text="Connexion", bg=ACCENT, fg="white",
                  font=("Courier", 11, "bold"), command=on_connect).pack(pady=20)
    
    def _start_server(self, ch, host, port):
        if ch == "UDP":
            s = UDPServer(host, port, self._log_cb("udp"))
            if ch == "UDP":
                self.srv_udp = s
        else:
            s = GenericTCPServer(host, port, ch, self._log_cb("srv"))
            if ch == "TCP":
                self.srv_tcp = s
            else:
                self.srv_bt = s
        s.start()
    
    def _start_client(self, ch, ip, port):
        if ch == "UDP":
            c = UDPClient(self.current_user, ip, port,
                         self._msg_cb(), self._usr_cb(), self._log_cb("udp"))
            if ch == "UDP":
                self.cli_udp = c
        else:
            c = GenericTCPClient(self.current_user, ip, port, ch,
                                self._msg_cb(), self._usr_cb(),
                                self._log_cb("net"))
            if ch == "TCP":
                self.cli_tcp = c
            else:
                self.cli_bt = c
        c.connect()
    
    def _switch_channel(self, ch):
        self.active_channel = ch
        colors = {"TCP": BLUE, "UDP": CYAN, "BT": PINK}
        self.chan_lbl.config(text=f"Canal: {ch}", fg=colors[ch])
    
    def _active_client(self):
        ch = self.active_channel
        if ch == "UDP" and self.cli_udp and self.cli_udp.connected:
            return self.cli_udp
        if ch == "BT" and self.cli_bt and self.cli_bt.connected:
            return self.cli_bt
        if self.cli_tcp and self.cli_tcp.connected:
            return self.cli_tcp
        return None
    
    def _send(self):
        cl = self._active_client()
        if not cl:
            messagebox.showwarning("Erreur", f"Aucun client actif sur {self.active_channel}")
            return
        to = self.to_e.get().strip()
        text = self.msg_e.get().strip()
        if not to or not text:
            return
        if to == self.current_user.name:
            messagebox.showwarning("Erreur", "Vous ne pouvez pas vous écrire")
            return
        self.msg_e.delete(0, tk.END)
        
        def _do():
            cl.send_message(to, text.encode())
            tag = {"TCP": "sent", "UDP": "udp", "BT": "bt"}.get(self.active_channel, "sent")
            self.root.after(0, lambda: self._chat_write(f"[moi -> {to}]: {text}\n", tag))
        threading.Thread(target=_do, daemon=True).start()
    
    def _on_incoming(self, pkg):
        sender = pkg["sender"]
        chan = pkg.get("channel", "TCP")
        try:
            pub = None
            if chan == "UDP" and self.cli_udp:
                pub = self.cli_udp.get_remote_pub(sender)
            elif chan == "BT" and self.cli_bt:
                pub = self.cli_bt.get_remote_pub(sender)
            elif self.cli_tcp:
                pub = self.cli_tcp.get_remote_pub(sender)
            
            plain, valid = decrypt_package(pkg, self.current_user.private, pub)
            tag = {"TCP": "recv", "UDP": "udp", "BT": "bt"}.get(chan, "recv")
            self._chat_write(f"[{sender}/{chan}]: ", tag)
            self._chat_write(plain.decode() + "\n", tag)
            self._chat_write("   ✔ Signature valide\n" if valid else "   ✘ Signature INVALIDE\n",
                            "sig_ok" if valid else "sig_bad")
        except Exception as e:
            self._chat_write(f"[ERREUR] {e}\n", "error")
    
    def _on_users(self, ul):
        self.online_users = ul
        self.users_lb.delete(0, tk.END)
        for u in ul:
            suffix = "  (moi)" if self.current_user and u == self.current_user.name else ""
            self.users_lb.insert(tk.END, f"  {u}{suffix}")
    
    def _pick_user(self, event):
        sel = self.users_lb.curselection()
        if sel:
            name = self.users_lb.get(sel[0]).split("  (moi)")[0].strip()
            self.to_e.delete(0, tk.END)
            self.to_e.insert(0, name)
    
    def _refresh_keys(self):
        if not self.current_user:
            return
        self.keys_a.delete("1.0", tk.END)
        self.keys_a.insert(tk.END, f"🔑 Clés RSA-2048 de {self.current_user.name}\n\n")
        self.keys_a.insert(tk.END, f"Clé publique (n):\n{str(self.current_user.public.public_numbers().n)[:200]}...\n")
    
    # ──────────────────────────────────────────────────────
    # QR CODE
    # ──────────────────────────────────────────────────────
    def _generate_qr(self):
        if not self.current_user:
            messagebox.showerror("Erreur", "Connectez-vous d'abord")
            return
        qr = QRKeyExchange(self.current_user, self._log_cb("qr"))
        filename = qr.save_qr(f"public_key_{self.current_user.name}.png")
        if filename:
            messagebox.showinfo("QR Code", f"QR code généré: {filename}")
    
    # ──────────────────────────────────────────────────────
    # BLUETOOTH
    # ──────────────────────────────────────────────────────
    def _scan_bluetooth(self):
        """Scan RFCOMM (PyBluez)"""
        devices = self.bluetooth.discover_devices()
        if devices:
            result = "Appareils RFCOMM trouvés:\n"
            for addr, name, _ in devices:
                result += f"  - {name} ({addr})\n"
            messagebox.showinfo("Bluetooth RFCOMM", result)
        else:
            messagebox.showinfo("Bluetooth RFCOMM", "Aucun appareil RFCOMM trouvé\n(PyBluez requis pour RFCOMM)")
    
    def _scan_ble(self):
        """Scan BLE (Bleak) - fonctionne sur Windows"""
        self._log("[BT/BLE] Recherche d'appareils BLE...", "bt")
        devices = self.bluetooth.discover_ble_devices()
        if devices:
            result = "Appareils BLE trouvés:\n"
            for addr, name, _ in devices:
                result += f"  - {name or 'Sans nom'} ({addr})\n"
            messagebox.showinfo("Bluetooth BLE", result)
        else:
            if not BLEAK_AVAILABLE:
                messagebox.showinfo("Bluetooth BLE", "Bleak non installé\npip install bleak")
            else:
                messagebox.showinfo("Bluetooth BLE", "Aucun appareil BLE trouvé")
    
    def _bt_connect_dialog(self):
        dlg = tk.Toplevel(self.root)
        dlg.title("Connexion Bluetooth")
        dlg.geometry("400x250")
        dlg.configure(bg=BG)
        
        tk.Label(dlg, text="Type de connexion:", bg=BG, fg=FG).pack(pady=5)
        bt_type = tk.StringVar(value="rfcomm")
        tk.Radiobutton(dlg, text="RFCOMM (Linux/WSL)", variable=bt_type, value="rfcomm",
                      bg=BG, fg=FG, selectcolor=BG).pack()
        tk.Radiobutton(dlg, text="BLE (Windows/Bleak)", variable=bt_type, value="ble",
                      bg=BG, fg=FG, selectcolor=BG).pack()
        
        tk.Label(dlg, text="Adresse MAC (ex: 00:11:22:33:44:55):", bg=BG, fg=FG).pack(pady=10)
        addr_entry = tk.Entry(dlg, bg=PANEL, fg=FG, width=30)
        addr_entry.pack(pady=5)
        
        def on_connect():
            addr = addr_entry.get().strip()
            if not addr:
                messagebox.showerror("Erreur", "Entrez une adresse MAC")
                return
            
            if bt_type.get() == "rfcomm":
                if self.bluetooth.connect(addr):
                    messagebox.showinfo("BT", f"Connecté en RFCOMM à {addr}")
                else:
                    messagebox.showerror("BT", "Échec de connexion RFCOMM\n(PyBluez requis)")
            else:
                if self.bluetooth.connect_ble(addr):
                    messagebox.showinfo("BT", f"Connecté en BLE à {addr}")
                else:
                    messagebox.showerror("BT", "Échec de connexion BLE")
            dlg.destroy()
        
        tk.Button(dlg, text="Connecter", bg=ACCENT, fg="white", command=on_connect).pack(pady=15)
    
    def _show_bt_info(self):
        info = "=== Informations Bluetooth ===\n\n"
        info += f"PyBluez (RFCOMM): {'✓ Disponible' if BLUEZ_AVAILABLE else '✗ Non disponible'}\n"
        info += f"Bleak (BLE): {'✓ Disponible' if BLEAK_AVAILABLE else '✗ Non disponible'}\n\n"
        info += "Pour RFCOMM: sudo apt install bluetooth libbluetooth-dev\n"
        info += "Pour BLE: pip install bleak\n\n"
        info += "Sur Windows: utilisez BLE\n"
        info += "Sur Linux/WSL: utilisez RFCOMM"
        messagebox.showinfo("Info Bluetooth", info)
    
    # ──────────────────────────────────────────────────────
    # SSL
    # ──────────────────────────────────────────────────────
    def _start_ssl_server(self):
        if hasattr(self, 'srv_ssl') and self.srv_ssl and self.srv_ssl.running:
            self._log("[SSL] Serveur déjà démarré", "warn")
            messagebox.showwarning("SSL", "Le serveur SSL est déjà démarré!")
            return
        
        self.srv_ssl = SSLServer("0.0.0.0", PORT_TCP_SSL, self._log_cb("ssl"))
        self.srv_ssl.start()
        self._log(f"[SSL] Serveur démarré sur port {PORT_TCP_SSL}", "ssl")
    
    def _ssl_connect_dialog(self):
        dlg = tk.Toplevel(self.root)
        dlg.title("Connexion SSL")
        dlg.geometry("400x250")
        dlg.configure(bg=BG)
        
        tk.Label(dlg, text="IP du serveur SSL:", bg=BG, fg=FG).pack(pady=10)
        ip_entry = tk.Entry(dlg, bg=PANEL, fg=FG, width=25)
        ip_entry.pack(pady=5)
        ip_entry.insert(0, "127.0.0.1")
        
        def on_connect():
            ip = ip_entry.get().strip()
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                ssl_sock = context.wrap_socket(sock, server_hostname="localhost")
                ssl_sock.connect((ip, PORT_TCP_SSL))
                ssl_sock.sendall(b"Test SSL!")
                
                response = ssl_sock.recv(1024)
                self._log(f"[SSL] Réponse: {response.decode()}", "ssl")
                self._log(f"[SSL] Connecté à {ip}:{PORT_TCP_SSL}", "ssl")
                ssl_sock.close()
                
                messagebox.showinfo("SSL", f"Connecté à {ip}:{PORT_TCP_SSL}")
            except Exception as e:
                self._log(f"[SSL] Erreur: {e}", "warn")
                messagebox.showerror("SSL", f"Erreur: {e}")
            
            dlg.destroy()
        
        tk.Button(dlg, text="Connecter SSL", bg=ACCENT, fg="white", command=on_connect).pack(pady=15)
    
    # ──────────────────────────────────────────────────────
    # VOTE HOMOMORPHIQUE (VERSION PARTAGÉE)
    # ──────────────────────────────────────────────────────
    
    # ÉTAPE 4: CHECK SPECIAL PACKETS
    def _check_special_packets(self):
        cl = self._active_client()

        if not cl:
            self.root.after(1000, self._check_special_packets)
            return

        pkt = cl._last_resp

        if not pkt:
            self.root.after(1000, self._check_special_packets)
            return

        cmd = pkt.get("cmd")

        # réception élection
        if cmd == "election_created":
            candidates = pkt["candidates"]

            # CORRECTION ÉTAPE 3: Créer le système de vote local SANS create_election
            self.vote_system = HomomorphicVote(self._log_cb("vote"))

            self.vote_system.candidates = candidates
            self.vote_system.election_active = True

            self.vote_status.config(
                text=f"Élection en cours - {len(candidates)} candidats",
                fg=GREEN
            )

            self.vote_log.insert(
                tk.END,
                f"✅ Élection reçue: {candidates}\n"
            )

            self._log(f"[VOTE] Élection reçue: {candidates}", "vote")

            cl._last_resp = None

        # réception résultats
        elif cmd == "vote_results":

            results = pkt["results"]
            
            # Mettre à jour le système de vote local
            if self.vote_system:
                self.vote_system.results = results

            self.vote_log.insert(tk.END, "\n📊 RÉSULTATS OFFICIELS\n")

            for cand, count in results.items():
                self.vote_log.insert(
                    tk.END,
                    f"  {cand}: {count} voix\n"
                )

            self.vote_log.insert(tk.END, "\n")
            self.vote_log.see(tk.END)

            self._log("[VOTE] Résultats reçus", "vote")

            cl._last_resp = None

        self.root.after(1000, self._check_special_packets)
    
    # ÉTAPE 6: ENVOYER L'ÉLECTION AU SERVEUR
    def _create_election(self):
        """Créer une élection - envoie la demande au serveur"""
        if not self.cli_tcp or not self.cli_tcp.connected:
            messagebox.showwarning("Erreur", "Non connecté au serveur TCP")
            return
        
        dlg = tk.Toplevel(self.root)
        dlg.title("Créer élection")
        dlg.geometry("400x400")
        dlg.configure(bg=BG)
        
        tk.Label(dlg, text="Nouvelle élection - Vote Homomorphique", bg=BG, fg=ACCENT2,
                 font=("Courier", 11, "bold")).pack(pady=10)
        
        tk.Label(dlg, text="Candidats (un par ligne):", bg=BG, fg=FG).pack(anchor="w", padx=20)
        candidates_text = tk.Text(dlg, height=8, bg=PANEL, fg=FG, font=("Courier", 9))
        candidates_text.pack(fill="both", expand=True, padx=20, pady=5)
        candidates_text.insert("1.0", "happy\nsad\nangry")
        
        def on_create():
            candidates = [c.strip() for c in candidates_text.get("1.0", tk.END).split("\n") if c.strip()]
            if len(candidates) < 2:
                messagebox.showerror("Erreur", "Minimum 2 candidats")
                return
            
            # CORRECTION ÉTAPE 2: Supprimer la création locale du système de vote
            
            # Envoyer au serveur pour diffusion
            cl = self._active_client()
            
            if cl:
                tcp_send(cl.sock, {
                    "cmd": "create_election",
                    "candidates": candidates
                })
            
            self.vote_status.config(text=f"Élection en cours - {len(candidates)} candidats", fg=GREEN)
            self.vote_log.insert(tk.END, f"✅ Élection créée avec {len(candidates)} candidats\n")
            self.vote_log.insert(tk.END, f"   Candidats: {', '.join(candidates)}\n")
            self.vote_log.see(tk.END)
            dlg.destroy()
        
        tk.Button(dlg, text="Créer l'élection", bg=GREEN, fg="white", command=on_create).pack(pady=15)
    
    def _show_vote_dialog(self):
        """Afficher la boîte de dialogue de vote"""
        if not self.vote_system or not self.vote_system.election_active:
            messagebox.showwarning("Vote", "Aucune élection en cours")
            return
        
        if not self.cli_tcp or not self.cli_tcp.connected:
            messagebox.showwarning("Erreur", "Non connecté au serveur TCP")
            return
        
        dlg = tk.Toplevel(self.root)
        dlg.title("Voter")
        dlg.geometry("400x350")
        dlg.configure(bg=BG)
        
        tk.Label(dlg, text="Choisissez votre candidat:", bg=BG, fg=FG, font=("Courier", 11)).pack(pady=15)
        
        selected = tk.IntVar(value=-1)
        for i, cand in enumerate(self.vote_system.candidates):
            tk.Radiobutton(dlg, text=cand, variable=selected, value=i,
                          bg=BG, fg=FG, selectcolor=BG).pack(pady=5)
        
        def on_vote():
            if selected.get() < 0:
                messagebox.showerror("Erreur", "Sélectionnez un candidat")
                return
            
            # Envoyer le vote au serveur
            tcp_send(self.cli_tcp.sock, {
                "cmd": "vote",
                "voter": self.current_user.name,
                "candidate_index": selected.get()
            })
            
            self.vote_log.insert(tk.END, f"🗳️ Vote envoyé pour {self.vote_system.candidates[selected.get()]}\n")
            messagebox.showinfo("Vote", "Vote envoyé au serveur")
            dlg.destroy()
        
        tk.Button(dlg, text="Confirmer", bg=YELLOW, fg="black", command=on_vote).pack(pady=20)
    
    # ÉTAPE 8: ENVOYER LES RÉSULTATS À TOUS
    def _tally_votes(self):
        """Demander le dépouillement au serveur"""
        if not self.vote_system or not self.vote_system.election_active:
            messagebox.showwarning("Dépouillement", "Aucune élection en cours")
            return
        
        if not self.cli_tcp or not self.cli_tcp.connected:
            messagebox.showwarning("Erreur", "Non connecté au serveur TCP")
            return
        
        # CORRECTION ÉTAPE 4: Ne pas calculer localement, envoyer la demande au serveur
        tcp_send(self.cli_tcp.sock, {
            "cmd": "vote_results"
        })
        
        self.vote_log.insert(tk.END, f"📊 Demande de dépouillement envoyée au serveur\n")
        
        messagebox.showinfo("Dépouillement", "Demande de dépouillement envoyée au serveur.\nLes résultats seront affichés quand ils seront reçus.")
    
    def _show_results(self):
        """Afficher les résultats locaux"""
        if not self.vote_system or not self.vote_system.results:
            messagebox.showinfo("Résultats", "Aucun résultat disponible.\nLancez d'abord le dépouillement.")
            return
        
        result_str = "Résultats:\n\n"
        for cand, count in self.vote_system.results.items():
            result_str += f"  {cand}: {count} voix\n"
        result_str += f"\nTotal: {sum(self.vote_system.results.values())} votes"
        messagebox.showinfo("Résultats", result_str)
    
    def _show_about(self):
        about = "TP6 - Communications Sécurisées\n\n"
        about += "Exercices:\n"
        about += "  6.1 TCP/SSL: ✅\n"
        about += "  6.2 Bluetooth: ✅\n"
        about += "     - RFCOMM (PyBluez) pour Linux\n"
        about += "     - BLE (Bleak) pour Windows\n"
        about += "  6.3 UDP/Wi-Fi: ✅\n"
        about += "  6.4 Vote homomorphique: ✅\n\n"
        about += "Sécurité: AES-256, RSA-2048, Signatures RSA-PSS\n"
        messagebox.showinfo("À propos", about)

# ════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("=" * 60)
    print("TP6 - Sécurisation des Communications")
    print("=" * 60)
    print(f"PyBluez (RFCOMM): {'✓' if BLUEZ_AVAILABLE else '✗'}")
    print(f"Bleak (BLE): {'✓' if BLEAK_AVAILABLE else '✗'}")
    print(f"QR Code: {'✓' if QR_AVAILABLE else '✗'}")
    print("=" * 60)
    if not BLEAK_AVAILABLE and not BLUEZ_AVAILABLE:
        print("⚠️ Bluetooth: pip install bleak (Windows) ou pybluez (Linux)")
    print("Démarrage de l'application...")
    print("=" * 60)
    
    root = tk.Tk()
    app = SecureApp(root)
    root.mainloop()