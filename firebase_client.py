import os
import threading
from datetime import datetime
from config import Config

# Eager or lazy initialization of firebase
_firebase_ready = False
_firebase_lock = threading.Lock()

try:
    import firebase_admin
    from firebase_admin import credentials, db
    _FIREBASE_AVAILABLE = True
except ImportError:
    _FIREBASE_AVAILABLE = False


def _init_firebase() -> bool:
    global _firebase_ready
    if not _FIREBASE_AVAILABLE:
        return False
    
    with _firebase_lock:
        if _firebase_ready:
            return True
        if firebase_admin._apps:
            _firebase_ready = True
            return True
            
        cert_path = getattr(Config, "FIREBASE_CERT_PATH", "firebase-key.json")
        db_url = getattr(Config, "FIREBASE_DB_URL", "https://your-firebase-db.firebaseio.com/")
        
        if not os.path.exists(cert_path):
            print(f"[Firebase] Private key file not found at {cert_path}. Cloud syncing features are disabled.")
            return False
            
        try:
            cred = credentials.Certificate(cert_path)
            firebase_admin.initialize_app(cred, {
                'databaseURL': db_url
            })
            _firebase_ready = True
            return True
        except Exception as e:
            print(f"[Firebase] Initialization failed: {e}")
            return False


def push_block(ip, reason):
    if not _init_firebase():
        return
    try:
        ref = db.reference("blocked_ips")
        safe_ip = ip.replace(".", "_")   # ✅ FIX
        ref.child(safe_ip).set({
            "ip": ip,                   # store real IP
            "reason": reason,
            "timestamp": str(datetime.now())
        })
    except Exception as e:
        print(f"[Firebase] Error pushing blocked IP: {e}")


def get_blocked_ips():
    if not _init_firebase():
        return {}
    try:
        ref = db.reference("blocked_ips")
        data = ref.get()
        return data if isinstance(data, dict) else {}
    except Exception as e:
        print(f"[Firebase] Error fetching blocked IPs: {e}")
        return {}


def remove_block(ip):
    if not _init_firebase():
        return
    try:
        ref = db.reference("blocked_ips")
        safe_ip = ip.replace(".", "_")
        ref.child(safe_ip).delete()
    except Exception as e:
        print(f"[Firebase] Error removing blocked IP: {e}")