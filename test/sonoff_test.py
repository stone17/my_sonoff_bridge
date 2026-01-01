import time
import json
import base64
import hashlib
import yaml
from zeroconf import ServiceBrowser, Zeroconf, InterfaceChoice
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# --- CONFIG ---
try:
    with open("sonoff_config.yaml", "r") as f:
        config = yaml.safe_load(f)
    dev = config['devices']['office_plug']
    DEVICE_ID = dev['id']
    API_KEY = dev['key']
except Exception as e:
    print(f"Config Error: {e}")
    exit(1)

# --- CRYPTO LOGIC (From local.py) ---
def decrypt(payload_b64, iv_b64):
    try:
        k = hashlib.md5(API_KEY.encode()).digest()
        iv = base64.b64decode(iv_b64)
        cipher = AES.new(k, AES.MODE_CBC, iv=iv)
        decrypted = cipher.decrypt(base64.b64decode(payload_b64))
        # Logic from local.py:Fix Sonoff RF Bridge syntax bug and trailing chars
        decrypted = unpad(decrypted, 16)
        return json.loads(decrypted.decode())
    except Exception as e:
        return None

# --- LISTENER ---
class PhysicsListener:
    def remove_service(self, zc, type, name): pass
    def add_service(self, zc, type, name): self.handle(zc, type, name)
    def update_service(self, zc, type, name): self.handle(zc, type, name)

    def handle(self, zc, type, name):
        if DEVICE_ID in name:
            info = zc.get_service_info(type, name)
            if not info or not info.properties: return
            
            props = {k.decode('utf-8', 'ignore'): v.decode('utf-8', 'ignore') for k, v in info.properties.items()}
            
            # REASSEMBLY LOGIC (From local.py _handler3)
            # Some devices split payload across data1..data4
            raw_data = "".join([props[f"data{i}"] for i in range(1, 5) if f"data{i}" in props])
            
            if raw_data and 'iv' in props:
                print(f"\n[SIGNAL DETECTED] {name}")
                print(f"IV: {props['iv']}")
                print(f"Encrypted Blob Length: {len(raw_data)}")
                
                res = decrypt(raw_data, props['iv'])
                
                if res:
                    print(">>> DECRYPTION SUCCESSFUL <<<")
                    print(json.dumps(res, indent=2))
                    # If this prints, YOUR KEY IS CORRECT.
                    # If this runs but produces garbage/error, YOUR KEY IS WRONG.
                else:
                    print("!!! DECRYPTION FAILED !!!")
                    print("Your API Key is likely incorrect (rotated on last pairing).")

print(f"--- MONITORING {DEVICE_ID} ---")
print("1. Run this script.")
print("2. TOGGLE THE PLUG (Physical Button or App).")
print("3. Watch for output.")

# Listen on ALL interfaces to bypass potential Docker/VPN binding issues
zc = Zeroconf(interfaces=InterfaceChoice.All)
browser = ServiceBrowser(zc, "_ewelink._tcp.local.", PhysicsListener())

try:
    while True:
        time.sleep(0.5)
except KeyboardInterrupt:
    pass
finally:
    zc.close()