import time
import json
import base64
import hashlib
import yaml
import sys
from zeroconf import ServiceBrowser, Zeroconf, InterfaceChoice
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# --- CONFIGURATION ---
CONFIG_FILE = "sonoff_config.yaml"

def load_config():
    try:
        with open(CONFIG_FILE, "r") as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"Error loading {CONFIG_FILE}: {e}")
        sys.exit(1)

# Load devices from config to get keys
config = load_config()
devices_map = {d['id']: d['key'] for d in config['devices'].values()}

print(f"Loaded keys for {len(devices_map)} devices: {list(devices_map.keys())}")

# --- CRYPTO LOGIC ---
def decrypt(payload_b64, iv_b64, api_key):
    try:
        # Generate AES Key from API Key
        k = hashlib.md5(api_key.encode()).digest()
        iv = base64.b64decode(iv_b64)
        cipher = AES.new(k, AES.MODE_CBC, iv=iv)
        decrypted = cipher.decrypt(base64.b64decode(payload_b64))
        
        # Remove padding
        try:
            decrypted = unpad(decrypted, 16)
        except:
            # Fallback for some firmware versions that might have non-standard padding
            pass
            
        return json.loads(decrypted.decode())
    except Exception as e:
        return None

# --- ZEROCONF LISTENER ---
class SonoffListener:
    def remove_service(self, zc, type, name):
        pass

    def add_service(self, zc, type, name):
        self.handle(zc, type, name)

    def update_service(self, zc, type, name):
        self.handle(zc, type, name)

    def handle(self, zc, type, name):
        # Check if we have a key for this device
        matched_id = None
        matched_key = None
        
        for dev_id, key in devices_map.items():
            if dev_id in name:
                matched_id = dev_id
                matched_key = key
                break
        
        if not matched_key:
            # Optional: Print unknown devices if you want to discover new IDs
            # print(f"Ignored unknown device: {name}")
            return

        info = zc.get_service_info(type, name)
        if not info or not info.properties:
            return

        try:
            # Decode properties from bytes to strings
            props = {k.decode('utf-8', 'ignore'): v.decode('utf-8', 'ignore') 
                     for k, v in info.properties.items()}
            
            # Reassemble chunked data (data1, data2, etc.)
            raw_data = "".join([props.get(f"data{i}", "") for i in range(1, 5)])
            
            if raw_data and 'iv' in props:
                # Attempt Decryption
                data = decrypt(raw_data, props['iv'], matched_key)
                
                if data:
                    timestamp = time.strftime("%H:%M:%S")
                    print(f"\n[{timestamp}] Message from {matched_id}")
                    print(json.dumps(data, indent=2))
                else:
                    print(f"\n[!] Failed to decrypt message from {matched_id}. Check API Key.")

        except Exception as e:
            print(f"Error parsing packet: {e}")

# --- MAIN LOOP ---
if __name__ == "__main__":
    print("--- Sonoff Network Listener Started ---")
    print("Listening for encrypted broadcasts...")
    
    # InterfaceChoice.All ensures we listen on all network adapters (good for finding devices)
    zc = Zeroconf(interfaces=InterfaceChoice.All)
    browser = ServiceBrowser(zc, "_ewelink._tcp.local.", SonoffListener())

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping listener...")
    finally:
        zc.close()