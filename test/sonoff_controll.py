import asyncio
import base64
import json
import time
import sys
import yaml
import aiohttp
import errno
from Crypto.Cipher import AES
from Crypto.Hash import MD5
from Crypto.Random import get_random_bytes

# --- CONFIGURATION ---
try:
    with open("/home/htpc/sonoff_config.yaml", "r") as f:
        config = yaml.safe_load(f)
    dev = config['devices']['office_plug']
    HOST = dev['ip']
    DEVICE_ID = dev['id']
    DEVICE_KEY = dev['key']
except Exception as e:
    print(f"Config Error: {e}")
    sys.exit(1)

# --- CRYPTO ---
def pad(data_to_pad: bytes, block_size: int):
    padding_len = block_size - len(data_to_pad) % block_size
    padding = bytes([padding_len]) * padding_len
    return data_to_pad + padding

def encrypt(payload: dict, devicekey: str):
    devicekey = devicekey.encode("utf-8")
    hash_ = MD5.new()
    hash_.update(devicekey)
    key = hash_.digest()
    
    iv = get_random_bytes(16)
    
    # Use standard json.dumps with spaces to match SonoffLAN behavior
    plaintext = json.dumps(payload["data"]).encode("utf-8")
    
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    padded = pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(padded)
    
    payload["encrypt"] = True
    payload["data"] = base64.b64encode(ciphertext).decode("utf-8")
    payload["iv"] = base64.b64encode(iv).decode("utf-8")
    return payload

# --- TRANSPORT ---
async def send_command(target_state, retry_count=5):
    url = f"http://{HOST}:8081/zeroconf/switches"
    seq = str(int(time.time() * 1000))
    
    # PARAMETER FIX: 'operSide': 1 is required for S60TPF / POWR3
    params = {
        "switches": [{"outlet": 0, "switch": target_state}],
        "operSide": 1
    }
    
    payload = {
        "sequence": seq,
        "deviceid": DEVICE_ID,
        "selfApikey": "123",
        "data": params
    }
    
    payload = encrypt(payload, DEVICE_KEY)
    
    async with aiohttp.ClientSession() as session:
        try:
            # Header "Connection: close" is required
            async with session.post(url, json=payload, headers={"Connection": "close"}, timeout=5) as r:
                resp = await r.json()
                if resp.get("error") == 0:
                    print("OK")
                    return True
                else:
                    print(f"Error: {resp}")
                    return False
                    
        except aiohttp.ClientOSError as e:
            if e.errno == errno.ECONNRESET and retry_count > 0:
                await asyncio.sleep(0.1)
                return await send_command(target_state, retry_count - 1)
            print(f"Connection Error: {e}")
            return False
            
        except Exception as e:
            print(f"Fail: {e}")
            return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 sonoff_control_final.py [on|off]")
        sys.exit(1)
    
    action = sys.argv[1].lower()
    if action in ["on", "off"]:
        asyncio.run(send_command(action))
    else:
        print("Invalid command.")