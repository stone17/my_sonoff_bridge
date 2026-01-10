import asyncio
import json
import base64
import hashlib
import os
import logging
import yaml
import time
import socket
from typing import Optional, Dict
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from zeroconf import ServiceBrowser, Zeroconf, InterfaceChoice
from Crypto.Cipher import AES
from Crypto.Hash import MD5
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes
import paho.mqtt.client as mqtt_client
import aiohttp

# --- CONFIG & LOGGING ---
CONFIG_FILE = os.getenv("CONFIG_PATH", "app/config.yaml")
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger("SonoffBridge")
# Suppress noisy zeroconf logs
logging.getLogger("zeroconf").setLevel(logging.WARNING)

# --- GLOBAL STATE ---
device_states = {}
http_session: Optional[aiohttp.ClientSession] = None

# --- CONFIG MANAGER ---
class ConfigManager:
    def __init__(self, filepath):
        self.filepath = filepath
        self.data = {
            "mqtt_broker": "192.168.0.100",
            "mqtt_port": 1883,
            "mqtt_prefix": "sonoff",
            "discovery_prefix": "homeassistant",
            "devices": {}
        }
        self.load()

    def load(self):
        if os.path.exists(self.filepath):
            try:
                with open(self.filepath, 'r') as f:
                    loaded = yaml.safe_load(f)
                    if loaded: self.data.update(loaded)
            except Exception as e:
                logger.error(f"Config Error: {e}")

    def save(self):
        try:
            with open(self.filepath, 'w') as f:
                yaml.dump(self.data, f)
        except Exception as e:
            logger.error(f"Save Error: {e}")

    def get_devices(self): return self.data.get("devices", {})
    def get_device(self, d_id): return self.data["devices"].get(d_id)
    
    def add_device(self, d_id, info):
        self.data["devices"][d_id] = info
        self.save()
        if mqtt_handler:
            mqtt_handler.publish_discovery(info)

    def delete_device(self, d_id):
        if mqtt_handler:
            dev = self.get_device(d_id)
            if dev: mqtt_handler.remove_discovery(dev)
        if d_id in self.data["devices"]:
            del self.data["devices"][d_id]
            self.save()

    def update_settings(self, broker, port, prefix, disc_prefix):
        self.data["mqtt_broker"] = broker
        self.data["mqtt_port"] = int(port)
        self.data["mqtt_prefix"] = prefix
        self.data["discovery_prefix"] = disc_prefix
        self.save()

cfg = ConfigManager(CONFIG_FILE)

# --- CRYPTO HELPERS ---
def decrypt(payload_b64, iv_b64, api_key):
    try:
        k = hashlib.md5(api_key.encode()).digest()
        iv = base64.b64decode(iv_b64)
        cipher = AES.new(k, AES.MODE_CBC, iv=iv)
        decrypted = unpad(cipher.decrypt(base64.b64decode(payload_b64)), 16)
        return json.loads(decrypted.decode())
    except: return None

def encrypt(payload: dict, devicekey: str):
    devicekey = devicekey.encode("utf-8")
    hash_ = MD5.new()
    hash_.update(devicekey)
    key = hash_.digest()
    iv = get_random_bytes(16)
    plaintext = json.dumps(payload["data"]).encode("utf-8")
    
    block_size = AES.block_size
    padding_len = block_size - len(plaintext) % block_size
    padding = bytes([padding_len]) * padding_len
    padded = plaintext + padding
    
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(padded)
    
    payload["encrypt"] = True
    payload["data"] = base64.b64encode(ciphertext).decode("utf-8")
    payload["iv"] = base64.b64encode(iv).decode("utf-8")
    return payload

# --- COMMS HELPER ---
async def send_sonoff_command(dev, params):
    global http_session
    if http_session is None or http_session.closed:
        http_session = aiohttp.ClientSession()

    seq = str(int(time.time() * 1000))
    payload = {
        "sequence": seq, "deviceid": dev['id'], "selfApikey": "123", "data": params
    }
    
    try:
        encrypted = encrypt(payload, dev['key'])
        url = f"http://{dev['ip']}:8081/zeroconf/switches"
        
        # Connection: close is crucial for some firmware versions to release the socket
        headers = {"Connection": "close"}
        
        async with http_session.post(url, json=encrypted, headers=headers, timeout=5) as r:
            return await r.json()
    except Exception as e:
        logger.error(f"Command Failed {dev['name']}: {e}")
        return None

# --- MQTT HANDLER ---
class MqttHandler:
    def __init__(self):
        self.client = mqtt_client.Client()
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message

    def start(self):
        try:
            broker = cfg.data['mqtt_broker']
            port = cfg.data['mqtt_port']
            logger.info(f"Connecting to MQTT {broker}:{port}")
            self.client.connect(broker, port, 60)
            self.client.loop_start()
        except Exception as e:
            logger.error(f"MQTT Start Error: {e}")

    def stop(self):
        self.client.loop_stop()
        self.client.disconnect()

    def on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            base = cfg.data.get("mqtt_prefix", "sonoff")
            logger.info(f"MQTT Connected. Listening on {base}/+/set")
            client.subscribe(f"{base}/+/set")
            # Publish discovery on connect
            for d_id, dev in cfg.get_devices().items():
                self.publish_discovery(dev)

    def on_message(self, client, userdata, msg):
        try:
            base = cfg.data.get("mqtt_prefix", "sonoff")
            topic_parts = msg.topic.split('/')
            if len(topic_parts) == 3 and topic_parts[0] == base and topic_parts[2] == 'set':
                device_id = topic_parts[1]
                payload = msg.payload.decode().upper()
                state = "on" if payload == "ON" else "off"
                asyncio.run_coroutine_threadsafe(self.execute_command(device_id, state), loop)
        except Exception as e:
            logger.error(f"MQTT Message Error: {e}")

    async def execute_command(self, device_id, state):
        dev = cfg.get_device(device_id)
        if dev:
            params = {"switches": [{"outlet": 0, "switch": state}], "operSide": 1}
            await send_sonoff_command(dev, params)
            # We do NOT poll here. We wait for the device to broadcast the change via mDNS.

    def publish_discovery(self, dev):
        d_id = dev['id']
        name = dev['name']
        base = cfg.data.get("mqtt_prefix", "sonoff")
        disc = cfg.data.get("discovery_prefix", "homeassistant")

        device_info = {"identifiers": [d_id], "name": name, "manufacturer": "Sonoff", "model": "S60TPF"}

        # Switch
        payload_sw = {
            "name": f"{name} Switch", "unique_id": f"sonoff_{d_id}_sw",
            "command_topic": f"{base}/{d_id}/set", "state_topic": f"{base}/{d_id}/state",
            "value_template": "{{ value_json.switch }}", "device": device_info
        }
        self.client.publish(f"{disc}/switch/sonoff_{d_id}/config", json.dumps(payload_sw), retain=True)

        # Power
        payload_p = {
            "name": f"{name} Power", "unique_id": f"sonoff_{d_id}_p",
            "state_topic": f"{base}/{d_id}/state", "unit_of_measurement": "W",
            "device_class": "power", "value_template": "{{ value_json.power }}", "device": device_info
        }
        self.client.publish(f"{disc}/sensor/sonoff_{d_id}_p/config", json.dumps(payload_p), retain=True)

        # Voltage
        payload_v = {
            "name": f"{name} Voltage", "unique_id": f"sonoff_{d_id}_v",
            "state_topic": f"{base}/{d_id}/state", "unit_of_measurement": "V",
            "device_class": "voltage", "value_template": "{{ value_json.voltage }}", "device": device_info
        }
        self.client.publish(f"{disc}/sensor/sonoff_{d_id}_v/config", json.dumps(payload_v), retain=True)

    def remove_discovery(self, dev, forced_prefix=None):
        d_id = dev['id']
        disc = forced_prefix if forced_prefix else cfg.data.get("discovery_prefix", "homeassistant")
        self.client.publish(f"{disc}/switch/sonoff_{d_id}/config", "", retain=True)
        self.client.publish(f"{disc}/sensor/sonoff_{d_id}_p/config", "", retain=True)
        self.client.publish(f"{disc}/sensor/sonoff_{d_id}_v/config", "", retain=True)

    def publish_state(self, dev, data):
        base = cfg.data.get("mqtt_prefix", "sonoff")
        payload = {}
        if 'switches' in data: payload['switch'] = data['switches'][0]['switch'].upper()
        if 'power' in data: payload['power'] = float(data['power']) / 100.0
        if 'voltage' in data: payload['voltage'] = float(data['voltage']) / 100.0
        
        if payload:
            self.client.publish(f"{base}/{dev['id']}/state", json.dumps(payload))
            logger.info(f"State Update {dev['name']}: {payload}")

mqtt_handler = MqttHandler()

# --- DATA PROCESSING ---
def process_data(dev, data):
    # Update local state
    if dev['id'] not in device_states: device_states[dev['id']] = {}
    device_states[dev['id']].update(data)
    
    # Push to MQTT
    mqtt_handler.publish_state(dev, data)

# --- ZEROCONF LISTENER ---
class SonoffListener:
    def remove_service(self, *args): pass
    def add_service(self, zc, type, name): self.handle(zc, type, name)
    def update_service(self, zc, type, name): self.handle(zc, type, name)
    def handle(self, zc, type, name):
        for d_id, dev in cfg.get_devices().items():
            if d_id in name:
                info = zc.get_service_info(type, name)
                if info and info.properties:
                    props = {k.decode('utf-8', 'ignore'): v.decode('utf-8', 'ignore') for k, v in info.properties.items()}
                    raw_data = "".join([props.get(f"data{i}", "") for i in range(1, 5)])
                    if raw_data and 'iv' in props:
                        data = decrypt(raw_data, props['iv'], dev['key'])
                        if data: process_data(dev, data)

# --- LIFECYCLE ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    global loop, http_session
    loop = asyncio.get_running_loop()
    
    # 1. Start HTTP Session (Used only for Control actions)
    http_session = aiohttp.ClientSession()
    
    # 2. Start MQTT
    mqtt_handler.start()
    
    # 3. Start Listener (The only source of data now)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        host_ip = s.getsockname()[0]
        s.close()
        zc = Zeroconf(interfaces=[host_ip])
        logger.info(f"Listener bound to {host_ip}")
    except:
        zc = Zeroconf(interfaces=InterfaceChoice.Default)
    
    browser = ServiceBrowser(zc, "_ewelink._tcp.local.", SonoffListener())
    
    yield
    
    # Shutdown
    mqtt_handler.stop()
    zc.close()
    if http_session:
        await http_session.close()

app = FastAPI(lifespan=lifespan)
templates = Jinja2Templates(directory="app/templates")

# --- ROUTES ---
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {
        "request": request, "devices": cfg.get_devices(), "settings": cfg.data
    })

@app.get("/status/{device_id}")
async def get_status(device_id: str):
    return JSONResponse(content=device_states.get(device_id, {}))

@app.post("/settings")
async def save_settings(
    mqtt_broker: str = Form(...), mqtt_port: int = Form(...),
    mqtt_prefix: str = Form(...), discovery_prefix: str = Form(...)
):
    old_disc_prefix = cfg.data.get("discovery_prefix", "homeassistant")
    devices = cfg.get_devices()
    for d_id, dev in devices.items():
        mqtt_handler.remove_discovery(dev, forced_prefix=old_disc_prefix)

    # Note: Poll interval argument removed
    cfg.update_settings(mqtt_broker, mqtt_port, mqtt_prefix, discovery_prefix)
    
    mqtt_handler.stop()
    mqtt_handler.start()
    return RedirectResponse(url="/", status_code=303)

@app.post("/add")
async def add_device(name: str = Form(...), ip: str = Form(...), device_id: str = Form(...), key: str = Form(...)):
    cfg.add_device(device_id, {"name": name, "ip": ip, "id": device_id, "key": key})
    return RedirectResponse(url="/", status_code=303)

@app.post("/delete/{device_id}")
async def delete_device(device_id: str):
    cfg.delete_device(device_id)
    return RedirectResponse(url="/", status_code=303)

@app.post("/control/{device_id}/{state}")
async def control(device_id: str, state: str):
    dev = cfg.get_device(device_id)
    if not dev: return {"error": "Unknown device"}
    params = {"switches": [{"outlet": 0, "switch": state}], "operSide": 1}
    # Send command only, don't poll
    res = await send_sonoff_command(dev, params)
    return res or {"error": "Failed"}