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
logging.getLogger("zeroconf").setLevel(logging.WARNING)

# --- GLOBAL STATE ---
device_states = {}

# --- CONFIG MANAGER ---
class ConfigManager:
    def __init__(self, filepath):
        self.filepath = filepath
        self.data = {
            "mqtt_broker": "192.168.0.100",
            "mqtt_port": 1883,
            "mqtt_prefix": "sonoff",           # Default Base Topic
            "discovery_prefix": "homeassistant", # Default Discovery Prefix
            "poll_interval": 10,
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
        if d_id in self.data["devices"]:
            del self.data["devices"][d_id]
            self.save()

    def update_settings(self, broker, port, poll, prefix, disc_prefix):
        self.data["mqtt_broker"] = broker
        self.data["mqtt_port"] = int(port)
        self.data["poll_interval"] = int(poll)
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
async def send_sonoff_request(dev, path, params):
    seq = str(int(time.time() * 1000))
    payload = {
        "sequence": seq, "deviceid": dev['id'], "selfApikey": "123", "data": params
    }
    try:
        encrypted = encrypt(payload, dev['key'])
        url = f"http://{dev['ip']}:8081/zeroconf/{path}"
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=encrypted, headers={"Connection": "close"}, timeout=5) as r:
                return await r.json()
    except Exception as e:
        logger.error(f"Req Error {dev['name']}: {e}")
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
            
            # Subscribe to command topics: prefix/{device_id}/set
            client.subscribe(f"{base}/+/set")
            
            # Re-publish discovery on connect to ensure Domoticz sees them
            for d_id, dev in cfg.get_devices().items():
                self.publish_discovery(dev)

    def on_message(self, client, userdata, msg):
        try:
            base = cfg.data.get("mqtt_prefix", "sonoff")
            topic_parts = msg.topic.split('/')
            
            # Match structure: prefix/device_id/set
            if len(topic_parts) == 3 and topic_parts[0] == base and topic_parts[2] == 'set':
                device_id = topic_parts[1]
                payload = msg.payload.decode().upper()
                
                logger.info(f"Command for {device_id}: {payload}")
                state = "on" if payload == "ON" else "off"
                asyncio.run_coroutine_threadsafe(self.execute_command(device_id, state), loop)
        except Exception as e:
            logger.error(f"MQTT Message Error: {e}")

    async def execute_command(self, device_id, state):
        dev = cfg.get_device(device_id)
        if dev:
            params = {"switches": [{"outlet": 0, "switch": state}], "operSide": 1}
            await send_sonoff_request(dev, "switches", params)
            await asyncio.sleep(0.5)
            await poll_device(dev)

    def publish_discovery(self, dev):
        d_id = dev['id']
        name = dev['name']
        base = cfg.data.get("mqtt_prefix", "sonoff")
        disc = cfg.data.get("discovery_prefix", "homeassistant")

        device_info = {
            "identifiers": [d_id],
            "name": name,
            "manufacturer": "Sonoff",
            "model": "DIY Bridge"
        }

        # 1. Switch Config
        # Topic: <disc>/switch/sonoff_<id>/config
        payload_sw = {
            "name": f"{name} Switch",
            "unique_id": f"sonoff_{d_id}_sw",
            "command_topic": f"{base}/{d_id}/set",
            "state_topic": f"{base}/{d_id}/state",
            "value_template": "{{ value_json.switch }}",
            "device": device_info
        }
        self.client.publish(f"{disc}/switch/sonoff_{d_id}/config", json.dumps(payload_sw), retain=True)

        # 2. Power Config
        payload_p = {
            "name": f"{name} Power",
            "unique_id": f"sonoff_{d_id}_p",
            "state_topic": f"{base}/{d_id}/state",
            "unit_of_measurement": "W",
            "device_class": "power",
            "value_template": "{{ value_json.power }}",
            "device": device_info
        }
        self.client.publish(f"{disc}/sensor/sonoff_{d_id}_p/config", json.dumps(payload_p), retain=True)

        # 3. Voltage Config
        payload_v = {
            "name": f"{name} Voltage",
            "unique_id": f"sonoff_{d_id}_v",
            "state_topic": f"{base}/{d_id}/state",
            "unit_of_measurement": "V",
            "device_class": "voltage",
            "value_template": "{{ value_json.voltage }}",
            "device": device_info
        }
        self.client.publish(f"{disc}/sensor/sonoff_{d_id}_v/config", json.dumps(payload_v), retain=True)
        
        logger.info(f"Published Discovery for {name} to {disc}/...")

    def publish_state(self, dev, data):
        base = cfg.data.get("mqtt_prefix", "sonoff")
        payload = {}
        
        if 'switches' in data:
            payload['switch'] = data['switches'][0]['switch'].upper()
        if 'power' in data:
             payload['power'] = float(data['power']) / 100.0
        if 'voltage' in data:
            payload['voltage'] = float(data['voltage']) / 100.0
            
        if payload:
            self.client.publish(f"{base}/{dev['id']}/state", json.dumps(payload))


mqtt_handler = MqttHandler()

# --- PROCESSING ---
async def poll_device(dev):
    data = await send_sonoff_request(dev, "info", {})
    if data: process_data(dev, data)

def process_data(dev, data):
    if dev['id'] not in device_states: device_states[dev['id']] = {}
    device_states[dev['id']].update(data)
    mqtt_handler.publish_state(dev, data)

async def polling_task():
    while True:
        try:
            interval = cfg.data.get("poll_interval", 10)
            for d_id, dev in cfg.get_devices().items():
                await poll_device(dev)
        except Exception: pass
        await asyncio.sleep(interval)

# --- ZEROCONF ---
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
                        if data:
                            process_data(dev, data)

# --- LIFECYCLE ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    global loop
    loop = asyncio.get_running_loop()
    mqtt_handler.start()
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        host_ip = s.getsockname()[0]
        s.close()
        zc = Zeroconf(interfaces=[host_ip])
    except:
        zc = Zeroconf(interfaces=InterfaceChoice.Default)
    
    browser = ServiceBrowser(zc, "_ewelink._tcp.local.", SonoffListener())
    ptask = asyncio.create_task(polling_task())
    
    yield
    
    ptask.cancel()
    mqtt_handler.stop()
    zc.close()

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
    mqtt_broker: str = Form(...), 
    mqtt_port: int = Form(...), 
    poll_interval: int = Form(...),
    mqtt_prefix: str = Form(...),
    discovery_prefix: str = Form(...)
):
    cfg.update_settings(mqtt_broker, mqtt_port, poll_interval, mqtt_prefix, discovery_prefix)
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
    res = await send_sonoff_request(dev, "switches", params)
    await poll_device(dev)
    return res or {"error": "Failed"}