import zeroconf
import time

class MyListener:
    def add_service(self, zc, type_, name):
        info = zc.get_service_info(type_, name)
        if info:
            print(f"Device Found: {name}")
            print(f"  IP: {info.parsed_addresses()[0]}")
            # The ID is in the name (e.g., ewelink_1000abcdef._treck._tcp.local.)
            print(f"  Properties: {info.properties}")

zc = zeroconf.Zeroconf()
listener = MyListener()
browser = zeroconf.ServiceBrowser(zc, "_ewelink._tcp.local.", listener)

print("Searching for Sonoff devices on LAN (ensure LAN Mode is ON in app)...")
time.sleep(10)
zc.close()
