# Copy to config.py on the board and fill in. Never commit config.py: it holds your Wi-Fi password.
WIFI_SSID = "your-wifi"
WIFI_PASSWORD = "your-wifi-password"

# The SENTINEL X API (e.g. https://sentinel-x-api.onrender.com). On a LAN you may use http://.
SERVER_URL = "https://your-api.example.com"
# One-time enrollment token from Devices -> Enrollment tokens (device type: sensor hub).
# After the first start the board stores its own device credential and this token is not reused.
ENROLLMENT_TOKEN = "sxe.paste-token-here"
HUB_NAME = "esp32-server-room"

INTERVAL_SECONDS = 30

# Sensors: kind is "dht22" (temperature + humidity), "analog" (e.g. MQ-2 gas, scaled) or
# "digital" (e.g. a door reed switch: 1 = open).
SENSORS = [
    {"key": "room", "kind": "dht22", "pin": 4},
    {"key": "gas", "kind": "analog", "pin": 34, "type": "gas", "unit": "ppm", "scale": 0.25},
    {"key": "rack_door", "kind": "digital", "pin": 27, "type": "door", "unit": "open", "invert": True},
]

# Outputs switched by SENTINEL X (set to None if not wired).
LED_PIN = 2
BUZZER_PIN = 15
