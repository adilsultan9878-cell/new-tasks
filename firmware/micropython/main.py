# SENTINEL X sensor hub for ESP32 / ESP8266 running MicroPython.
#
# Enrolls once with a one-time token, then every INTERVAL_SECONDS posts its sensor readings and
# applies the LED / buzzer state the server returns. The server sends state, never commands; this
# program runs nothing it receives.
import json
import time

import machine
import network
import urequests

import config

VERSION = "0.3.0"
TOKEN_FILE = "sentinel_token.json"
API = config.SERVER_URL.rstrip("/") + "/api/v1/agent"


class Revoked(Exception):
    pass


def connect_wifi(timeout_s=20):
    sta = network.WLAN(network.STA_IF)
    sta.active(True)
    if not sta.isconnected():
        sta.connect(config.WIFI_SSID, config.WIFI_PASSWORD)
        start = time.time()
        while not sta.isconnected():
            if time.time() - start > timeout_s:
                raise OSError("Wi-Fi connection timed out")
            time.sleep(0.5)
    return sta.ifconfig()[0]


def post(path, body, token=None):
    headers = {"Content-Type": "application/json", "User-Agent": "sentinel-x-esp32/" + VERSION}
    if token:
        headers["Authorization"] = "Bearer " + token
    response = urequests.post(API + path, data=json.dumps(body), headers=headers)
    try:
        status = response.status_code
        data = response.json() if response.text else {}
    finally:
        response.close()
    return status, data


def load_token():
    try:
        with open(TOKEN_FILE) as f:
            return json.load(f)["device_token"]
    except (OSError, ValueError, KeyError):
        return None


def save_token(token):
    with open(TOKEN_FILE, "w") as f:
        json.dump({"device_token": token}, f)


def forget_token():
    try:
        import os

        os.remove(TOKEN_FILE)
    except OSError:
        pass


def enroll(ip):
    facts = {"hostname": config.HUB_NAME, "name": config.HUB_NAME, "os": "MicroPython", "agent_version": VERSION,
             "ip_address": ip}
    status, data = post("/enroll", {"enrollment_token": config.ENROLLMENT_TOKEN, "device": facts})
    if status != 201:
        raise RuntimeError("enrollment failed (%s): %s" % (status, data.get("error", {}).get("message", data)))
    save_token(data["device_token"])
    return data["device_token"]


class Sensors:
    def __init__(self, specs):
        self.items = []
        for spec in specs:
            kind = spec["kind"]
            if kind == "dht22":
                import dht

                device = dht.DHT22(machine.Pin(spec["pin"]))
            elif kind == "analog":
                device = machine.ADC(machine.Pin(spec["pin"]))
                if hasattr(device, "atten"):
                    device.atten(machine.ADC.ATTN_11DB)
            else:
                device = machine.Pin(spec["pin"], machine.Pin.IN, machine.Pin.PULL_UP)
            self.items.append((spec, device))

    def read(self):
        readings = []
        for spec, device in self.items:
            try:
                if spec["kind"] == "dht22":
                    device.measure()
                    readings.append({"sensor_key": spec["key"] + "_temp", "sensor_type": "temperature",
                                     "unit": "C", "value": device.temperature()})
                    readings.append({"sensor_key": spec["key"] + "_humidity", "sensor_type": "humidity",
                                     "unit": "%", "value": device.humidity()})
                elif spec["kind"] == "analog":
                    readings.append({"sensor_key": spec["key"], "sensor_type": spec.get("type", "analog"),
                                     "unit": spec.get("unit"), "value": device.read() * spec.get("scale", 1)})
                else:
                    value = device.value()
                    if spec.get("invert"):
                        value = 1 - value
                    readings.append({"sensor_key": spec["key"], "sensor_type": spec.get("type", "digital"),
                                     "unit": spec.get("unit"), "value": value})
            except OSError as exc:  # a disconnected sensor must not stop the others
                print("sensor", spec["key"], "failed:", exc)
        return readings


class Actuators:
    def __init__(self, led_pin, buzzer_pin):
        self.pins = {}
        if led_pin is not None:
            self.pins["led"] = machine.Pin(led_pin, machine.Pin.OUT)
        if buzzer_pin is not None:
            self.pins["buzzer"] = machine.Pin(buzzer_pin, machine.Pin.OUT)
        self.apply({})

    def apply(self, state):
        # Only the two known outputs, only on/off: anything else in the response is ignored.
        for name, pin in self.pins.items():
            pin.value(1 if state.get(name) is True else 0)


def cycle(token, sensors, actuators):
    readings = sensors.read()
    if not readings:
        return None
    status, data = post("/sensors/readings", {"readings": readings}, token)
    if status == 401:
        raise Revoked()
    if status == 200:
        actuators.apply(data.get("actuators") or {})
    return status


def main():
    actuators = Actuators(config.LED_PIN, config.BUZZER_PIN)
    sensors = Sensors(config.SENSORS)
    ip = connect_wifi()
    token = load_token() or enroll(ip)
    print("SENTINEL X hub", config.HUB_NAME, "reporting every", config.INTERVAL_SECONDS, "s")
    while True:
        try:
            cycle(token, sensors, actuators)
        except Revoked:
            print("credential revoked: create a new enrollment token to re-enroll")
            forget_token()
            actuators.apply({})
            return
        except Exception as exc:  # network hiccups: keep going
            print("report failed:", exc)
            try:
                connect_wifi()
            except OSError:
                pass
        time.sleep(config.INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
