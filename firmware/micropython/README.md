# ESP32 sensor hub (MicroPython)

Reports sensors to SENTINEL X and drives an LED and a buzzer from the state the server returns.

1. Flash [MicroPython](https://micropython.org/download/) on the ESP32.
2. In the console: **Devices → Enrollment token** (device type *sensor hub*); copy the token.
3. Copy `config.example.py` to `config.py`, fill in Wi-Fi, server URL, token and your sensors.
4. Upload `config.py` and `main.py` to the board (e.g. `mpremote cp config.py main.py :`) and reset it.

The board enrolls once and stores its own device credential in `sentinel_token.json`; revoke it
from the console at any time. Readings appear under **IoT Security**; set thresholds there and pick
which outputs (LED, buzzer) switch on when a sensor leaves its range.

Wiring used by the example: DHT22 on GPIO 4, MQ-2 analog out on GPIO 34, a door reed switch on
GPIO 27 (to GND), LED on GPIO 2, active buzzer on GPIO 15.

**Security note.** MicroPython's TLS does not verify server certificates, so a board talking to an
internet API over HTTPS can be impersonated on a hostile network. Keep boards on a trusted network,
or publish to a local, password-protected MQTT broker and run `sentinel-agent mqtt-bridge` on a
Raspberry Pi or PC (the bridge verifies certificates). The board never executes anything it receives.
