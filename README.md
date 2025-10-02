# Cyber360SparkChallenge-IoT


### IoT Device Hardening – Secure a vulnerable smart home system
ASU’s Smart Dorm testbed has been experiencing strange activity from connected devices. Your task: identify insecure configurations, simulate a breach, and propose a hardened configuration.
Deliverable format:
- URL to Github repo == Hardened code (commented out) for microcontroller
- PDF == Report including executive summary, technical findings, and recommended/implemented mitigations
- URL == Plus: presentation deck

Track tools:
    • IoT device (1 per team)
    • Use either Arduino IDE or compiler of choice
    • Bring own device Computer/laptop
    • Working Template code (ready for hardening)


Install `ESP32` Boards from Board Manager.

If using Arduino IDE 2.x:
Tools -> Board -> Board Manager -> SEARCH ESP32

If using Arduino IDE < 2.0:
https://randomnerdtutorials.com/installing-the-esp32-board-in-arduino-ide-windows-instructions/


Required Libraries:
These can be installed from Tools->Managed Libraries

[arduino-mqtt - V2.5.2](https://github.com/256dpi/arduino-mqtt)


NOTE: You will be given a host number to replace in code for XXX upon hardware checkout. Good luck!
