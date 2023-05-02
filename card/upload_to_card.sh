#!/bin/bash

./sdk/bin/converter -classdir ./target/classes -out CAP -v -applet 0x2D:0x54:0x45:0x53:0x54:0x70 PosCard -exportpath ./sdk/api_export_files nl.ru.sec_protocol.group5 0x2D:0x54:0x45:0x53:0x54 1.0

java -jar ./GlobalPlatformPro/tool/target/gp.jar --install ./target/classes/nl/ru/sec_protocol/group5/javacard/group5.cap