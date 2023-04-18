
Build tool for smart card interaction
```shell
cd GlobalPlatformPro/
./mvnw package
```

Build applet
```shell
mvn compile
```

Convert to CAP file
```shell
./sdk/bin/converter -classdir ./target/classes -out CAP -v -exportpath ./sdk/api_export_files nl.ru.sec_protocol.group5 0x2D:0x54:0x45:0x53:0x54 1.0
```

Upload to smart card
```shell
java -jar ./GlobalPlatformPro/tool/target/gp.jar --load ./target/classes/nl/ru/sec_protocol/group5/javacard/group5.cap
```

Delete from smart card
```shell
java -jar ./GlobalPlatformPro/tool/target/gp.jar --delete 2D54455354
```