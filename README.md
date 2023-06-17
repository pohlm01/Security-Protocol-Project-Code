# Security Protocol Project

This is the repository of Group 5 of the Security Protocol Project Course at Radboud University in the academic year 2022/23

It contains code for JavaCards to be used in a simple money card use case.
For detailed information about the use case and protocol, see our [documentation](https://github.com/pohlm01/Security-Protocol-Project).


## Setup
After pulling the repository, make sure you have the Git submodules set up as well.
```shell
git submodule init
git submodule update
```

This project contains code for the JavaCard, as well as for the different terminals.
Depending on the IDE you are using, we recommend opening the two folders in different IDE instances, as they use different Java versions.
Each folder contains a `pom.xml` to instruct Maven, how to build the application.

To be able to upload things to the card, make sure, you also build the content of the [GlobalPlatformPro](card/GlobalPlatformPro) submodule first.
For that run
```shell
cd card/GlobalPlatformPro
./mvnw package
```

Also, make sure, your `pcscd` service is running.
For Ubuntu, you can check that with
```shell
systemctl status pcscd
```

If it is not active yet, start it using
```shell
systemctl start pcscd
```

For compiling the cards' code, you need to have a Java SKD that allows to compile to a Java 1.2 target.
Recent versions do not have support for this any longer, but the Java 1.8 SDK should be capable of doing that.

At the same time, you need to have Java 18 (or newer) to compile and run the terminal code.
As mentioned earlier, it can be handy to let an IDE manage the different versions.

Depending on the card-reader used, you may also need to install the corresponding drivers.

## Run the code
After the setup is complete, you should be able to compile and run the code using Maven or your IDE.

To upload code to the card, run the following command in the `./card` directory:
```shell
mvn clean install
```
This cleans the card, compiles the code, and uploads it to the card.
You may also run the steps individually.

## Administrating the Backend
The Backend can be used to generate keys and signatures for the terminals, as well as for creating a Certificate Revocation List (CRL) to block cards.
The terminals necessarily require these files to exist to start up.
The backend public and private key are included in the repository.
For obvious reasons, including the private key is generally a very bad idea, but as this is just for demonstration, it is not a problem.
