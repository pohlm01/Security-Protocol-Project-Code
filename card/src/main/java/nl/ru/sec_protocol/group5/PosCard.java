package nl.ru.sec_protocol.group5;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

public class PosCard extends Applet implements ISO7816 {

    public void process(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        byte instruction = buffer[OFFSET_INS];

        switch (instruction) {
            case '0':
                initialize(buffer);
                break;
            case '1':
                buy(buffer);
                break;
            case '2':
                reload(buffer);
                break;
            default:
                ISOException.throwIt(SW_INS_NOT_SUPPORTED);
        }
    }

    private void initialize(byte[] buffer) {

    }

    private void buy(byte[] buffer) {

    }

    private void reload(byte[] buffer) {

    }
}
