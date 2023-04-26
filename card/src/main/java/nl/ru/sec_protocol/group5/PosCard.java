package nl.ru.sec_protocol.group5;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

public class PosCard extends Applet implements ISO7816 {
    public static byte RELOAD = 0;
    public static byte RELOAD_CONFIRM_PENDING = 1;
    public static byte POS = 3;
    public static byte FINISHED = 2;



    private short balance; //FIXME Currently limited to 655,36 EUR
    private byte[] priv_key;

    private byte[] pub_key_card;

    private byte[] pub_key_backend;

    private byte[] signature;

    private byte[] card_id;

    private byte[] expiration_date; // [day, month, year(two last digits)]

    private boolean blocked;

    private boolean initialized;

    private byte[] state;

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
        balance = 0;
    }

    private void buy(byte[] buffer) {
        balance -= 10; //FIXME
    }

    private void reload(byte[] buffer) {
        balance += 10; //FIXME
    }
}
