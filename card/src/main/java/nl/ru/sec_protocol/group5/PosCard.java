package nl.ru.sec_protocol.group5;

import javacard.framework.*;
import javacard.security.*;

public class PosCard extends Applet implements ISO7816 {
    private final static short EC_KEY_LENGTH = KeyBuilder.LENGTH_EC_F2M_193;

    public final static byte INIT = 0;
    public final static byte RELOAD = 1;
    public final static byte RELOAD_CONFIRM_PENDING = 2;
    public final static byte POS = 3;
    public final static byte FINISHED = 4;


    private short balance; //FIXME Currently limited to 655,36 EUR
    private javacard.security.RSAPrivateKey priv_key_card;

    private javacard.security.RSAPublicKey pub_key_card;

    private javacard.security.RSAPublicKey pub_key_backend;

    private final byte[] signature;

    // 4 bytes
    private final byte[] card_id;

    private final byte[] expiration_date; // [day, month, year(three last digits, using 2000 as base year)]

    private boolean blocked;

    private boolean initialized;

    private byte state;

    PosCard() {
        card_id = new byte[4];
        expiration_date = new byte[3];
        signature = new byte[2048 / 8];
        register();
    }

    public static void install(byte[] buffer, short offset, byte length) throws SystemException {
        new PosCard();
    }

    public void process(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        byte instruction = buffer[OFFSET_INS];

        if (selectingApplet()) {
            return;
        }

        switch (instruction) {
            case (byte) 0x02:
                generateKeys(apdu);
                break;
            case (byte) 0x04:
                setCardIdAndExpirationDate(apdu);
                break;
            case (byte) 0x06:
                signCard(apdu);
                break;
            case (byte) 0x08:
                buy(apdu);
                break;
            case (byte) 0x0A:
                reload(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void signCard(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        signature[0] = buffer[OFFSET_P1];
        Util.arrayCopy(buffer, OFFSET_CDATA, signature, (short) 1, (short) (255));
        initialized = true;
    }

    private void setCardIdAndExpirationDate(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        Util.arrayCopy(buffer, OFFSET_CDATA, card_id, (short) 0, (short) 4);
        Util.arrayCopy(buffer, (short) (OFFSET_CDATA + 4), expiration_date, (short) 0, (short) 3);
    }

    private void generateKeys(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        // Step 4
        pub_key_backend = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_2048, false);
        pub_key_backend.setModulus(buffer, OFFSET_CDATA, (short) (KeyBuilder.LENGTH_RSA_2048 / 8));

        // Step 5
        KeyPair keyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_2048);
        keyPair.genKeyPair();
        priv_key_card = (RSAPrivateKey) keyPair.getPrivate();
        pub_key_card = (RSAPublicKey) keyPair.getPublic();

        balance = 0;

        // Step 6
        pub_key_card.getModulus(buffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, (short) (KeyBuilder.LENGTH_RSA_2048 / 8));
    }

    private void buy(APDU apdu) {
        //FIXME
    }

    private void reload(APDU apdu) {
        //FIXME
    }
}
