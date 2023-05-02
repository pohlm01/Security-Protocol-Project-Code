package nl.ru.sec_protocol.group5;

import javacard.framework.*;
import javacard.security.*;

public class PosCard extends Applet implements ISO7816 {
    private final static short EC_KEY_LENGTH = KeyBuilder.LENGTH_EC_F2M_193;

    public final static byte RELOAD = 0;
    public final static byte RELOAD_CONFIRM_PENDING = 1;
    public final static byte POS = 3;
    public final static byte FINISHED = 2;


    private short balance; //FIXME Currently limited to 655,36 EUR
    private javacard.security.RSAPrivateKey priv_key_card;

    private javacard.security.RSAPublicKey pub_key_card;

    private javacard.security.RSAPublicKey pub_key_backend;

    private byte[] signature;

    // 4 bytes
    private byte[] card_id;

    private byte[] expiration_date; // [day, month, year(three last digits, using 2000 as base year)]

    private boolean blocked;

    private boolean initialized;

    private byte state;

    PosCard() {
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
//                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                initialize(apdu);
                break;
            case (byte) 0x04:
//                ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
                buy(apdu);
                break;
            case (byte) 0x06:
//                ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
                reload(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void initialize(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
//        // Step 4
//        pub_key_backend = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_F2M_PUBLIC, EC_KEY_LENGTH, false);
//        // We use OFFSET_CDATA + 1 as start because the first byte is for the sign only (and therefore 0x00).
//        // TODO make sure the buffer contains data in the ANSI X9.62 format and make sure the length is correct
//        pub_key_backend.setW(buffer, (short) (OFFSET_CDATA + 1), (short) (EC_KEY_LENGTH / 8));
//
//        Util.arrayCopy(buffer, (short) (OFFSET_CDATA + 1 + (EC_KEY_LENGTH / 8)), card_id, (short) 0, (short) 4);
//
//        Util.arrayCopy(buffer, (short) (OFFSET_CDATA + 1 + (EC_KEY_LENGTH / 8) + 4), card_id, (short) 0, (short) 3);
//

        // Step 5
//        KeyPair keyPair = new KeyPair(KeyPair.ALG_EC_F2M, EC_KEY_LENGTH);
        KeyPair keyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_2048);
        keyPair.genKeyPair();
        priv_key_card = (RSAPrivateKey) keyPair.getPrivate();
        pub_key_card = (RSAPublicKey) keyPair.getPublic();
//
//        balance = 0;
//
//        // Step 6
//        short le = apdu.setOutgoing();
//        if (le < EC_KEY_LENGTH) {
//            ISOException.throwIt((short) (SW_WRONG_LENGTH | EC_KEY_LENGTH));
//        }

//        short len_return_apdu = pub_key_card.getW(buffer, (short) 0);
//        apdu.setOutgoingLength(len_return_apdu);
//        apdu.sendBytes((short) 0, (short) len_return_apdu);
//        byte[] testArray = new byte[]{1,2,3};
        pub_key_card.getModulus(buffer, (short) 0);
//        apdu.setOutgoing();
//        apdu.sendBytes((short) 0, (short) 3);
        apdu.setOutgoingAndSend((short) 0, (short) (KeyBuilder.LENGTH_RSA_2048/8));
    }

    private void buy(APDU apdu) {
        //FIXME
    }

    private void reload(APDU apdu) {
        //FIXME
    }
}
