package nl.ru.sec_protocol.group5;

import javacard.framework.*;
import javacard.security.*;

public class PosCard extends Applet implements ISO7816 {
    public final static byte[] PUBLIC_EXPONENT = new byte[]{0x01, 0x00, 0x01};
    public final static byte[] ZERO = new byte[]{0x00, 0x00, 0x00, 0x00};

    public final static short ID_SIZE = 4;
    public final static short COUNTER_SIZE = 4;
    public final static short DATE_SIZE = 3;
    public final static short KEY_SIZE = 256;
    public final static short SIGNATURE_SIZE = KEY_SIZE;

    public final static short OFFSET_PUB_KEY = ID_SIZE + DATE_SIZE;
    public final static short OFFSET_DOMAIN_SEPARATOR = OFFSET_PUB_KEY + KEY_SIZE;

    private final static byte DOMAIN_SEPARATOR_POS = 0x02;
    private final static byte DOMAIN_SEPARATOR_RELOAD = 0x03;

    public final static byte INIT = 0;
    public final static byte RELOAD_META_EXCHANGED = 1;
    public final static byte RELOAD_PUB_KEYS_EXCHANGED = 2;
    public final static byte RELOAD_TERMINAL_AUTHENTICATED = 3;
    public final static byte RELOAD_AMOUNT_RECEIVED = 4;
    public final static byte RELOAD_AMOUNT_AUTHENTICATED = 5;
    public final static byte FINISHED = 6;


    private short balance; //FIXME Currently limited to 655,36 EUR
    private javacard.security.RSAPrivateKey priv_key_card;

    private javacard.security.RSAPublicKey pub_key_card;

    private javacard.security.RSAPublicKey pub_key_backend;

    private final Object[] pub_key_terminal;

    private final byte[] signature;

    // 4 bytes
    private final byte[] card_id;

    private short counter;

    private final byte[] expiration_date; // [day, month, year(three last digits, using 2000 as base year)]

    private boolean blocked;

    private boolean initialized;

    private final byte[] state;

    /**
     * terminalId || expirationDate || terminalPubKey || domainSeparator
     */
    private final byte[] transientData;

    private final byte[] currentDate;

    private final byte[] terminalCounter;
    private final byte[] terminalSignature;

    PosCard() {
        card_id = new byte[4];
        expiration_date = new byte[3];
        signature = new byte[2048 / 8];
        transientData = JCSystem.makeTransientByteArray((short) (ID_SIZE + DATE_SIZE + 1 + KEY_SIZE), JCSystem.CLEAR_ON_RESET);
        terminalSignature = JCSystem.makeTransientByteArray(SIGNATURE_SIZE, JCSystem.CLEAR_ON_RESET);
        currentDate = JCSystem.makeTransientByteArray(DATE_SIZE, JCSystem.CLEAR_ON_RESET);
        terminalCounter = JCSystem.makeTransientByteArray(COUNTER_SIZE, JCSystem.CLEAR_ON_RESET);
        pub_key_terminal = JCSystem.makeTransientObjectArray((short) 1, JCSystem.CLEAR_ON_RESET);
        state = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_RESET);
        initialized = false;
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

        if (blocked) {
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
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
            case (byte) 0x20:
                reloadIdDateCounter(apdu);
                break;
            case (byte) 0x22:
                reloadExchangePubKeys(apdu);
                break;
            case (byte) 0x24:
                reloadExchangeSignature(apdu);
                break;
            case (byte) 0x26:
                reloadReceiveAmount(apdu);
                break;
            case (byte) 0x28:
                reloadVerifyAmountAndSignature(apdu);
                break;
            case (byte) 0x40:
                buy(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void reloadReceiveAmount(APDU apdu){
        if (state[0] != RELOAD_TERMINAL_AUTHENTICATED) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        byte[] buffer = apdu.getBuffer();

        // Return an error if the amount is negative
        if (Util.arrayCompare(buffer, (short) 0, ZERO, (short) 0, (short) 4) < 0) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        Util.arrayCopy(buffer, (short) 0, transientData, (short) (ID_SIZE + DATE_SIZE), (short) 4);
        // transientData = terminalId || expirationDate || amount

        state[0] = RELOAD_AMOUNT_RECEIVED;

        apdu.setOutgoingAndSend((short) 0, (short) 0);
    }

    private void reloadVerifyAmountAndSignature(APDU apdu){
        if (state[0] != RELOAD_AMOUNT_RECEIVED) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        byte[] buffer = apdu.getBuffer();

        counter += 1;

        // TODO: fix offsets
        this.transientData[ID_SIZE + DATE_SIZE + 4] = buffer[OFFSET_P1];
        Util.arrayCopy(buffer, OFFSET_CDATA, transientData, (short) 1, (short) (SIGNATURE_SIZE - 1));

        //verifySignature(transientData, (short) (ID_SIZE + DATE_SIZE + 4), , );

    }

    private void signCard(APDU apdu) {
        if (initialized) {
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }

        byte[] buffer = apdu.getBuffer();

        // Step 13
        signature[0] = buffer[OFFSET_P1];
        Util.arrayCopy(buffer, OFFSET_CDATA, signature, (short) 1, (short) (255));
        initialized = true;
    }

    private void setCardIdAndExpirationDate(APDU apdu) {
        if (initialized) {
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }

        byte[] buffer = apdu.getBuffer();

        // Step 8
        Util.arrayCopy(buffer, OFFSET_CDATA, card_id, (short) 0, (short) 4);
        Util.arrayCopy(buffer, (short) (OFFSET_CDATA + 4), expiration_date, (short) 0, (short) 3);
    }

    private void generateKeys(APDU apdu) {
        if (initialized) {
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }

        byte[] buffer = apdu.getBuffer();

        // Step 4
        pub_key_backend = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_2048, false);
        pub_key_backend.setExponent(PUBLIC_EXPONENT, (short) 0, (short) PUBLIC_EXPONENT.length);
        transientData[0] = buffer[OFFSET_P1];
        Util.arrayCopy(buffer, OFFSET_CDATA, transientData, (short) 1, (short) (KEY_SIZE - 1));
        pub_key_backend.setModulus(transientData, (short) 0, KEY_SIZE);

        // Step 5
        KeyPair keyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_2048);
        keyPair.genKeyPair();
        priv_key_card = (RSAPrivateKey) keyPair.getPrivate();
        pub_key_card = (RSAPublicKey) keyPair.getPublic();

        balance = 0;

        // Step 6
        pub_key_card.getModulus(buffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, KEY_SIZE);
    }

    private void reloadIdDateCounter(APDU apdu) {
        if (state[0] != INIT) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        byte[] buffer = apdu.getBuffer();

        counter += 1;

        // save terminal metadata
        Util.arrayCopy(buffer, OFFSET_CDATA, transientData, (short) 0, (short) (ID_SIZE + DATE_SIZE));
        Util.arrayCopy(buffer, (short) (OFFSET_CDATA + ID_SIZE + DATE_SIZE), terminalCounter, (short) 0, COUNTER_SIZE);
        Util.arrayCopy(buffer, (short) (OFFSET_CDATA + ID_SIZE + DATE_SIZE + COUNTER_SIZE), currentDate, (short) 0, DATE_SIZE);

        // send card metadata
        Util.arrayCopy(card_id, (short) 0, buffer, (short) 0, ID_SIZE);
        Util.arrayCopy(expiration_date, (short) 0, buffer, (short) ID_SIZE, DATE_SIZE);
        counterAsBytes(buffer, (short) (ID_SIZE + DATE_SIZE));

        apdu.setOutgoingAndSend((short) 0, (short) (ID_SIZE + DATE_SIZE + COUNTER_SIZE));

        state[0] = RELOAD_META_EXCHANGED;
    }

    private void reloadExchangePubKeys(APDU apdu) {
        if (state[0] != RELOAD_META_EXCHANGED) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        byte[] buffer = apdu.getBuffer();

        // save terminal pub key in transient memory for later verification
        this.transientData[OFFSET_PUB_KEY] = buffer[OFFSET_P1];
        Util.arrayCopy(buffer, OFFSET_CDATA, transientData, (short) (OFFSET_PUB_KEY + 1), (short) (KEY_SIZE - 1));
        this.transientData[OFFSET_DOMAIN_SEPARATOR] = DOMAIN_SEPARATOR_RELOAD;

        // return cards pub key for later verification by the terminal
        pub_key_card.getModulus(buffer, (short) 0);

        state[0] = RELOAD_PUB_KEYS_EXCHANGED;

        apdu.setOutgoingAndSend((short) 0, KEY_SIZE);
    }

    private void reloadExchangeSignature(APDU apdu) {
        if (state[0] != RELOAD_PUB_KEYS_EXCHANGED) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        byte[] buffer = apdu.getBuffer();

        // save terminal signature in transient memory for verification
        this.terminalSignature[0] = buffer[OFFSET_P1];
        Util.arrayCopy(buffer, OFFSET_CDATA, terminalSignature, (short) 1, (short) (SIGNATURE_SIZE - 1));
        verifyTerminalSignature();

        this.pub_key_terminal[0] = KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_2048, false);
        ((RSAPublicKey) pub_key_terminal[0]).setExponent(PUBLIC_EXPONENT, (short) 0, (short) PUBLIC_EXPONENT.length);
        ((RSAPublicKey) pub_key_terminal[0]).setModulus(transientData, OFFSET_PUB_KEY, KEY_SIZE);


        // return cards signature for verification by the terminal
        Util.arrayCopy(signature, (short) 0, buffer, (short) 0, SIGNATURE_SIZE);
        state[0] = RELOAD_TERMINAL_AUTHENTICATED;

        apdu.setOutgoingAndSend((short) 0, (short) SIGNATURE_SIZE);
    }

    private void verifySignature(byte[] sig_a, short offset_a, byte[] sig_b, short offset_b, RSAPublicKey key) {
        // General verification function. Note that the whole byte array (starting from i or j) is compared.
        Signature signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
        signature.init(key, Signature.MODE_VERIFY);
        boolean valid = signature.verify(sig_a, offset_a, SIGNATURE_SIZE, sig_b, offset_b, SIGNATURE_SIZE);
        if (!valid) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    private void verifyTerminalSignature() {
        Signature signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
        signature.init(pub_key_backend, Signature.MODE_VERIFY);
        boolean valid = signature.verify(transientData, (short) 0, (short) transientData.length, terminalSignature, (short) 0, SIGNATURE_SIZE);
        if (!valid) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    private void counterAsBytes(byte[] buffer, short startIndex) {
        buffer[startIndex] = 0x00;
        buffer[(short) (startIndex + 1)] = 0x00;
        Util.setShort(buffer, (short) (startIndex + 2), counter);
    }

    private void buy(APDU apdu) {
        //FIXME
    }
}
