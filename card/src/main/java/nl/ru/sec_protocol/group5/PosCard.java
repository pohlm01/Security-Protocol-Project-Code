package nl.ru.sec_protocol.group5;

import javacard.framework.*;
import javacard.security.Signature;

public class PosCard extends Applet implements ISO7816 {
    /////////  Transient part ////////////
    protected final byte[] state;
    protected final byte[] transientData;
    protected final Object[] terminalPubKey;
    protected final byte[] terminalId;
    protected final byte[] terminalCounter;
    protected final byte[] terminalType;
    protected final byte[] terminalExpirationTimestamp;
    protected final byte[] terminalSignature;
    protected final byte[] currentTimestamp;

    ////////// Helper objects ///////////
    private final Init init;
    private final MutualAuth mutualAuth;
    private final Reload reload;
    private final Payment payment;
    private final Block block;
    final Utils utils;
    final Signature signatureInstance;

    /////////// Persistent part /////////
    protected byte[] balance;
    protected short cardCounter;
    protected javacard.security.RSAPrivateKey cardPrivKey;
    protected javacard.security.RSAPublicKey cardPubKey;
    protected javacard.security.RSAPublicKey backendPubKey;
    protected boolean blocked;
    protected boolean initialized;
    protected final byte[] cardId;
    protected final byte[] cardExpirationTimestamp; // UNIX epoch TS
    protected final byte[] cardSignature;

    PosCard() {
        balance = new byte[]{0x00, 0x00, 0x00, 0x00};
        cardId = new byte[4];
        cardExpirationTimestamp = new byte[Constants.EPOCH_SIZE];
        cardSignature = new byte[Constants.SIGNATURE_SIZE];
        blocked = false;
        initialized = false;

        cardCounter = 0;

        state = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_RESET);
        transientData = JCSystem.makeTransientByteArray((short) (Constants.ID_SIZE + Constants.EPOCH_SIZE + 1 + Constants.KEY_SIZE), JCSystem.CLEAR_ON_RESET);

        terminalPubKey = JCSystem.makeTransientObjectArray((short) 1, JCSystem.CLEAR_ON_RESET);
        terminalId = JCSystem.makeTransientByteArray(Constants.ID_SIZE, JCSystem.CLEAR_ON_RESET);
        terminalCounter = JCSystem.makeTransientByteArray(Constants.COUNTER_SIZE, JCSystem.CLEAR_ON_RESET);
        terminalType = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_RESET);
        terminalExpirationTimestamp = JCSystem.makeTransientByteArray((short) Constants.EPOCH_SIZE, JCSystem.CLEAR_ON_RESET);
        terminalSignature = JCSystem.makeTransientByteArray(Constants.SIGNATURE_SIZE, JCSystem.CLEAR_ON_RESET);

        currentTimestamp = JCSystem.makeTransientByteArray(Constants.EPOCH_SIZE, JCSystem.CLEAR_ON_RESET);

        init = new Init(this);
        mutualAuth = new MutualAuth(this);
        reload = new Reload(this);
        payment = new Payment(this);
        block = new Block(this);
        utils = new Utils(this);

        signatureInstance = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);

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
                init.generateKeys(apdu);
                break;
            case (byte) 0x04:
                init.setCardIdAndExpirationDate(apdu);
                break;
            case (byte) 0x06:
                init.signCard(apdu);
                break;
            case (byte) 0x20:
                mutualAuth.exchangeMetadata(apdu);
                break;
            case (byte) 0x22:
                mutualAuth.exchangePubKeys(apdu);
                break;
            case (byte) 0x24:
                mutualAuth.exchangeSignature(apdu);
                break;
            case (byte) 0x26:
                mutualAuth.activeAuthentication(apdu);
                break;
            case (byte) 0x28:
                utils.receiveAmount(apdu);
                break;
            case (byte) 0x30:
                reload.verifyAmount(apdu);
                break;
            case (byte) 0x32:
                reload.finalizeReload(apdu);
                break;
            case (byte) 0x42:
                payment.verifyAmount(apdu);
                break;
            case (byte) 0x50:
                block.block(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }
}
