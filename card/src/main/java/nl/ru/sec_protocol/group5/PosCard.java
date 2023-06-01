package nl.ru.sec_protocol.group5;

import com.sun.imageio.plugins.jpeg.JPEG;
import javacard.framework.*;
import javacard.security.*;

public class PosCard extends Applet implements ISO7816 {
    /////////// Persistent part /////////
    protected byte[] balance;
    protected final byte[] cardId;
    protected final byte[] cardExpirationDate; // [day, month, year(three last digits, using 2000 as base year)]
    protected final byte[] cardSignature;

    protected short cardCounter;

    protected javacard.security.RSAPrivateKey cardPrivKey;
    protected javacard.security.RSAPublicKey cardPubKey;
    protected javacard.security.RSAPublicKey backendPubKey;
    protected boolean blocked;
    protected boolean initialized;


    /////////  Transient part ////////////
    protected final byte[] state;

    /**
     * terminalId || expirationDate || terminalPubKey || domainSeparator
     */
    protected final byte[] transientData;

    protected final Object[] terminalPubKey;
    protected final byte[] terminalId;
    protected final byte[] terminalCounter;
    protected final byte[] terminalType;
    protected final byte[] terminalSignature;

    protected final byte[] currentDate;
    protected byte[] amount;
    protected short[] xA;
    protected short[] xB;
    protected short[] yA;
    protected short[] yB;


    ////////// Helper objects ///////////
    private final Init init;
    private final MutualAuth mutualAuth;
    private final Reload reload;
    private final Block block;
    final Utils utils;
    final Signature signatureInstance;

    PosCard() {
        balance = new byte[]{0x00,0x00,0x00,0x00};
        cardId = new byte[4];
        cardExpirationDate = new byte[3];
        cardSignature = new byte[2048 / 8];
        blocked = false;
        initialized = false;

        cardCounter = 0;

        state = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_RESET);
        transientData = JCSystem.makeTransientByteArray((short) (Constants.ID_SIZE + Constants.DATE_SIZE + 1 + Constants.KEY_SIZE), JCSystem.CLEAR_ON_RESET);

        terminalPubKey = JCSystem.makeTransientObjectArray((short) 1, JCSystem.CLEAR_ON_RESET);
        terminalId = JCSystem.makeTransientByteArray(Constants.ID_SIZE, JCSystem.CLEAR_ON_RESET);
        terminalCounter = JCSystem.makeTransientByteArray(Constants.COUNTER_SIZE, JCSystem.CLEAR_ON_RESET);
        terminalType = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_RESET);
        terminalSignature = JCSystem.makeTransientByteArray(Constants.SIGNATURE_SIZE, JCSystem.CLEAR_ON_RESET);

        currentDate = JCSystem.makeTransientByteArray(Constants.DATE_SIZE, JCSystem.CLEAR_ON_RESET);

        amount = JCSystem.makeTransientByteArray((short) 4, JCSystem.CLEAR_ON_RESET);
        xA = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_RESET);
        xB = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_RESET);
        yA = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_RESET);
        yB = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_RESET);


        init = new Init(this);
        mutualAuth = new MutualAuth(this);
        reload = new Reload(this);
        utils = new Utils(this);
        block = new Block(this);

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
                reload.receiveAmount(apdu);
                break;
            case (byte) 0x30:
                reload.verifyAmountAndSignature(apdu);
                break;
            case (byte) 0x32:
                reload.finalizeReload(apdu);
                break;
            case (byte) 0x40:
                buy(apdu);
                break;
            case (byte) 0x50:
                block.block(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }


    private void buy(APDU apdu) {
        //FIXME
        //Adding here the calls to the functions that do Step 3,4,6,7,8,9. Majority can be used from Reload with small
        //mods.
    }
}
