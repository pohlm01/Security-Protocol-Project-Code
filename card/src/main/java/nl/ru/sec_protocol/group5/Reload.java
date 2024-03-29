package nl.ru.sec_protocol.group5;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.RSAPublicKey;

public class Reload {
    private final PosCard applet;

    public Reload(PosCard applet) {
        this.applet = applet;
    }

    /**
     * Receives a signature over the amount signed by the terminal.
     * Sends back a signature over the time stamp, counter, amount, and both IDs to be used for non-repudiation.
     *
     * @param apdu incoming APDU
     * @author Bart Veldman
     */
    void verifyAmount(APDU apdu) {
        if (applet.state[0] != Constants.AMOUNT_RECEIVED && applet.terminalType[0] == Constants.TERMINAL_TYPE_RELOAD) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        byte[] buffer = apdu.getBuffer();

        applet.utils.verifyAmountSignature(buffer);

        // Step 8 - Reload protocol
        applet.state[0] = Constants.RELOAD_AMOUNT_AUTHENTICATED;

        // create and send signature
        // terminal ID || card counter || amount || card ID || time stamp
        // Step 9 - Reload protocol
        Util.arrayCopy(applet.currentTimestamp, (short) 0, applet.transientData, (short) (Constants.ID_SIZE + Constants.COUNTER_SIZE + Constants.AMOUNT_SIZE + Constants.ID_SIZE), Constants.EPOCH_SIZE);
        applet.utils.sign(applet.transientData, (short) 0, (short) (Constants.ID_SIZE + Constants.COUNTER_SIZE + Constants.AMOUNT_SIZE + Constants.ID_SIZE + Constants.EPOCH_SIZE), buffer, (short) 0, applet.cardPrivKey);

        apdu.setOutgoingAndSend((short) 0, (short) Constants.SIGNATURE_SIZE);
    }

    /**
     * Receives a signature over the amount signed by the terminal.
     * Verifies the signature and increases the applet's balance.
     *
     * @param apdu incoming APDU
     * @author Bart Veldman
     */
    void finalizeReload(APDU apdu) {
        if (applet.state[0] != Constants.RELOAD_AMOUNT_AUTHENTICATED) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        byte[] buffer = apdu.getBuffer();

        // Step 13 - Reload protocol
        applet.utils.incrementCounter(applet.cardCounter);

        // verify signature
        // Step 14 - Reload protocol
        applet.terminalSignature[0] = buffer[ISO7816.OFFSET_P1];
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, applet.terminalSignature, (short) 1, (short) (Constants.SIGNATURE_SIZE - 1));

        // terminal ID || card counter || amount || card ID || time stamp
        Util.arrayCopy(applet.cardCounter, (short) 0, applet.transientData, Constants.ID_SIZE, Constants.COUNTER_SIZE);

        applet.utils.verifySignature(applet.transientData, Constants.ID_SIZE, (short) (Constants.COUNTER_SIZE + 4 + Constants.ID_SIZE), applet.terminalSignature, (short) 0, (RSAPublicKey) applet.terminalPubKey[0]);

        // increase card's balance
        // Step 15 - Reload protocol
        applet.utils.byteArrayAddition(applet.balance, (short) 0, applet.transientData, (short) (Constants.ID_SIZE + Constants.COUNTER_SIZE));

        // Step 16 - Reload protocol
        applet.state[0] = Constants.FINISHED;
    }
}
