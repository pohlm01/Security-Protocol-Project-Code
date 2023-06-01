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
     * Receive the amount with which to increase the card's balance.
     * Checks if the amount is positive and stores it in transientData.
     *
     * @param apdu incoming APDU
     * @author Bart Veldman
     */
    void receiveAmount(APDU apdu) {
        if (applet.state[0] != Constants.TERMINAL_ACTIVELY_AUTHENTICATED) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        byte[] buffer = apdu.getBuffer();

        // Return an error if the amount is negative
        if (Util.arrayCompare(buffer, (short) 0, Constants.ZERO, (short) 0, (short) 4) < 0) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        // terminal ID || 4 bytes for counter || amount
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, applet.transientData, (short) (Constants.ID_SIZE + Constants.COUNTER_SIZE), (short) 4);

        applet.state[0] = Constants.RELOAD_AMOUNT_RECEIVED;
    }

    /**
     * Receives a signature over the amount signed by the terminal.
     * Sends back a signature over the time stamp, counter, amount, and both IDs to be used for non-repudiation.
     *
     * @param apdu incoming APDU
     * @author Bart Veldman
     */
    void verifyAmount(APDU apdu) {
        if (applet.state[0] != Constants.RELOAD_AMOUNT_RECEIVED) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        byte[] buffer = apdu.getBuffer();

        applet.cardCounter += 1;

        // verify signature
        applet.terminalSignature[0] = buffer[ISO7816.OFFSET_P1];
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, applet.terminalSignature, (short) 1, (short) (Constants.SIGNATURE_SIZE - 1));

        // terminal ID || card counter || amount || card ID
        // the terminal ID should already be present, because it was written to transient data in the last step of the mutual auth
        Utils.counterAsBytes(applet.cardCounter, applet.transientData, Constants.ID_SIZE);
        // The amount is written at the correct place during `receiveAmount`
        Util.arrayCopy(applet.cardId, (short) 0, applet.transientData, (short) (Constants.ID_SIZE + Constants.COUNTER_SIZE + 4), Constants.ID_SIZE);

        applet.utils.verifySignature(applet.transientData, Constants.ID_SIZE, (short) (Constants.COUNTER_SIZE + 4 + Constants.ID_SIZE), applet.terminalSignature, (short) 0, (RSAPublicKey) applet.terminalPubKey[0]);

        applet.state[0] = Constants.RELOAD_AMOUNT_AUTHENTICATED;

        // create and send signature
        // terminal ID || card counter || amount || card ID || time stamp
        Util.arrayCopy(applet.currentDate, (short) 0, applet.transientData, (short) (Constants.ID_SIZE + Constants.COUNTER_SIZE + 4 + Constants.ID_SIZE), Constants.DATE_SIZE);
        applet.utils.sign(applet.transientData, (short) 0, (short) (Constants.ID_SIZE + Constants.COUNTER_SIZE + 4 + Constants.ID_SIZE + Constants.DATE_SIZE), buffer, (short) 0, applet.cardPrivKey);

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

        applet.cardCounter += 1;

        // verify signature
        applet.terminalSignature[0] = buffer[ISO7816.OFFSET_P1];
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, applet.terminalSignature, (short) 1, (short) (Constants.SIGNATURE_SIZE - 1));

        // terminal ID || card counter || amount || card ID || time stamp
        Utils.counterAsBytes(applet.cardCounter, applet.transientData, Constants.ID_SIZE);

        applet.utils.verifySignature(applet.transientData, Constants.ID_SIZE, (short) (Constants.COUNTER_SIZE + 4 + Constants.ID_SIZE), applet.terminalSignature, (short) 0, (RSAPublicKey) applet.terminalPubKey[0]);

        // increase card's balance
        Util.arrayCopy(applet.transientData, (short) (Constants.ID_SIZE + Constants.COUNTER_SIZE), applet.amount, (short) 0, (short) 4);
        applet.utils.increaseBalance(applet.amount);

        applet.state[0] = Constants.FINISHED;

        apdu.setOutgoingAndSend((short) 0, (short) 0);
    }
}
