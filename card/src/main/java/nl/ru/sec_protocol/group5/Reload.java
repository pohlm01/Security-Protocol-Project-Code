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

        // Step 6,7 - Reload Protocol
        applet.utils.verifyAmountSignature(buffer);

        // Step 8 - Reload Protocol
        applet.state[0] = Constants.RELOAD_AMOUNT_AUTHENTICATED;

        // Step 9 - Reload Protocol
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

        // Step 13 - Reload Protocol
        applet.cardCounter += 1;

        // Step 14 - Reload Protocol
        // verify signature
        applet.terminalSignature[0] = buffer[ISO7816.OFFSET_P1];
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, applet.terminalSignature, (short) 1, (short) (Constants.SIGNATURE_SIZE - 1));

        // terminal ID || card counter || amount || card ID || time stamp
        Utils.counterAsBytes(applet.cardCounter, applet.transientData, Constants.ID_SIZE);

        applet.utils.verifySignature(applet.transientData, Constants.ID_SIZE, (short) (Constants.COUNTER_SIZE + 4 + Constants.ID_SIZE), applet.terminalSignature, (short) 0, (RSAPublicKey) applet.terminalPubKey[0]);

        // Step 15 - Reload Protocol
        // increase card's balance
        applet.utils.byteArrayAddition(applet.balance, (short) 0, applet.transientData, (short) (Constants.ID_SIZE + Constants.COUNTER_SIZE));

        // Step 16 - Reload Protocol
        applet.state[0] = Constants.FINISHED;

        apdu.setOutgoingAndSend((short) 0, (short) 0);
    }
}
