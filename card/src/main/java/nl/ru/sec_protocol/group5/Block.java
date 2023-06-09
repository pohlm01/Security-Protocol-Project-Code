package nl.ru.sec_protocol.group5;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.RSAPublicKey;

public class Block {
    private final PosCard applet;

    Block(PosCard applet) {
        this.applet = applet;
    }

    /**
     * Checks the signature and blocks the card if the signature is valid
     *
     * @param apdu incoming APDU
     * @author Maximilian Pohl
     */
    void block(APDU apdu) {
        if (applet.state[0] != Constants.TERMINAL_ACTIVELY_AUTHENTICATED) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        byte[] buffer = apdu.getBuffer();

        applet.cardCounter += 1;

        // save terminal signature in transient memory for verification
        applet.terminalSignature[0] = buffer[ISO7816.OFFSET_P1];
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, applet.terminalSignature, (short) 1, (short) (Constants.SIGNATURE_SIZE - 1));

        Util.arrayCopy(applet.cardId, (short) 0, applet.transientData, (short) 0, Constants.ID_SIZE);
        Utils.counterAsBytes(applet.cardCounter, applet.transientData, Constants.COUNTER_SIZE);

        applet.utils.verifySignature(applet.transientData, (short) 0, (short) (Constants.ID_SIZE + Constants.COUNTER_SIZE), applet.terminalSignature, (short) 0, (RSAPublicKey) applet.terminalPubKey[0]);

        applet.blocked = true;

        Util.arrayCopy(applet.terminalId, (short) 0, applet.transientData, (short) 0, Constants.ID_SIZE);
        Util.arrayCopy(applet.terminalCounter, (short) 0, applet.transientData, Constants.ID_SIZE, Constants.ID_SIZE);
        Util.arrayCopy(applet.terminalExpirationDate, (short) 0, applet.transientData, (short) (Constants.ID_SIZE + Constants.ID_SIZE), Constants.DATE_SIZE);

        applet.utils.sign(applet.transientData, (short) 0, (short) (Constants.COUNTER_SIZE + Constants.ID_SIZE + Constants.DATE_SIZE), buffer, (short) 0, applet.cardPrivKey);
        apdu.setOutgoingAndSend((short) 0, Constants.SIGNATURE_SIZE);
    }
}
