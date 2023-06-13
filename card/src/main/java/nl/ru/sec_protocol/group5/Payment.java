package nl.ru.sec_protocol.group5;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.RSAPublicKey;

public class Payment {
    private final PosCard applet;

    public Payment(PosCard applet) {
        this.applet = applet;
    }

    /**
     * Checks the current state of the card. Increase the card counter by 1,
     * verifies the signature S2, decrease the balance, change the state to FINISHED and
     * sends a signature S3 with time stamp, card counter, amount, card id and terminal id.
     *
     * @param apdu incoming APDU
     * @author Felix Moelder
     */
    void verifyAmount(APDU apdu) {
        if (applet.state[0] != Constants.AMOUNT_RECEIVED && applet.terminalType[0] == Constants.TERMINAL_TYPE_POS) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        byte[] buffer = apdu.getBuffer();

        applet.utils.verifyAmountSignature(buffer);

        applet.utils.byteArraySubtraction(applet.balance, (short) 0, applet.transientData, (short) (Constants.ID_SIZE + Constants.COUNTER_SIZE));

        applet.state[0] = Constants.FINISHED;

        // create and send signature
        // terminal ID || card counter || amount || card id || time stamp
        Util.arrayCopy(applet.currentDate, (short) 0, applet.transientData, (short) (Constants.ID_SIZE + Constants.COUNTER_SIZE + Constants.AMOUNT_SIZE + Constants.ID_SIZE), Constants.EPOCH_SIZE);
        applet.utils.sign(applet.transientData, (short) 0, (short) (Constants.ID_SIZE + Constants.COUNTER_SIZE + Constants.AMOUNT_SIZE + Constants.ID_SIZE + Constants.EPOCH_SIZE), buffer, (short) 0, applet.cardPrivKey);

        apdu.setOutgoingAndSend((short) 0, (short) Constants.SIGNATURE_SIZE);
    }
}
