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
     * Receive the amount which has to decrease the card's balance.
     * Check if the amount is bigger than 0 and stores it in transientData.
     *
     * @param apdu
     * @author Felix Moelder
     */
    void receiveAmount(APDU apdu) {
        if (applet.state[0] != Constants.TERMINAL_ACTIVELY_AUTHENTICATED) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        byte[] buffer = apdu.getBuffer();

        //Return an error if the amount is negative
        if(Util.arrayCompare(buffer, (short) 0, Constants.ZERO, (short) 0, (short) 4) < 0) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        //terminal ID || 4 bytes for counter || amount
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, applet.transientData, (short) (Constants.ID_SIZE + Constants.COUNTER_SIZE), (short) Constants.AMOUNT_SIZE);

        applet.state[0] = Constants.POS_AMOUNT_RECEIVED;
    }

    /**
     * Checks the current state of the card. Increase the card counter by 1,
     * verifies the signature S2, decrease the balance, change the state to FINISHED and
     * sends a signature S3 with time stamp, card counter, amount, card id and terminal id.
     *
     * @param apdu
     * @author Felix Moelder
     */
    void verifyAmount(APDU apdu) {
        if (applet.state[0] != Constants.POS_AMOUNT_RECEIVED) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        byte[] buffer = apdu.getBuffer();

        applet.cardCounter += 1;

        //verify signature
        applet.terminalSignature[0] = buffer[ISO7816.OFFSET_P1];
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, applet.terminalSignature, (short) 1, (short) (Constants.SIGNATURE_SIZE - 1));

        //terminal id || card counter || amount || card id
        //the terminal id should already be present, because it was written to transient data in the last step of the mutual authentication
        Util.arrayCopy(applet.cardId, (short) 0, applet.transientData, (short) (Constants.ID_SIZE + Constants.COUNTER_SIZE + Constants.AMOUNT_SIZE), Constants.ID_SIZE);

        applet.utils.verifySignature(applet.transientData, Constants.ID_SIZE, (short) (Constants.COUNTER_SIZE + Constants.AMOUNT_SIZE + Constants.ID_SIZE), applet.terminalSignature, (short) 0, (RSAPublicKey) applet.terminalPubKey[0]);

        applet.utils.byteArraySubtraction(applet.balance, (short) 0, applet.transientData, (short) (Constants.ID_SIZE + Constants.COUNTER_SIZE));

        applet.state[0] = Constants.FINISHED;

        //create and send signature
        //time stamp || card counter || amount || card id || terminal id
        Util.arrayCopy(applet.currentDate, (short) 0, applet.transientData, (short) (Constants.ID_SIZE + Constants.COUNTER_SIZE + Constants.AMOUNT_SIZE + Constants.ID_SIZE), Constants.DATE_SIZE);
        applet.utils.sign(applet.transientData, (short) 0, (short) (Constants.ID_SIZE + Constants.COUNTER_SIZE + Constants.AMOUNT_SIZE + Constants.ID_SIZE + Constants.DATE_SIZE), buffer, (short) 0, applet.cardPrivKey);

        apdu.setOutgoingAndSend((short) 0, (short) Constants.SIGNATURE_SIZE);
    }
}
