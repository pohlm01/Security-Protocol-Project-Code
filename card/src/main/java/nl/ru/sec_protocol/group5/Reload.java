package nl.ru.sec_protocol.group5;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

public class Reload {
    private final PosCard applet;

    public Reload(PosCard applet) {
        this.applet = applet;
    }

    /**
     * TODO
     *
     * @param apdu incoming APDU
     * @author Bart Veldman
     */
    void receiveAmount(APDU apdu) {
        if (applet.state[0] != Constants.TERMINAL_PASSIVELY_AUTHENTICATED) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        byte[] buffer = apdu.getBuffer();

        // Return an error if the amount is negative
        if (Util.arrayCompare(buffer, (short) 0, Constants.ZERO, (short) 0, (short) 4) < 0) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        Util.arrayCopy(buffer, (short) 0, applet.transientData, (short) (Constants.ID_SIZE + Constants.DATE_SIZE), (short) 4);
        // transientData = terminalId || expirationDate || amount

        applet.state[0] = Constants.RELOAD_AMOUNT_RECEIVED;

        apdu.setOutgoingAndSend((short) 0, (short) 0);
    }

    /**
     * TODO
     *
     * @param apdu incoming APDU
     * @author Bart Veldman
     */
    void verifyAmountAndSignature(APDU apdu) {
        if (applet.state[0] != Constants.RELOAD_AMOUNT_RECEIVED) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        byte[] buffer = apdu.getBuffer();

        applet.cardCounter += 1;

        applet.transientData[Constants.ID_SIZE + Constants.DATE_SIZE + 4] = buffer[ISO7816.OFFSET_P1];
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, applet.transientData, (short) (Constants.ID_SIZE + Constants.DATE_SIZE + 4 + 1), (short) (Constants.SIGNATURE_SIZE - 1));

        // TODO
        //verifySignature(transientData, (short) (ID_SIZE + DATE_SIZE + 4), , );

    }
}
