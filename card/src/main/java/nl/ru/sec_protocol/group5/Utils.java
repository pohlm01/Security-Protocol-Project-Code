package nl.ru.sec_protocol.group5;

import javacard.framework.*;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.Signature;

public class Utils {
    private final PosCard applet;

    private final short[] X;
    private final short[] Y;

    Utils(PosCard applet) {
        this.applet = applet;
        this.X = JCSystem.makeTransientShortArray((short) 2, JCSystem.CLEAR_ON_RESET);
        this.Y = JCSystem.makeTransientShortArray((short) 2, JCSystem.CLEAR_ON_RESET);
    }
    void sign(byte[] data, short offset_data, short data_length, byte[] sig, short offset_sig, RSAPrivateKey key) {
        applet.signatureInstance.init(key, Signature.MODE_SIGN);
        applet.signatureInstance.sign(data, offset_data, data_length, sig, offset_sig);
    }

    void verifySignature(byte[] data, short offset_data, short data_length, byte[] sig, short offset_sig, RSAPublicKey key) {
        applet.signatureInstance.init(key, Signature.MODE_VERIFY);
        boolean valid = applet.signatureInstance.verify(data, offset_data, data_length, sig, offset_sig, Constants.SIGNATURE_SIZE);
        if (!valid) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    void verifyTerminalSignature(byte domainSeparator) {
        applet.transientData[Constants.OFFSET_DOMAIN_SEPARATOR] = domainSeparator;

        applet.signatureInstance.init(applet.backendPubKey, Signature.MODE_VERIFY);
        boolean valid = applet.signatureInstance.verify(applet.transientData, (short) 0, (short) applet.transientData.length, applet.terminalSignature, (short) 0, Constants.SIGNATURE_SIZE);
        if (!valid) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
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
        // Step 3 - Reload Protocol
        if (Util.arrayCompare(buffer, (short) 0, Constants.ZERO, (short) 0, (short) 4) < 0) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        // terminal ID || 4 bytes for counter || amount
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, applet.transientData, (short) (Constants.ID_SIZE + Constants.COUNTER_SIZE), (short) 4);

        // Step 4 - Reload Protocol
        applet.state[0] = Constants.AMOUNT_RECEIVED;
    }

    void verifyAmountSignature(byte[] buffer) {
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
    }

    static void counterAsBytes(short counter, byte[] buffer, short startIndex) {
        buffer[startIndex] = 0x00;
        buffer[(short) (startIndex + 1)] = 0x00;
        Util.setShort(buffer, (short) (startIndex + 2), counter);
    }

    /**
     * Int like addition operation on two byte arrays.
     * Treats the four bytes, beginning from offset, as an int.
     * <br>
     * This is done by casting the byte arrays to short arrays of length 2 and checking for overflow.
     *
     * @param arrayX byte array of <code>length >= offsetX + 4</code>. The Sum of both arrays will be returned here
     * @param offsetX offset at which the int starts
     * @param arrayY byte array of <code>length >= offsetY + 4</code>
     * @param offsetY offset at which the int starts
     * @author Bart Veldman
     */
    void byteArrayAddition(byte[] arrayX, short offsetX, byte[] arrayY, short offsetY){
        X[0] = Util.getShort(arrayX, offsetX);
        X[1] = Util.getShort(arrayX, (short) (2 + offsetX));
        Y[0] = Util.getShort(arrayY, offsetY);
        Y[1] = Util.getShort(arrayY, (short) (2 + offsetY));
        shortArrayAddition(X, Y);
        Util.setShort(arrayX, offsetX, X[0]);
        Util.setShort(arrayX, (short) (2 + offsetX), X[1]);
    }

    /**
     * Int like subtraction operation on two byte arrays.
     * Treats the four bytes, beginning from offset, as an int.
     * Subtraction is performed by adding the negation of Y (x - y = x + (-y))
     *
     * @param arrayX byte array of <code>length >= offsetX + 4</code>. <code>arrayX - arrayY</code> will be returned here.
     * @param offsetX offset at which the int starts
     * @param arrayY byte array of <code>length >= offsetY + 4</code>
     * @param offsetY offset at which the int starts
     * @author Bart Veldman
     */
    void byteArraySubtraction(byte[] arrayX, short offsetX, byte[] arrayY, short offsetY) {
        // return an error if the result would be negative
        // FIXME does not work if balance byte is 'negative' in Java's opinion
        if (Util.arrayCompare(arrayX, offsetX, arrayY, offsetY, (short) 4) < 0) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        X[0] = Util.getShort(arrayX, offsetX);
        X[1] = Util.getShort(arrayX, (short) (2 + offsetX));
        // negate Y : inverse and increment
        Y[0] = (short) ~Util.getShort(arrayY, offsetY);
        Y[1] = (short) ~Util.getShort(arrayY, (short) (2 + offsetY));
        Y[0] = (short) (Y[0] + (~Y[1] == 0 ? 1 : 0));
        Y[1] = (short) (Y[1] + 1);
        shortArrayAddition(X, Y);
        Util.setShort(arrayX, offsetX, X[0]);
        Util.setShort(arrayX, (short) (2 + offsetX), X[1]);
    }

    /** In place addition of two short arrays with length 2, each array treated as one int
     *
     * @param x short array of length 2. Will contain the result afterward
     * @param y short array of length 2
     * @author Bart Veldman
     */
    void shortArrayAddition(short[] x, short[] y){
        /* 3 conditions where we have a carrier bit:
          - both are negative (signed short, so the first bit will be a 1)
          - one side (a) is negative and the other side (b) is larger than the negation of a. The sum must be >= 2^16 so there is overflow
          - vice versa
          source: https://stackoverflow.com/questions/74383478/how-to-get-the-value-of-the-carry-bit-when-adding-two-shorts-in-java
        */
        x[0] = (short) (x[0] + y[0] + (
                        x[1] < 0 && y[1] < 0 ||
                        x[1] < 0 && y[1] >= (short) -x[1] ||
                        y[1] < 0 && x[1] >= (short) -y[1] ? 1 : 0));
        x[1] = (short) (x[1] + y[1]);
    }
}