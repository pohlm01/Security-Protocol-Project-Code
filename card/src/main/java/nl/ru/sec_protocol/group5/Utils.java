package nl.ru.sec_protocol.group5;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
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
        X[0] = Util.getShort(arrayX, offsetX);
        X[1] = Util.getShort(arrayX, (short) (2 + offsetX));
        // inverse arrayY
        Y[0] = (short) ~Util.getShort(arrayY, offsetY);
        Y[1] = (short) ~Util.getShort(arrayY, (short) (2 + offsetY));
        // increment
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