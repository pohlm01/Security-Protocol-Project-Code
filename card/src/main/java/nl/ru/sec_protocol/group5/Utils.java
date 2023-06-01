package nl.ru.sec_protocol.group5;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.Signature;

public class Utils {
    private final PosCard applet;

    protected static short[] X;
    protected static short[] Y;
    protected static byte[] B;
    protected static short[] addResult;

    Utils(PosCard applet) {
        this.applet = applet;
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
     * Addition operation on two byte arrays of length 4
     * Casts the byte arrays to short arrays of length 2 and checks for overflow
     *
     * @param arrayX byte array of length 4. Sum of both arrays will be returned here
     * @param arrayY byte array of length 4
     * @author Bart Veldman
     */
    byte[] byteArrayAddition(byte[] arrayX, byte[] arrayY){
        X[0] = Util.getShort(arrayX, (short) 0);
        X[1] = Util.getShort(arrayX, (short) 2);
        Y[0] = Util.getShort(arrayY, (short) 0);
        Y[1] = Util.getShort(arrayY, (short) 2);
        shortArrayAddition(X, Y);
        Util.setShort(B, (short) 0, addResult[0]);
        Util.setShort(B, (short) 2, addResult[1]);
        return B;
    }

    /**
     * Subtraction operation on two byte arrays of length 4
     * Please ensure that Y is larger than X as this is not checked
     * Subtraction performed by adding the negation of Y (x - y = x + (-y))
     *
     * @param arrayX byte array of length 4
     * @param arrayY byte array of length 4
     * @author Bart Veldman
     */
    byte[] byteArraySubtraction(byte[] arrayX, byte[] arrayY) {
        X[0] = Util.getShort(arrayX, (short) 0);
        X[1] = Util.getShort(arrayX, (short) 2);
        // inverse arrayY
        Y[0] = (short) ~Util.getShort(arrayY, (short) 0);
        Y[1] = (short) ~Util.getShort(arrayY, (short) 2);
        // increment
        Y[0] = (short) (Y[0] + (~Y[1] == 0 ? 1 : 0));
        Y[1] = (short) (Y[1] + 1);
        shortArrayAddition(X, Y);
        Util.setShort(B, (short) 0, addResult[0]);
        Util.setShort(B, (short) 2, addResult[1]);
        return B;
    }

    void shortArrayAddition(short[] x, short[] y){
        /* 3 conditions where we have a carrier bit:
          - both are negative (signed short, so the first bit will be a 1)
          - one side (a) is negative and the other side (b) is larger than the negation of a. The sum must be >= 2^16 so there is overflow
          - vice versa
          source: https://stackoverflow.com/questions/74383478/how-to-get-the-value-of-the-carry-bit-when-adding-two-shorts-in-java
        */
        addResult[0] = (short) (x[0] + y[0] + (
                        x[1] < 0 && y[1] < 0 ||
                        x[1] < 0 && y[1] >= (short) -x[1] ||
                        y[1] < 0 && x[1] >= (short) -y[1] ? 1 : 0));
        addResult[1] = (short) (x[1] + y[1]);
    }
}