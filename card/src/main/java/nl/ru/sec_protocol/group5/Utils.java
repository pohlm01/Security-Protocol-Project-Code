package nl.ru.sec_protocol.group5;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.Signature;

public class Utils {
    private final PosCard applet;

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

    void increaseBalance(byte[] amount){
        applet.xA[0] = Util.getShort(amount, (short) 0);
        applet.xB[0] = Util.getShort(amount, (short) 2);
        applet.yA[0] = Util.getShort(applet.balance, (short) 0);
        applet.yB[0] = Util.getShort(applet.balance, (short) 2);
        /* 3 conditions where we have a carrier bit:
          - both are negative (signed short, so the first bit will be a 1)
          - one side (a) is negative and the other side (b) is larger than the negation of a. The sum must be >= 2^16 so there is overflow
          - vice versa
          source: https://stackoverflow.com/questions/74383478/how-to-get-the-value-of-the-carry-bit-when-adding-two-shorts-in-java
        */
        Util.setShort(applet.balance, (short) 0, (short) (applet.xA[0] + applet.yA[0] + (
                                                            applet.xB[0] < 0 && applet.yB[0] < 0 ||
                                                            applet.xB[0] < 0 && applet.yB[0] >= (short) -applet.xB[0] ||
                                                            applet.yB[0] < 0 && applet.xB[0] >= (short) -applet.yB[0] ? 1 : 0)));
        Util.setShort(applet.balance, (short) 2, (short) (applet.xB[0] + applet.yB[0]));
    }

    void decreaseBalance(byte[] amount){
        // TODO
    }
}
