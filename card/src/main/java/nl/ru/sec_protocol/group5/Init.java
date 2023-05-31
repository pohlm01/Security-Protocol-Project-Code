package nl.ru.sec_protocol.group5;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;

public class Init {
    private final PosCard applet;

    Init(PosCard applet) {
        this.applet = applet;
    }

    /**
     * Copy signature created by the backend to the cards EEPROM for later authentication towards the terminals.
     *
     * @param apdu incoming APDU
     * @author Maximilian Pohl
     */
    void signCard(APDU apdu) {
        if (applet.initialized) {
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }

        byte[] buffer = apdu.getBuffer();

        // Step 13
        applet.cardSignature[0] = buffer[ISO7816.OFFSET_P1];
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, applet.cardSignature, (short) 1, (short) (255));
        applet.initialized = true;
    }

    /**
     * Copy card ID and expiration date to the cards EEPROM for later authentication towards the terminals.
     *
     * @param apdu incoming APDU
     * @author Maximilian Pohl
     */
    void setCardIdAndExpirationDate(APDU apdu) {
        if (applet.initialized) {
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }

        byte[] buffer = apdu.getBuffer();

        // Step 8
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, applet.cardId, (short) 0, (short) 4);
        Util.arrayCopy(buffer, (short) (ISO7816.OFFSET_CDATA + 4), applet.cardExpirationDate, (short) 0, (short) 3);
    }

    /**
     * Generate new public/private 2048-bit RSA key pair and send back the public key to the init terminal to get it
     * signed by the backend.
     *
     * @param apdu incoming APDU
     * @author Maximilian Pohl
     */
    void generateKeys(APDU apdu) {
        if (applet.initialized) {
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }

        byte[] buffer = apdu.getBuffer();

        // Step 4
        applet.backendPubKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_2048, false);
        applet.backendPubKey.setExponent(Constants.PUBLIC_EXPONENT, (short) 0, (short) Constants.PUBLIC_EXPONENT.length);
        applet.transientData[0] = buffer[ISO7816.OFFSET_P1];
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, applet.transientData, (short) 1, (short) (Constants.KEY_SIZE - 1));
        applet.backendPubKey.setModulus(applet.transientData, (short) 0, Constants.KEY_SIZE);

        // Step 5
        KeyPair keyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_2048);
        keyPair.genKeyPair();
        applet.cardPrivKey = (RSAPrivateKey) keyPair.getPrivate();
        applet.cardPubKey = (RSAPublicKey) keyPair.getPublic();

        // Step 6
        applet.cardPubKey.getModulus(buffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, Constants.KEY_SIZE);
    }

}
