package nl.ru.sec_protocol.group5;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.KeyBuilder;
import javacard.security.RSAPublicKey;
import javacard.security.Signature;

public class MutualAuth {
    private final PosCard applet;

    MutualAuth(PosCard applet) {
        this.applet = applet;
    }

    /**
     * Exchange the terminal/card ID, expiration date, counter and current date with the terminal to verify it later.
     *
     * @param apdu incoming APDU
     * @author Maximilian Pohl
     */
    void exchangeMetadata(APDU apdu) {
        if (applet.state[0] != Constants.INIT) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        byte[] buffer = apdu.getBuffer();

        // Step 3 - Mutual Auth
        applet.utils.incrementCounter(applet.cardCounter);

        // save terminal metadata
        // Step 4 - Mutual Auth
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, applet.transientData, (short) 0, (short) (Constants.ID_SIZE + Constants.EPOCH_SIZE));
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, applet.terminalId, (short) 0, Constants.ID_SIZE);
        Util.arrayCopy(buffer, (short) (ISO7816.OFFSET_CDATA + Constants.ID_SIZE), applet.terminalExpirationTimestamp, (short) 0, Constants.EPOCH_SIZE);
        Util.arrayCopy(buffer, (short) (ISO7816.OFFSET_CDATA + Constants.ID_SIZE + Constants.EPOCH_SIZE), applet.terminalCounter, (short) 0, Constants.COUNTER_SIZE);
        Util.arrayCopy(buffer, (short) (ISO7816.OFFSET_CDATA + Constants.ID_SIZE + Constants.EPOCH_SIZE + Constants.COUNTER_SIZE), applet.currentTimestamp, (short) 0, Constants.EPOCH_SIZE);

        // Check if the terminal is expired
        if (Utils.bitArrayCompare(applet.currentTimestamp, (short) 0, applet.terminalExpirationTimestamp, (short) 0, Constants.EPOCH_SIZE) > 0) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        // send card metadata
        Util.arrayCopy(applet.cardId, (short) 0, buffer, (short) 0, Constants.ID_SIZE);
        Util.arrayCopy(applet.cardExpirationTimestamp, (short) 0, buffer, (short) Constants.ID_SIZE, Constants.EPOCH_SIZE);
        Util.arrayCopy(applet.cardCounter, (short) 0, buffer, (short) (Constants.ID_SIZE + Constants.EPOCH_SIZE), Constants.COUNTER_SIZE);

        // Step 5 - Mutual Auth
        applet.state[0] = Constants.TERMINAL_META_EXCHANGED;

        // Step 6 - Mutual Auth
        apdu.setOutgoingAndSend((short) 0, (short) (Constants.ID_SIZE + Constants.EPOCH_SIZE + Constants.COUNTER_SIZE));
    }

    /**
     * Exchange the terminal/card public keys verify it later.
     *
     * @param apdu incoming APDU
     * @author Maximilian Pohl
     */
    void exchangePubKeys(APDU apdu) {
        if (applet.state[0] != Constants.TERMINAL_META_EXCHANGED) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        byte[] buffer = apdu.getBuffer();

        // save terminal pub key in transient memory for later verification
        // Step 8 - Mutual Auth
        applet.transientData[Constants.OFFSET_PUB_KEY] = buffer[ISO7816.OFFSET_P1];
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, applet.transientData, (short) (Constants.OFFSET_PUB_KEY + 1), (short) (Constants.KEY_SIZE - 1));

        // return cards pub key for later verification by the terminal
        applet.cardPubKey.getModulus(buffer, (short) 0);

        // Step 9 - Mutual Auth
        applet.state[0] = Constants.PUB_KEYS_EXCHANGED;

        apdu.setOutgoingAndSend((short) 0, Constants.KEY_SIZE);
    }

    /**
     * Exchange the terminal/card signature from the backend and verify the validity together with the previously
     * stored metadata and public terminal key. Sends back the signature of the card which was provided by the back end.
     *
     * @param apdu incoming APDU
     * @author Maximilian Pohl
     */
    void exchangeSignature(APDU apdu) {
        if (applet.state[0] != Constants.PUB_KEYS_EXCHANGED) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        byte[] buffer = apdu.getBuffer();

        // save terminal signature in transient memory for verification
        // Step 12 - Mutual Auth
        applet.terminalSignature[0] = buffer[ISO7816.OFFSET_P1];
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, applet.terminalSignature, (short) 1, (short) (Constants.SIGNATURE_SIZE - 1));

        // use param2 to decide if it is a reload or POS terminal
        byte terminalType = buffer[ISO7816.OFFSET_P2];
        verifyTerminalSignature(terminalType);

        // Step 13 - Mutual Auth
        this.applet.terminalPubKey[0] = KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_2048, false);
        ((RSAPublicKey) applet.terminalPubKey[0]).setExponent(Constants.PUBLIC_EXPONENT, (short) 0, (short) Constants.PUBLIC_EXPONENT.length);
        ((RSAPublicKey) applet.terminalPubKey[0]).setModulus(applet.transientData, Constants.OFFSET_PUB_KEY, Constants.KEY_SIZE);

        // Step 14 - Mutual Auth
        applet.terminalType[0] = terminalType;
        applet.state[0] = Constants.TERMINAL_PASSIVELY_AUTHENTICATED;

        // return cards signature for verification by the terminal
        // Step 15 - Mutual Auth
        Util.arrayCopy(applet.cardSignature, (short) 0, buffer, (short) 0, Constants.SIGNATURE_SIZE);
        apdu.setOutgoingAndSend((short) 0, (short) Constants.SIGNATURE_SIZE);
    }


    /**
     * @param domainSeparator byte indicating whether a POS or reload terminal should be authenticated
     * @author Maximilian Pohl
     */
    void verifyTerminalSignature(byte domainSeparator) {
        applet.transientData[Constants.OFFSET_DOMAIN_SEPARATOR] = domainSeparator;

        applet.signatureInstance.init(applet.backendPubKey, Signature.MODE_VERIFY);
        boolean valid = applet.signatureInstance.verify(applet.transientData, (short) 0, (short) applet.transientData.length, applet.terminalSignature, (short) 0, Constants.SIGNATURE_SIZE);
        if (!valid) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    /**
     * Receives a signature over the card details signed by the terminal. As this includes the card counter, it prevents
     * replay attacks.
     * Sends back a signature over the terminal details including the terminals counter to prevent replay attacks.
     *
     * @param apdu incoming APDU
     * @author Maximilian Pohl
     */
    void activeAuthentication(APDU apdu) {
        if (applet.state[0] != Constants.TERMINAL_PASSIVELY_AUTHENTICATED) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        byte[] buffer = apdu.getBuffer();

        // Step 18 - Mutual Auth
        this.applet.terminalSignature[0] = buffer[ISO7816.OFFSET_P1];
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, applet.terminalSignature, (short) 1, (short) (Constants.SIGNATURE_SIZE - 1));

        // card ID || card expiration date || card counter
        Util.arrayCopy(applet.cardId, (short) 0, applet.transientData, Constants.OFFSET_PUB_KEY, Constants.COUNTER_SIZE);
        Util.arrayCopy(applet.cardExpirationTimestamp, (short) 0, applet.transientData, (short) (Constants.OFFSET_PUB_KEY + Constants.COUNTER_SIZE), Constants.EPOCH_SIZE);
        Util.arrayCopy(applet.cardCounter, (short) 0, applet.transientData, (short) (Constants.OFFSET_PUB_KEY + Constants.COUNTER_SIZE + Constants.EPOCH_SIZE), Constants.COUNTER_SIZE);
        applet.utils.verifySignature(applet.transientData, Constants.OFFSET_PUB_KEY, (short) (Constants.ID_SIZE + Constants.EPOCH_SIZE + Constants.COUNTER_SIZE), applet.terminalSignature, (short) 0, (RSAPublicKey) applet.terminalPubKey[0]);

        // Step 19 - Mutual Auth
        if (Utils.bitArrayCompare(applet.currentTimestamp, (short) 0, applet.cardExpirationTimestamp, (short) 0, Constants.EPOCH_SIZE) > 0) {
            applet.blocked = true;
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        // terminalId || terminal expirationDate || terminal counter
        Util.arrayCopy(applet.terminalCounter, (short) 0, applet.transientData, Constants.OFFSET_PUB_KEY, Constants.COUNTER_SIZE);
        applet.utils.sign(applet.transientData, (short) 0, (short) (Constants.ID_SIZE + Constants.EPOCH_SIZE + Constants.COUNTER_SIZE), buffer, (short) 0, applet.cardPrivKey);

        // Step 20 - Mutual Auth
        applet.state[0] = Constants.TERMINAL_ACTIVELY_AUTHENTICATED;

        // Step 21 - Mutual Auth
        apdu.setOutgoingAndSend((short) 0, (short) Constants.SIGNATURE_SIZE);
    }
}
