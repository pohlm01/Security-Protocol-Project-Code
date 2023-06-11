package nl.ru.sec_protocol.group5;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.time.LocalDate;

import static nl.ru.sec_protocol.group5.Utils.*;
import static nl.ru.sec_protocol.group5.Utils.SIGNATURE_SIZE;

public abstract class Handle {
    protected final static byte SEND_ID_DATE_COUNTER_APDU_INS = 0x20;
    protected final static byte SEND_PUB_KEY_APDU_INS = 0x22;
    protected final static byte SEND_BACKEND_SIGNATURE_APDU_INS = 0x24;
    protected final static byte SEND_CHALLENGE_SIGNATURE_APDU_INS = 0x26;
    protected final static byte SEND_AMOUNT_APDU_INS = 0x28;
    protected final static byte SEND_RELOAD_AMOUNT_SIGNATURE_APDU_INS = 0x30;
    protected final static byte SEND_AMOUNT_LOG_SIGNATURE_APDU_INS = 0x32;
    protected final static byte SEND_PAYMENT_AMOUNT_SIGNATURE_APDU_INS = 0x42;
    private final static byte SEND_CARD_BLOCK_INS = 0x50;

    protected final static byte TERMINAL_TYPE_POS = 0x02;
    protected final static byte TERMINAL_TYPE_RELOAD = 0x03;
    protected int cardId;
    protected int cardCounter;
    protected LocalDate cardExpirationDate;
    protected RSAPublicKey cardPubKey;

    protected final Terminal terminal;

    public Handle(Terminal terminal) {
        this.terminal = terminal;
    }

    public abstract void handleCard(CardChannel channel) throws CardException, NoSuchAlgorithmException, IOException, InvalidKeySpecException, SignatureException, InvalidKeyException;


    /**
     * Performs active mutual authentication with the card and stores the relevant data as in the class attributes
     *
     * @param channel channel to communicate with the card
     * @author Maximilian Pohl
     */
    protected final void mutualAuthentication(CardChannel channel, byte terminalType) throws CardException, NoSuchAlgorithmException, IOException, InvalidKeySpecException, SignatureException, InvalidKeyException {
        // Step 2
        terminal.counter += 1;

        exchangeMetadata(channel);

        exchangePublicKeys(channel);

        exchangeBackendSignatures(channel, terminalType);

        activeAuthentication(channel);

        checkCrl(channel);
    }


    /**
     * Sends the terminal ID, expiration date, and counter to the card and receives
     * the card ID, expiration date, and counter from the card.
     *
     * @param channel channel to communicate with the card
     * @author Maximilian Pohl
     */
    private void exchangeMetadata(CardChannel channel) throws CardException {
        // Step 3
        var dataToSend = new byte[ID_SIZE + DATE_SIZE + COUNTER_SIZE + DATE_SIZE];

        // send terminalId || expirationDate || counter || timestamp
        System.arraycopy(Utils.intToBytes(terminal.id), 0, dataToSend, 0, ID_SIZE);
        System.arraycopy(Utils.dateToBytes(terminal.expirationDate), 0, dataToSend, ID_SIZE, DATE_SIZE);
        System.arraycopy(Utils.intToBytes(terminal.counter), 0, dataToSend, ID_SIZE + DATE_SIZE, 4);
        terminal.timeStamp = LocalDate.now();
        System.arraycopy(Utils.dateToBytes(terminal.timeStamp), 0, dataToSend, ID_SIZE + DATE_SIZE + 4, DATE_SIZE);

        var apdu = new CommandAPDU((byte) 0x00, SEND_ID_DATE_COUNTER_APDU_INS, (byte) 0x00, (byte) 0x00, dataToSend);
        System.out.printf("sending terminalId, expirationDate, counter, and timestamp: %s\n", apdu);

        var response = channel.transmit(apdu);
        System.out.printf("metadata response: %s\n", response);
        var cardMetaData = response.getData();

        // extract the card id
        cardId = Utils.bytesToInt(cardMetaData, 0);

        // extract the card expiration date
        cardExpirationDate = bytesToDate(cardMetaData, ID_SIZE);

        // extract the counter
        cardCounter = Utils.bytesToInt(cardMetaData, ID_SIZE + DATE_SIZE);
    }


    /**
     * Sends the terminal public key to the card and receives
     * the card public key from the card.
     *
     * @param channel channel to communicate with the card
     * @author Maximilian Pohl
     */
    private void exchangePublicKeys(CardChannel channel) throws CardException, NoSuchAlgorithmException, InvalidKeySpecException {
        // exchange public keys
        var modulus = terminal.pubKey.getModulus().toByteArray();

        // We have a `dataOffset` of 2 because the fist byte is unnecessary because it only indicates the sign, which is always positive in our case.
        // The second byte gets cut off because we can only send 255 bytes as payload, but the key is 256 bytes in size.
        // Therefore, we transmit the first byte of the key (second in the byte array) as Param1 of the APDU.
        var apdu = new CommandAPDU((byte) 0x00, SEND_PUB_KEY_APDU_INS, modulus[1], (byte) 0x00, modulus, 2, KEY_SIZE - 1, KEY_SIZE);
        System.out.printf("send pub terminal key: %s\n", apdu);

        var response = channel.transmit(apdu);
        System.out.printf("receive pub card key: %s\n", response);

        cardPubKey = bytesToPubKey(response.getData());
    }


    /**
     * Sends the terminal signature created by the backend to the card and receives
     * the card signature that was created by the backend as well from the card.
     * <p>
     * It additionally verifies that the signature of the card matches the metadata and public card key
     * received earlier
     *
     * @param channel channel to communicate with the card
     * @author Maximilian Pohl
     */
    private void exchangeBackendSignatures(CardChannel channel, byte terminalType) throws CardException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, SignatureException, InvalidKeyException {
        // exchange signatures generated by the backend to achieve a passively authenticated status
        assert terminal.signature != null;
        var apdu = new CommandAPDU((byte) 0x00, SEND_BACKEND_SIGNATURE_APDU_INS, terminal.signature[0], terminalType, terminal.signature, 1, SIGNATURE_SIZE - 1, SIGNATURE_SIZE);
        System.out.printf("send terminal signature: %s\n", apdu);

        var response = channel.transmit(apdu);
        System.out.printf("receive card signature: %s\n", response);

        var cardPassivelyVerified = verifyCardMetadata(response.getData());
        System.out.printf("card passively verified: %s\n", cardPassivelyVerified);
    }

    /**
     * Checks if the card is already expired and if it is properly signed by the back end
     *
     * @param signature contains the bytes of the SHA1withRSA signature over
     *                  `card ID || card expiration date || card pub key || 0x01`
     *                  signed by the private back end key k_b
     * @return true if metadata are ok, false otherwise
     * @author Maximilian Pohl
     */
    private boolean verifyCardMetadata(byte[] signature) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        // verify that the card is not expired yet
        if (cardExpirationDate.isBefore(LocalDate.now())) {
            System.out.println("Card has already expired");
            return false;
        }

        var metadata = new byte[ID_SIZE + DATE_SIZE];
        System.arraycopy(Utils.intToBytes(cardId), 0, metadata, 0, ID_SIZE);
        System.arraycopy(Utils.dateToBytes(cardExpirationDate), 0, metadata, ID_SIZE, DATE_SIZE);

        var card_modulus = cardPubKey.getModulus().toByteArray();

        Signature sig_object = Signature.getInstance("SHA1withRSA");
        sig_object.initVerify(Utils.readPublicKey(new File("backend_public.pem")));

        sig_object.update(metadata, 0, ID_SIZE + DATE_SIZE);
        sig_object.update(card_modulus, 1, SIGNATURE_SIZE);
        sig_object.update((byte) 0x01);

        return sig_object.verify(signature);
    }


    /**
     * Sends a signature over the card ID, card expiration date, and card counter, signed with the
     * private reload terminal key. As the counter will always be a new, this signature prevents replay attacks from
     * a fraudulent terminal.
     * <p>
     * It also receives a signature over the terminal ID, terminal expiration date, and terminal counter, signed with the
     * private card key. As the counter will always be a new, this signature prevents replay attacks from a
     * fraudulent card.
     *
     * @param channel channel to communicate with the card
     * @author Maximilian Pohl
     */
    private void activeAuthentication(CardChannel channel) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, CardException {
        // Sign counters and terminal/card IDs to achieve an actively authenticated status
        // cardID || card expiration date || card counter
        var dataToSign = new byte[COUNTER_SIZE + ID_SIZE + DATE_SIZE];
        System.arraycopy(Utils.intToBytes(cardId), 0, dataToSign, 0, ID_SIZE);
        System.arraycopy(Utils.dateToBytes(cardExpirationDate), 0, dataToSign, ID_SIZE, DATE_SIZE);
        System.arraycopy(Utils.intToBytes(cardCounter), 0, dataToSign, ID_SIZE + DATE_SIZE, COUNTER_SIZE);

        var challenge_signature = Utils.sign(dataToSign, terminal.privKey);

        var apdu = new CommandAPDU((byte) 0x00, SEND_CHALLENGE_SIGNATURE_APDU_INS, challenge_signature[0], (byte) 0x00, challenge_signature, 1, SIGNATURE_SIZE - 1, SIGNATURE_SIZE);
        System.out.printf("send challenge signature: %s\n", apdu);

        var response = channel.transmit(apdu);
        System.out.printf("receive challenge signature: %s\n", response);

        var cardActivelyVerified = checkActiveCardAuthenticationSignature(response.getData());
        System.out.printf("card actively verified: %s\n", cardActivelyVerified);
    }

    /**
     * @param signature contains the bytes of the SHA1withRSA signature over
     *                  `terminal ID || terminal expiration date || counter`
     *                  signed by the private card key k_c
     * @author Maximilian Pohl
     */
    private boolean checkActiveCardAuthenticationSignature(byte[] signature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sig_object = Signature.getInstance("SHA1withRSA");
        sig_object.initVerify(cardPubKey);

        sig_object.update(Utils.intToBytes(terminal.id));
        sig_object.update(Utils.dateToBytes(terminal.expirationDate));
        sig_object.update(Utils.intToBytes(terminal.counter));

        return sig_object.verify(signature);
    }

    /**
     * checks if the card is blocked by a valid CRL and sends a signed block command if so.
     * @author Maximilian Pohl
     */
    private void checkCrl(CardChannel channel) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, SignatureException, InvalidKeyException, CardException {
        for (var blockedCardIds : parseCrl()) {
            if (blockedCardIds == this.cardId){
                blockCard(channel);
                throw new RuntimeException("Card got blocked by backend");
            }
        }
    }

    /**
     * sends a signed block command to the card.
     * @param channel channel to communicate with the card
     * @author Maximilian Pohl
     */
    private void blockCard(CardChannel channel) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, CardException {
        System.out.printf("Blocking card with ID %s as it is part of the CRL", this.cardId);

        cardCounter++;

        var dataToSign = new byte[ID_SIZE + COUNTER_SIZE];
        System.arraycopy(Utils.intToBytes(cardId), 0, dataToSign, 0, ID_SIZE);
        System.arraycopy(Utils.intToBytes(cardCounter), 0, dataToSign, ID_SIZE, COUNTER_SIZE);
        var signature = sign(dataToSign, terminal.privKey);
        
        var apdu = new CommandAPDU((byte) 0x00, SEND_CARD_BLOCK_INS, signature[0], (byte) 0x00, signature, 1, SIGNATURE_SIZE - 1, SIGNATURE_SIZE);
        System.out.printf("send block command: %s\n", apdu);

        var response = channel.transmit(apdu);
        System.out.printf("receive block response: %s\n", response);
        
        // TODO verify signature and log the successful blocking
    }

}
