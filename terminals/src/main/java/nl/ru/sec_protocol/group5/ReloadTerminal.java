package nl.ru.sec_protocol.group5;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.time.LocalDate;
import java.util.Arrays;
import java.util.Scanner;

import static nl.ru.sec_protocol.group5.Utils.*;

public class ReloadTerminal extends Terminal {
    private final static byte SEND_ID_DATE_COUNTER_APDU_INS = 0x08;
    private final static byte SEND_PUB_KEY_APDU_INS = 0x0A;
    private final static byte SEND_SIGNATURE_APDU_INS = 0x0C;
    private final static byte SEND_AMOUNT = 0x0E;
    private final static byte SEND_AMOUNT_SIGNATURE = 0x10;

    private final int terminalId;
    private final LocalDate expirationDate;
    private static int counter = 0;

    private static int card_id;
    private static int counter_card;

    private final RSAPublicKey reloadPubKey;
    private final RSAPrivateKey reloadPrivKey;
    private final byte[] signature;


    public ReloadTerminal(int terminalId, LocalDate expirationDate) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        this.expirationDate = expirationDate;
        this.terminalId = terminalId;

        this.reloadPubKey = Utils.readPublicKey(new File("reload_public.pem"));
        this.reloadPrivKey = Utils.readPrivateKey(new File("reload_private.pem"));
        this.signature = Files.readAllBytes(Paths.get("reload_signature"));

        // Step 2
        ReloadTerminal.counter += 1;
    }


    public static void main(String[] args) throws CardException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException, IOException {
        ReloadTerminal reloadTerminal = new ReloadTerminal(12345, LocalDate.of(2023, 6, 1));
        reloadTerminal.start();
    }

    @Override
    public void handleCard(CardChannel channel) throws NoSuchAlgorithmException, CardException, InvalidKeySpecException, SignatureException, InvalidKeyException, IOException {
        authenticateToCard(channel);

        var scanner = new Scanner(System.in);
        System.out.println("What amount should be added to the card's balance?");
        var amount = scanner.nextInt();
        communicateAmount(channel, amount);

    }

    private void communicateAmount(CardChannel channel, int amount) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, CardException {
        // send amount
        var dataToSend = new byte[4];
        System.arraycopy(Utils.intToBytes(amount), 0, dataToSend, 0, 4);

        var apdu = new CommandAPDU((byte) 0x00, SEND_AMOUNT, (byte) 0x00, (byte) 0x00, dataToSend);
        System.out.printf("sending amount: %s\n", apdu);

        var response = channel.transmit(apdu);
        System.out.printf("response: %s\n", response);

        // create signature
        var data = new byte[COUNTER_SIZE + 4 + ID_SIZE];
        System.arraycopy(Utils.intToBytes(counter_card), 0, data, 0, COUNTER_SIZE);
        System.arraycopy(Utils.intToBytes(amount), 0, data, COUNTER_SIZE, 4);
        System.arraycopy(Utils.intToBytes(card_id), 0, data, COUNTER_SIZE + 4, ID_SIZE);

        Signature signer = Signature.getInstance("SHA1withRSA");
        signer.initSign(reloadPrivKey);
        signer.update(data);
        var signature_amount = signer.sign();

        // send signature
        apdu = new CommandAPDU((byte) 0x00, SEND_AMOUNT_SIGNATURE, signature_amount[0], (byte) 0x00, signature_amount, 1, SIGNATURE_SIZE - 1, SIGNATURE_SIZE);
        System.out.printf("send amount signature: %s\n", apdu);

        response = channel.transmit(apdu);
        System.out.printf("receive amount signature: %s\n", response);
    }

    private void authenticateToCard(CardChannel channel) throws CardException, NoSuchAlgorithmException, IOException, InvalidKeySpecException, SignatureException, InvalidKeyException {
        // Step 2
        counter += 1;

        // Step 3
        var dataToSend = new byte[ID_SIZE + DATE_SIZE + COUNTER_SIZE + DATE_SIZE];

        // send terminalId || expirationDate || counter || timestamp
        System.arraycopy(Utils.intToBytes(terminalId), 0, dataToSend, 0, ID_SIZE);
        System.arraycopy(Utils.dateToBytes(expirationDate), 0, dataToSend, ID_SIZE, DATE_SIZE);
        System.arraycopy(Utils.intToBytes(counter), 0, dataToSend, ID_SIZE + DATE_SIZE, 4);
        System.arraycopy(Utils.dateToBytes(LocalDate.now()), 0, dataToSend, ID_SIZE + DATE_SIZE + 4, DATE_SIZE);

        var apdu = new CommandAPDU((byte) 0x00, SEND_ID_DATE_COUNTER_APDU_INS, (byte) 0x00, (byte) 0x00, dataToSend);
        System.out.printf("sending terminalId, expirationDate, counter, and timestamp: %s\n", apdu);

        var response = channel.transmit(apdu);
        System.out.printf("response: %s\n", response);
        var cardMetaData = response.getData();

        // extract the card id
        byte[] card_id_bytes = Arrays.copyOfRange(cardMetaData, 0, ID_SIZE);
        ByteBuffer wrapped_id = ByteBuffer.wrap(card_id_bytes);
        card_id = wrapped_id.getInt();

        // extract the counter
        byte[] counter_card_bytes = Arrays.copyOfRange(cardMetaData, ID_SIZE + DATE_SIZE, cardMetaData.length);
        ByteBuffer wrapped_counter = ByteBuffer.wrap(counter_card_bytes);
        counter_card = wrapped_counter.getInt();

        // exchange public keys
        var modulus = this.reloadPubKey.getModulus().toByteArray();

        // We have a `dataOffset` of 2 because the fist byte is unnecessary because it only indicates the sign, which is always positive in our case.
        // The second byte gets cut off because we can only send 255 bytes as payload, but the key is 256 bytes in size.
        // Therefore, we transmit the first byte of the key (second in the byte array) as Param1 of the APDU.
        apdu = new CommandAPDU((byte) 0x00, SEND_PUB_KEY_APDU_INS, modulus[1], (byte) 0x00, modulus, 2, KEY_SIZE - 1, KEY_SIZE);
        System.out.printf("send pub terminal key: %s\n", apdu);

        response = channel.transmit(apdu);
        System.out.printf("receive pub card key: %s\n", response);
        var cardPubKey = response.getData();

        // exchange signatures
        apdu = new CommandAPDU((byte) 0x00, SEND_SIGNATURE_APDU_INS, signature[0], (byte) 0x00, signature, 1, SIGNATURE_SIZE - 1, SIGNATURE_SIZE);
        System.out.printf("send terminal signature: %s\n", apdu);

        response = channel.transmit(apdu);
        System.out.printf("receive card signature: %s\n", response);

        var cardVerified = verifyCardMetadata(cardMetaData, cardPubKey, response.getData());
        System.out.printf("card verified: %s\n", cardVerified);
    }

    private boolean verifyCardMetadata(byte[] metadata, byte[] cardPubKey, byte[] signature) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        // verify that the card is not expired yet
        var expiration_date = bytesToDate(Arrays.copyOfRange(metadata, ID_SIZE, ID_SIZE + DATE_SIZE));
        if (expiration_date.isBefore(LocalDate.now())){
            System.out.println("Card has already expired");
            return false;
        }

        Signature sig_object = Signature.getInstance("SHA1withRSA");
        sig_object.initVerify(Utils.readPublicKey(new File("backend_public.pem")));

        sig_object.update(metadata, 0, ID_SIZE + DATE_SIZE);
        sig_object.update(cardPubKey);
        sig_object.update((byte) 0x01);

        return sig_object.verify(signature);
    }
}
