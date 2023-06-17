package nl.ru.sec_protocol.group5;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;

import static nl.ru.sec_protocol.group5.Utils.*;

public class PosHandle extends Handle {
    public PosHandle(PosTerminal terminal) {
        super(terminal);
    }

    public void handleCard(CardChannel channel) throws CardException, NoSuchAlgorithmException, IOException, InvalidKeySpecException, SignatureException, InvalidKeyException {
        mutualAuthentication(channel, TERMINAL_TYPE_POS);

        // Step 1 - Payment protocol
        var scanner = new Scanner(System.in);
        System.out.println("What amount should be payed?");
        var amount = scanner.nextInt();
        communicateAmount(channel, amount);
    }

    /**
     * Signs the amount to pay together with the card counter and card id and verifies successful finalization of the pos protocol
     *
     * @param channel channel to communicate with the card
     * @param amount amount to be paid in cents
     * @author Felix Moelder
     */
    private void communicateAmount(CardChannel channel, int amount) throws CardException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        // send amount
        // Step 2 - Payment protocol
        var apdu = new CommandAPDU((byte) 0x00, SEND_AMOUNT_APDU_INS, (byte) 0x00, (byte) 0x00, Utils.intToBytes(amount));
        System.out.printf("sending amount to pay: %s\n", apdu);

        var response = channel.transmit(apdu);
        System.out.printf("response: %s\n", response);

        // create signature
        // Step 5 - Payment protocol
        var data = new byte[COUNTER_SIZE + AMOUNT_SIZE + ID_SIZE];
        cardCounter += 1;
        System.arraycopy(Utils.intToBytes(cardCounter), 0, data, 0, COUNTER_SIZE);
        System.arraycopy(Utils.intToBytes(amount), 0, data, COUNTER_SIZE, AMOUNT_SIZE);
        System.arraycopy(Utils.intToBytes(cardId), 0, data, COUNTER_SIZE + AMOUNT_SIZE, ID_SIZE);

        var signatureAmount = Utils.sign(data, terminal.privKey);

        // Step 5 send signature
        apdu = new CommandAPDU((byte) 0x00, SEND_PAYMENT_AMOUNT_SIGNATURE_APDU_INS, signatureAmount[0], (byte) 0x00, signatureAmount, 1, SIGNATURE_SIZE - 1, SIGNATURE_SIZE);
        System.out.printf("send amount signature: %s\n", apdu);

        response = channel.transmit(apdu);
        System.out.printf("receive amount signature: %s\n", response);

        // verify signature
        // Step 10 + 11 - Payment protocol
        var signatureVerified = verifyAmountSignature(response.getData(), terminal.id, cardCounter, amount, cardId, timeStamp, cardPubKey);
        System.out.printf("signatures verified: %s\n", signatureVerified);

        // Step 12 - Payment protocol
        // TODO log the transaction details

        System.out.printf("Successfully payed %s\n\n", amount);

        // Step 13 - Payment protocol
        // TODO show success on terminal display
    }
}
