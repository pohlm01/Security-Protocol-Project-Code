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
import static nl.ru.sec_protocol.group5.Utils.SIGNATURE_SIZE;

public class ReloadHandle extends Handle {
    public ReloadHandle(ReloadTerminal terminal) {
        super(terminal);
    }

    public void handleCard(CardChannel channel) throws CardException, NoSuchAlgorithmException, IOException, InvalidKeySpecException, SignatureException, InvalidKeyException {
        mutualAuthentication(channel, TERMINAL_TYPE_RELOAD);

        var scanner = new Scanner(System.in);
        System.out.println("What amount should be added to the card's balance?");
        var amount = scanner.nextInt();
        communicateAmount(channel, amount);

        finalizeReload(channel, amount);
    }

    /**
     * Signs the amount with which to increase the card's balance and sends the amount and signature to the card
     *
     * @param channel channel to communicate with the card
     * @param amount amount to increase the card's balance with
     * @author Bart Veldman
     */
    private void communicateAmount(CardChannel channel, int amount) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, CardException {
        // send amount
        var apdu = new CommandAPDU((byte) 0x00, SEND_AMOUNT_APDU_INS, (byte) 0x00, (byte) 0x00, Utils.intToBytes(amount));

        var response = channel.transmit(apdu);
        if (response.getSW() != 0x9000) {
            System.out.println("An error occurred while sending the amount: " + response.getSW());
            System.exit(1);
        }

        // create signature
        var data = new byte[COUNTER_SIZE + 4 + ID_SIZE];
        cardCounter += 1;
        System.arraycopy(Utils.intToBytes(cardCounter), 0, data, 0, COUNTER_SIZE);
        System.arraycopy(Utils.intToBytes(amount), 0, data, COUNTER_SIZE, 4);
        System.arraycopy(Utils.intToBytes(cardId), 0, data, COUNTER_SIZE + 4, ID_SIZE);

        var signatureAmount = Utils.sign(data, terminal.privKey);

        // send signature, receive and verify signature
        apdu = new CommandAPDU((byte) 0x00, SEND_RELOAD_AMOUNT_SIGNATURE_APDU_INS, signatureAmount[0], (byte) 0x00, signatureAmount, 1, SIGNATURE_SIZE - 1, SIGNATURE_SIZE);
        response = channel.transmit(apdu);

        if (!verifyAmountSignature(response.getData(), amount, cardPubKey, terminal.id, cardCounter, cardId)) {
            System.out.println("An error occurred while verifying the amount");
            System.exit(1);
        }
    }

    /**
     * Signs the amount, card counter and card id and verifies successful finalization of the reload protocol
     *
     * @param channel channel to communicate with the card
     * @param amount amount to increase the card's balance with
     * @author Bart Veldman
     */
    private void finalizeReload(CardChannel channel, int amount) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, CardException {
        // pretend we log the transaction here

        var data= new byte[COUNTER_SIZE + AMOUNT_SIZE + ID_SIZE];
        cardCounter += 1;
        System.arraycopy(Utils.intToBytes(cardCounter), 0, data, 0, COUNTER_SIZE);
        System.arraycopy(Utils.intToBytes(amount), 0, data, COUNTER_SIZE, AMOUNT_SIZE);
        System.arraycopy(Utils.intToBytes(cardId), 0, data, COUNTER_SIZE + AMOUNT_SIZE, ID_SIZE);

        var signatureAmount = Utils.sign(data, terminal.privKey);

        var apdu = new CommandAPDU((byte) 0x00, SEND_AMOUNT_LOG_SIGNATURE_APDU_INS, signatureAmount[0], (byte) 0x00, signatureAmount, 1, SIGNATURE_SIZE - 1);

        var response = channel.transmit(apdu);
        if (response.getSW() != 0x9000) {
            System.out.println("Reloading failed");
            System.exit(1);
        }
        System.out.println("Card reload successful. Added " + amount + " to the card's balance");
    }
}
