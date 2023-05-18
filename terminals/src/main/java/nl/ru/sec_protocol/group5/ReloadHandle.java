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
    }

    /**
     * // TODO
     *
     * @param channel channel to communicate with the card
     * @author Bart Veldman
     */
    private void communicateAmount(CardChannel channel, int amount) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, CardException {
        // send amount
        var dataToSend = new byte[4];
        System.arraycopy(Utils.intToBytes(amount), 0, dataToSend, 0, 4);

        var apdu = new CommandAPDU((byte) 0x00, SEND_AMOUNT_APDU_INS, (byte) 0x00, (byte) 0x00, dataToSend);
        System.out.printf("sending amount: %s\n", apdu);

        var response = channel.transmit(apdu);
        System.out.printf("response: %s\n", response);

        // create signature
        var data = new byte[COUNTER_SIZE + 4 + ID_SIZE];
        System.arraycopy(Utils.intToBytes(cardCounter), 0, data, 0, COUNTER_SIZE);
        System.arraycopy(Utils.intToBytes(amount), 0, data, COUNTER_SIZE, 4);
        System.arraycopy(Utils.intToBytes(cardId), 0, data, COUNTER_SIZE + 4, ID_SIZE);

        var signature_amount = Utils.sign(data, terminal.privKey);

        // send signature
        apdu = new CommandAPDU((byte) 0x00, SEND_AMOUNT_SIGNATURE_APDU_INS, signature_amount[0], (byte) 0x00, signature_amount, 1, SIGNATURE_SIZE - 1, SIGNATURE_SIZE);
        System.out.printf("send amount signature: %s\n", apdu);

        response = channel.transmit(apdu);
        System.out.printf("receive amount signature: %s\n", response);
    }
}
