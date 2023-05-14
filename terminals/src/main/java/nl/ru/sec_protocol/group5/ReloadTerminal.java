package nl.ru.sec_protocol.group5;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.time.LocalDate;
import java.util.Arrays;

import static nl.ru.sec_protocol.group5.Utils.*;

public class ReloadTerminal extends Terminal {
    private final static byte SEND_ID_DATE_COUNTER_APDU_INS = 0x08;
    private final static byte SEND_PUB_KEY_APDU_INS = 0x0A;
    private final static byte SEND_SIGNATURE_APDU_INS = 0x0C;

    private final int terminalId;
    private final LocalDate expirationDate;
    private static int counter = 0;

    private final RSAPublicKey reloadPubKey;
    private final RSAPrivateKey reloadPrivKey;
    private final byte[] signature;


    public ReloadTerminal(int terminalId, LocalDate expirationDate) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        this.expirationDate = expirationDate;
        this.terminalId = terminalId;

        this.reloadPubKey = Utils.readPublicKey(new File("reload_public.pem"));
        this.reloadPrivKey = Utils.readPrivateKey(new File("reload_private.pem"));
        this.signature = Files.readAllBytes(Paths.get("reload_signature"));
    }


    public static void main(String[] args) throws CardException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException, IOException {
        ReloadTerminal reloadTerminal = new ReloadTerminal(12345, LocalDate.of(2023, 6, 1));
        reloadTerminal.start();
    }

    @Override
    public void handleCard(CardChannel channel) throws NoSuchAlgorithmException, CardException, InvalidKeySpecException, SignatureException, InvalidKeyException {
        authenticateToCard(channel);
    }

    private void authenticateToCard(CardChannel channel) throws CardException {
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

        // exchange public keys
        var modulus = this.reloadPubKey.getModulus().toByteArray();
        // We start to copy from the third byte of the modulus onwards
        // This is because the fist byte is unnecessary because it only indicates the sign, which is always positive in our case
        // The second byte gets cut off because we can only send 255 bytes as payload, but the key is 256 bytes in size.
        // Therefore, we transmit the first byte of the key (second in the byte array) as Param1 of the APDU.
        apdu = new CommandAPDU((byte) 0x00, SEND_PUB_KEY_APDU_INS, modulus[1], (byte) 0x00, modulus, 2, KEY_SIZE - 1, KEY_SIZE);
        System.out.printf("send pub terminal key: %s\n", apdu);

        response = channel.transmit(apdu);
        System.out.printf("receive pub card key: %s\n", response);

        // exchange signatures
        apdu = new CommandAPDU((byte) 0x00, SEND_SIGNATURE_APDU_INS, signature[0], (byte) 0x00, signature, 1, SIGNATURE_SIZE - 1, SIGNATURE_SIZE);
        System.out.printf("send terminal signature: %s\n", apdu);

        response = channel.transmit(apdu);
        System.out.printf("receive card signature: %s\n", response);
        System.out.println(Arrays.toString(response.getData()));
    }
}