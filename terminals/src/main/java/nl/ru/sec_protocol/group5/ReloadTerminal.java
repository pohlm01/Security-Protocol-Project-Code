package nl.ru.sec_protocol.group5;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.time.LocalDate;

import static nl.ru.sec_protocol.group5.Utils.DATE_SIZE;
import static nl.ru.sec_protocol.group5.Utils.ID_SIZE;

public class ReloadTerminal extends Terminal {
    private final static byte SEND_ID_DATE_COUNTER_APDU_INS = 0x08;

    private final int terminalId;
    private final LocalDate expirationDate;
    private static int counter = 0;

    private static RSAPublicKey reloadPubKey;

    static {
        try {
            reloadPubKey = Utils.readPublicKey(new File("reload_public.pem"));
        } catch (Exception e) {
            System.out.println("Failed to read reload_public.pem");
            System.exit(1);
        }
    }

    private static RSAPrivateKey reloadPrivKey;

    static {
        try {
            reloadPrivKey = Utils.readPrivateKey(new File("reload_private.pem"));
        } catch (Exception e) {
            System.out.println("Failed to read reload_private.pem");
            System.exit(1);
        }
    }

    // FIXME find the correct data type and a representation to store this on the disk
    //  We also have to figure out how to produce this signature most conveniently, probably with `openssl`.
    private static byte[] signature;

    static {
        try {
            signature = Files.readAllBytes(Paths.get("reload_signature"));
        } catch (Exception e) {
            System.out.println("Failed to read reload_signature");
            System.exit(1);
        }
    }

    public ReloadTerminal(int terminalId, LocalDate expirationDate) {
        this.expirationDate = expirationDate;
        this.terminalId = terminalId;
    }


    public static void main(String[] args) throws CardException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException {
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
        var dataToSend = new byte[ID_SIZE + DATE_SIZE + 4 + DATE_SIZE];

        // send terminalId || expirationDate || counter || timestamp
        System.arraycopy(Utils.intToBytes(terminalId), 0, dataToSend, 0, ID_SIZE);
        System.arraycopy(Utils.dateToBytes(expirationDate), 0, dataToSend, ID_SIZE, DATE_SIZE);
        System.arraycopy(Utils.intToBytes(counter), 0, dataToSend, ID_SIZE + DATE_SIZE, 4);
        System.arraycopy(Utils.dateToBytes(LocalDate.now()), 0, dataToSend, ID_SIZE + DATE_SIZE + 4, DATE_SIZE);

        var apdu = new CommandAPDU((byte) 0x00, SEND_ID_DATE_COUNTER_APDU_INS, (byte) 0x00, (byte) 0x00, dataToSend);
        System.out.printf("sending terminalId, expirationDate, counter, and timestamp: %s\n", apdu);

        var response = channel.transmit(apdu);
        System.out.printf("response: %s\n", response);
    }
}
