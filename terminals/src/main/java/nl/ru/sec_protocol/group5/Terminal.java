package nl.ru.sec_protocol.group5;

import jnasmartcardio.Smartcardio;

import javax.smartcardio.*;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.time.LocalDate;


public abstract class Terminal {
    private CardTerminal terminal;
    final RSAPublicKey backendPubKey;


    final int id;
    final LocalDate expirationDate;
    int counter = 0;

    final RSAPublicKey pubKey;
    final RSAPrivateKey privKey;
    final byte[] signature;

    public static final BigInteger pubExponent = new BigInteger("65537");
    private static final byte[] aid = new byte[]{0x2D, 0x54, 0x45, 0x53, 0x54, 0x70};
    private static final CommandAPDU select_aid = new CommandAPDU((byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, aid);


    Terminal(File publicKey, File privateKey, File signature, int id, LocalDate expirationDate) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        try {
            Security.addProvider(new Smartcardio());
            CardTerminals terminals = TerminalFactory.getInstance("PC/SC", null, Smartcardio.PROVIDER_NAME).terminals();

            java.util.List<CardTerminal> terminal_list = terminals.list();
            this.terminal = terminal_list.get(0);
        } catch (Exception e) {
            System.out.printf("Error connecting to terminal: %s", e);
            System.exit(1);
        }
        this.id = id;
        this.expirationDate = expirationDate;

        this.pubKey = Utils.readPublicKey(publicKey);
        this.privKey = Utils.readPrivateKey(privateKey);
        if (signature == null) {
            this.signature = null;
        } else {
            this.signature = Files.readAllBytes(signature.toPath());
        }

        this.backendPubKey = Utils.readPublicKey(new File("backend_public.pem"));;
    }

    public void start() throws CardException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException, IOException {
        while (terminal.waitForCardPresent(0)) {
            var channel = terminal.connect("*").getBasicChannel();
            select_applet(channel);
            handleCard(channel);
            terminal.waitForCardAbsent(0);
        }
    }

    abstract public void handleCard(CardChannel channel) throws NoSuchAlgorithmException, CardException, InvalidKeySpecException, SignatureException, InvalidKeyException, IOException;


    private void select_applet(CardChannel channel) throws CardException {
        var response = channel.transmit(select_aid);
        if (response.getSW() != 0x9000) {
            // TODO make sure this is less paranoid and tries again. Currently it crashes very easily, because if the card gets close to the terminal it tries to access it over NFC first.
            System.out.printf("Error selecting the applet: %s\n", response);
            System.exit(1);
        }
    }
}
