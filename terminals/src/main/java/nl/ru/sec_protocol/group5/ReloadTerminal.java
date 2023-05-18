package nl.ru.sec_protocol.group5;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.time.LocalDate;

public class ReloadTerminal extends Terminal {
    protected final static byte SEND_ID_DATE_COUNTER_APDU_INS = 0x20;
    protected final static byte SEND_PUB_KEY_APDU_INS = 0x22;
    protected final static byte SEND_BACKEND_SIGNATURE_APDU_INS = 0x24;
    protected final static byte SEND_CHALLENGE_SIGNATURE_APDU_INS = 0x26;
    protected final static byte SEND_AMOUNT_APDU_INS = 0x28;
    protected final static byte SEND_AMOUNT_SIGNATURE_APDU_INS = 0x30;

    protected final int id;
    protected final LocalDate expirationDate;
    protected int counter = 0;

    protected final RSAPublicKey pubKey;
    protected final RSAPrivateKey privKey;
    protected final byte[] signature;


    public ReloadTerminal(int terminalId, LocalDate expirationDate) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        this.expirationDate = expirationDate;
        this.id = terminalId;

        this.pubKey = Utils.readPublicKey(new File("reload_public.pem"));
        this.privKey = Utils.readPrivateKey(new File("reload_private.pem"));
        this.signature = Files.readAllBytes(Paths.get("reload_signature"));
    }

    public static void main(String[] args) throws CardException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException, IOException {
        ReloadTerminal reloadTerminal = new ReloadTerminal(12345, LocalDate.of(2023, 6, 1));
        reloadTerminal.start();
    }

    @Override
    public void handleCard(CardChannel channel) throws NoSuchAlgorithmException, CardException, InvalidKeySpecException, SignatureException, InvalidKeyException, IOException {
        var handle = new ReloadHandle(this);
        handle.handleCard(channel);
    }
}
