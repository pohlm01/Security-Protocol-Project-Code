package nl.ru.sec_protocol.group5;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.time.LocalDate;
import java.time.LocalTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;

public class ReloadTerminal extends Terminal {


    public ReloadTerminal(int terminalId, OffsetDateTime expirationDate) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        super(new File("reload_public.pem"), new File("reload_private.pem"), new File("reload_signature"), terminalId, expirationDate);
    }

    public static void main(String[] args) throws CardException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException, IOException {
        ReloadTerminal reloadTerminal = new ReloadTerminal(12345, OffsetDateTime.of(LocalDate.of(2023, 7, 1), LocalTime.MIDNIGHT, ZoneOffset.UTC));
        reloadTerminal.start();
    }

    @Override
    public void handleCard(CardChannel channel) throws NoSuchAlgorithmException, CardException, InvalidKeySpecException, SignatureException, InvalidKeyException, IOException {
        var handle = new ReloadHandle(this);
        handle.handleCard(channel);
    }
}
