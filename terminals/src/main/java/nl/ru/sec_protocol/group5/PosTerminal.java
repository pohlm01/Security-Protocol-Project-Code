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

public class PosTerminal extends Terminal {

    public PosTerminal(int terminalId, OffsetDateTime expirationDate) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        super(new File("pos_public.pem"), new File("pos_private.pem"), new File("pos_signature"), terminalId, expirationDate);
    }

    public static void main(String[] args) throws CardException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException, IOException {
        PosTerminal posTerminal = new PosTerminal(2345, OffsetDateTime.of(LocalDate.of(2023, 7, 1), LocalTime.MIDNIGHT, ZoneOffset.UTC));
        posTerminal.start();
    }

    @Override
    public void handleCard(CardChannel channel) throws NoSuchAlgorithmException, CardException, InvalidKeySpecException, SignatureException, InvalidKeyException, IOException {
        var handle = new PosHandle(this);
        handle.handleCard(channel);
    }
}
