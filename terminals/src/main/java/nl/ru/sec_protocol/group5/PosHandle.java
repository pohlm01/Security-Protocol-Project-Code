package nl.ru.sec_protocol.group5;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

public class PosHandle extends Handle {
    public PosHandle(PosTerminal terminal) {
        super(terminal);
    }

    public void handleCard(CardChannel channel) throws CardException, NoSuchAlgorithmException, IOException, InvalidKeySpecException, SignatureException, InvalidKeyException {
        mutualAuthentication(channel, TERMINAL_TYPE_POS);
        //Backend for getting the amount from Cash desk?
        //Step 2,5,10,11,12: communicateAmount of ReloadHandle can be reused after small mods. verSig and logAFin might
        // be necessary to achieve Step 10,11 and 12.
        //Step 13 Adding some I/O
    }
}
