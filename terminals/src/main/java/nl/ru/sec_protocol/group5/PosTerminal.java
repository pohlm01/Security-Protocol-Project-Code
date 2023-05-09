package nl.ru.sec_protocol.group5;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import java.io.File;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;

public class PosTerminal extends Terminal{

    private static int counter = 0;

    private static RSAPublicKey posPubKey;

    static {
        try {
            posPubKey = Utils.readPublicKey(new File("pos_public.pem"));
        } catch (Exception e) {
            System.exit(1);
        }
    }
    private static RSAPrivateKey posPrivKey;

    static {
        try {
            posPrivKey = Utils.readPrivateKey(new File("pos_private.pem"));
        } catch (Exception e) {
            System.exit(1);
        }
    }
    // FIXME find the correct data type and a representation to store this on the disk
    //  We also have to figure out how to produce this signature most conveniently, probably with `openssl`.
    private static byte[] signature;


    public static void main(String[] args) throws CardException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException {
        InitTerminal initTerminal = new InitTerminal();
        initTerminal.start();
    }

    @Override
    public void handleCard(CardChannel channel) throws NoSuchAlgorithmException, CardException, InvalidKeySpecException, SignatureException, InvalidKeyException {

    }
}
