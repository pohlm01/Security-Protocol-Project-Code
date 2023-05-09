package nl.ru.sec_protocol.group5;

import javax.smartcardio.*;

import jnasmartcardio.Smartcardio;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.time.LocalDate;
import java.util.Arrays;
import java.util.Date;

public class Terminal {

    private final Card card;

    public static final BigInteger pubExponent = new BigInteger("65537");
    private static final byte[] aid = new byte[]{0x2D, 0x54, 0x45, 0x53, 0x54, 0x70};

    private static final CommandAPDU select_aid = new CommandAPDU((byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, aid);

    public static void main(String[] args) throws CardException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        Security.addProvider(new Smartcardio());
        CardTerminals terminals = TerminalFactory.getInstance("PC/SC", null, Smartcardio.PROVIDER_NAME).terminals();

        java.util.List<CardTerminal> terminal_list = terminals.list();
        CardTerminal terminal = terminal_list.get(0);
        Card card = terminal.connect("*");

        Terminal t = new Terminal(card);
        t.initializeCard(12345, LocalDate.now());

//        System.out.println(Arrays.toString(card.getATR().getBytes()));
//        System.out.println(new String(card.getATR().getHistoricalBytes()));
    }

    Terminal(Card card) {
        this.card = card;
    }

    public void initializeCard(int card_id, LocalDate expiration_date) throws NoSuchAlgorithmException, CardException, InvalidKeySpecException {
        var channel = card.getBasicChannel();

        var response = channel.transmit(select_aid);
        System.out.println(response);

        var pub_key_card = generateKeyMaterial(channel);

    }

    /**
    @return Public key generated on the card
     **/
    private RSAPublicKey generateKeyMaterial(CardChannel channel) throws NoSuchAlgorithmException, CardException, InvalidKeySpecException {
        var keyGenerator = KeyPairGenerator.getInstance("RSA");

        keyGenerator.initialize(2048);
        var keyPair = keyGenerator.generateKeyPair();

        var publicKey = (RSAPublicKey) keyPair.getPublic();
        var pubModulus = publicKey.getModulus().toByteArray();


        var apdu = new CommandAPDU((byte) 0x00, (byte) 0x02, (byte) 0x00, (byte) 0x00, pubModulus,2048 / 8);
        System.out.println(apdu);

        var response = channel.transmit(apdu);
        System.out.println(response);
        System.out.println(Arrays.toString(response.getData()));

        BigInteger modulus = new BigInteger(1, response.getData(), 0, 2048/8);

        RSAPublicKeySpec publicSpec = new RSAPublicKeySpec(modulus, pubExponent);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) factory.generatePublic(publicSpec);
    }

    private void sendCardIdAndExpirationDate(CardChannel channel, int cardId, Date expirationDate){

    }

    private byte[] intToBytes( final int i ) {
        ByteBuffer bb = ByteBuffer.allocate(4);
        bb.putInt(i);
        return bb.array();
    }

    private boolean select_applet(CardChannel channel) throws CardException {
        var response = channel.transmit(select_aid);
        return response.getSW() == 9000;
    }
}
