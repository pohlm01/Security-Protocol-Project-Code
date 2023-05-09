package nl.ru.sec_protocol.group5;

import javax.smartcardio.*;

import jnasmartcardio.Smartcardio;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.time.LocalDate;

public class Terminal {

    private final Card card;

    private RSAPrivateKey backendPrivKey; // TODO this should live longer than the program, e.g., in a file
    private RSAPublicKey backendPubKey; // TODO this should live longer than the program, e.g., in a file

    public static final BigInteger pubExponent = new BigInteger("65537");
    private static final byte[] aid = new byte[]{0x2D, 0x54, 0x45, 0x53, 0x54, 0x70};

    private static final CommandAPDU select_aid = new CommandAPDU((byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, aid);

    public static void main(String[] args) throws CardException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, SignatureException, InvalidKeyException {
        Security.addProvider(new Smartcardio());
        CardTerminals terminals = TerminalFactory.getInstance("PC/SC", null, Smartcardio.PROVIDER_NAME).terminals();

        java.util.List<CardTerminal> terminal_list = terminals.list();
        CardTerminal terminal = terminal_list.get(0);
        Card card = terminal.connect("*");

        Terminal t = new Terminal(card);
        t.initializeCard(12345, LocalDate.of(2030, 1, 31));
    }

    Terminal(Card card) {
        this.card = card;
    }

    public void initializeCard(int cardId, LocalDate expirationDate) throws NoSuchAlgorithmException, CardException, InvalidKeySpecException, SignatureException, InvalidKeyException {
        var channel = card.getBasicChannel();

        select_applet(channel);

        var pubKeyCard = generateKeyMaterial(channel);
        sendCardIdAndExpirationDate(channel, cardId, expirationDate);

        signCard(channel, backendPrivKey, pubKeyCard, cardId, expirationDate);
    }

    private void signCard(CardChannel channel, RSAPrivateKey backendPrivKey, RSAPublicKey cardPublicKey, int cardId, LocalDate expirationDate) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, CardException {
        // cardId || expirationDate || K_c || 0x01
        var data = new byte[4 + 3 + (2048 / 8) + 1]; // TODO introduce constants for all these values

        System.arraycopy(intToBytes(cardId), 0, data, 0, 4);
        System.arraycopy(dateToBytes(expirationDate), 0, data, 4, 3);
        System.arraycopy(cardPublicKey.getModulus().toByteArray(), 0, data, 3 + 4, 2048 / 8);
        data[4 + 3 + (2048 / 8)] = 0x01;

        Signature signer = Signature.getInstance("SHA1withRSA");
        signer.initSign(backendPrivKey);
        signer.update(data);
        var signature = signer.sign();

        // We are limited to send 255 bytes of data, but the signature is 256 bytes long
        // thue we create a new buffer that contains the whole signature except for the first byte.
        // This missing, fist byte is then sent as the `Param1` of the APDU and resembled later in the card.
        // TODO check why we do not have the same problem with the public backend key send to the card.
        var sendBuffer = new byte[255];
        System.arraycopy(signature, 1, sendBuffer, 0, 255);

        System.out.printf("Signature length: %s\n", signature.length);

        var apdu = new CommandAPDU((byte) 0x00, (byte) 0x06, signature[0], (byte) 0x00, sendBuffer);
        System.out.printf("signCard: %s\n", apdu);

        var response = channel.transmit(apdu);
        System.out.printf("signCard: %s\n", response);
    }

    /**
     * @return Public key generated on the card
     **/
    private RSAPublicKey generateKeyMaterial(CardChannel channel) throws NoSuchAlgorithmException, CardException, InvalidKeySpecException {
        var keyGenerator = KeyPairGenerator.getInstance("RSA");

        keyGenerator.initialize(2048);
        var keyPair = keyGenerator.generateKeyPair();

        backendPrivKey = (RSAPrivateKey) keyPair.getPrivate();

        backendPubKey = (RSAPublicKey) keyPair.getPublic();
        var pubModulus = backendPubKey.getModulus().toByteArray();

        // make sure we get rid of the byte indicating the sign by cutting of the first byte
        var data = new byte[2048 / 8];
        System.arraycopy(pubModulus, 1, data, 0, data.length);

        var apdu = new CommandAPDU((byte) 0x00, (byte) 0x02, (byte) 0x00, (byte) 0x00, data, 2048 / 8);
        System.out.printf("generateKeyMaterial: %s\n", apdu);

        var response = channel.transmit(apdu);
        System.out.printf("generateKeyMaterial: %s\n", response);

        BigInteger modulus = new BigInteger(1, response.getData(), 0, 2048 / 8);

        RSAPublicKeySpec publicSpec = new RSAPublicKeySpec(modulus, pubExponent);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) factory.generatePublic(publicSpec);
    }

    private void sendCardIdAndExpirationDate(CardChannel channel, int cardId, LocalDate expirationDate) throws CardException {
        var data = new byte[4 + 3];
        System.arraycopy(intToBytes(cardId), 0, data, 0, 4);
        System.arraycopy(dateToBytes(expirationDate), 0, data, 4, 3);

        var apdu = new CommandAPDU((byte) 0x00, (byte) 0x04, (byte) 0x00, (byte) 0x00, data);
        var response = channel.transmit(apdu);
        System.out.printf("sendCardIdAndExpirationDate: %s\n", response);
    }

    private byte[] dateToBytes(LocalDate date) {
        byte day = (byte) date.getDayOfMonth();
        byte month = (byte) date.getMonth().getValue();
        byte year = (byte) (date.getYear() - 2000);

        return new byte[]{day, month, year};
    }

    private byte[] intToBytes(int i) {
        ByteBuffer bb = ByteBuffer.allocate(4);
        bb.putInt(i);
        return bb.array();
    }

    private boolean select_applet(CardChannel channel) throws CardException {
        var response = channel.transmit(select_aid);
        return response.getSW() == 9000;
    }
}
