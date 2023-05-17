package nl.ru.sec_protocol.group5;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.time.LocalDate;
import java.util.Scanner;

import static nl.ru.sec_protocol.group5.Utils.*;

public class InitTerminal extends Terminal {

    private final RSAPrivateKey backendPrivKey;


    private InitTerminal(String backend_priv_key_name) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        backendPrivKey = Utils.readPrivateKey(new File(backend_priv_key_name));
    }

    public static void main(String[] args) throws CardException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException, IOException {
        InitTerminal initTerminal = new InitTerminal("backend_private.pem");
        initTerminal.start();
    }

    private void signCard(CardChannel channel, RSAPrivateKey backendPrivKey, RSAPublicKey cardPublicKey, int cardId, LocalDate expirationDate) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, CardException {
        // cardId || expirationDate || K_c || 0x01
        var data = new byte[ID_SIZE + DATE_SIZE + KEY_SIZE + 1];

        System.arraycopy(Utils.intToBytes(cardId), 0, data, 0, ID_SIZE);
        System.arraycopy(Utils.dateToBytes(expirationDate), 0, data, ID_SIZE, DATE_SIZE);
        System.arraycopy(cardPublicKey.getModulus().toByteArray(), 1, data, ID_SIZE + DATE_SIZE, KEY_SIZE);
        data[ID_SIZE + DATE_SIZE + SIGNATURE_SIZE] = 0x01;

        var signature = Utils.sign(data, backendPrivKey);

        // We are limited to send 255 bytes of data, but the signature is 256 bytes long
        // thue we create a new buffer that contains the whole signature except for the first byte.
        // This missing, fist byte is then sent as the `Param1` of the APDU and resembled later in the card.
        var apdu = new CommandAPDU((byte) 0x00, (byte) 0x06, signature[0], (byte) 0x00, signature, 1, SIGNATURE_SIZE - 1);
        System.out.printf("signCard: %s\n", apdu);

        var response = channel.transmit(apdu);
        System.out.printf("signCard: %s\n", response);
    }

    /**
     * @return Public key generated on the card
     **/
    private RSAPublicKey generateKeyMaterial(CardChannel channel) throws NoSuchAlgorithmException, CardException, InvalidKeySpecException {
        var pubModulus = backendPubKey.getModulus().toByteArray();

        // make sure we get rid of the byte indicating the sign by cutting of the first byte.
        // As the key is 256 byte in size, but the APDU data part can be max 255 bytes in size, the first byte goes into the param 1 of the APDU.
        var apdu = new CommandAPDU((byte) 0x00, (byte) 0x02, pubModulus[1], (byte) 0x00, pubModulus, 2, KEY_SIZE - 1, KEY_SIZE);
        System.out.printf("generateKeyMaterial: %s\n", apdu);

        var response = channel.transmit(apdu);
        System.out.printf("generateKeyMaterial: %s\n", response);

        if (response.getSW() != 0x9000) {
            System.out.println("Generating keys failed. Is the card already initialized?");
            System.exit(1);
        }

        BigInteger modulus = new BigInteger(1, response.getData(), 0, KEY_SIZE);

        RSAPublicKeySpec publicSpec = new RSAPublicKeySpec(modulus, pubExponent);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) factory.generatePublic(publicSpec);
    }

    private void sendCardIdAndExpirationDate(CardChannel channel, int cardId, LocalDate expirationDate) throws CardException {
        var data = new byte[ID_SIZE + DATE_SIZE];
        System.arraycopy(Utils.intToBytes(cardId), 0, data, 0, ID_SIZE);
        System.arraycopy(Utils.dateToBytes(expirationDate), 0, data, ID_SIZE, DATE_SIZE);

        var apdu = new CommandAPDU((byte) 0x00, (byte) 0x04, (byte) 0x00, (byte) 0x00, data);
        var response = channel.transmit(apdu);
        System.out.printf("sendCardIdAndExpirationDate: %s\n", response);
    }

    @Override
    public void handleCard(CardChannel channel) throws NoSuchAlgorithmException, CardException, InvalidKeySpecException, SignatureException, InvalidKeyException {
        var scanner = new Scanner(System.in);
        System.out.println("What card ID should be used? (or press Enter)");
        int cardId;
        // FIXME .hasNext() does not work for me ):
        if (!scanner.hasNext()) {
            cardId = 123;
        }
        else {
            cardId = scanner.nextInt();
        }

        // FIXME .hasNext() does not work for me ):
        LocalDate expirationDate;
        System.out.println("When should the card expire (yyyy-mm-dd)? (or press Enter)");
        if (!scanner.hasNext()) {
            scanner.nextLine();
            expirationDate = LocalDate.parse(scanner.nextLine());
        }
        else {
            expirationDate = LocalDate.parse("2033-10-10");
        }


        var pubKeyCard = generateKeyMaterial(channel);
        sendCardIdAndExpirationDate(channel, cardId, expirationDate);
        signCard(channel, backendPrivKey, pubKeyCard, cardId, expirationDate);

        System.out.println("Done...\n\n");
    }
}
