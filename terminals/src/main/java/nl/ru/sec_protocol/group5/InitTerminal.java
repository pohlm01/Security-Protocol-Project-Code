package nl.ru.sec_protocol.group5;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.time.LocalDate;
import java.time.LocalTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Scanner;

import static nl.ru.sec_protocol.group5.Utils.*;

public class InitTerminal extends Terminal {
    private final RSAPrivateKey backendPrivKey;


    private InitTerminal(String backend_priv_key_name) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        super(null, null, null, 0, null);
        backendPrivKey = Utils.readPrivateKey(new File(backend_priv_key_name));
    }

    public static void main(String[] args) throws CardException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException, IOException {
        InitTerminal initTerminal = new InitTerminal("backend_private.pem");
        initTerminal.start();
    }

    /**
     * Signs the card metadata and public key together with the domain separator 0x01 using the private key of the
     * backend and sends to the card
     *
     * @param channel        to communicate with the card
     * @param backendPrivKey to sign
     * @param cardPublicKey  to be signed
     * @param cardId         to be signed
     * @param expirationDate to be signed
     * @author Maximilian Pohl
     */
    private void signCard(CardChannel channel, RSAPrivateKey backendPrivKey, RSAPublicKey cardPublicKey, int cardId, OffsetDateTime expirationDate) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, CardException {
        // cardId || expirationDate || K_c || 0x01
        var data = new byte[ID_SIZE + EPOCH_SIZE + KEY_SIZE + 1];

        System.arraycopy(Utils.intToBytes(cardId), 0, data, 0, ID_SIZE);
        System.arraycopy(Utils.dateToBytes(expirationDate), 0, data, ID_SIZE, EPOCH_SIZE);
        System.arraycopy(cardPublicKey.getModulus().toByteArray(), 1, data, ID_SIZE + EPOCH_SIZE, KEY_SIZE);
        data[ID_SIZE + EPOCH_SIZE + SIGNATURE_SIZE] = 0x01;

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
     * @author Maximilian Pohl
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

    private void sendCardIdAndExpirationDate(CardChannel channel, int cardId, OffsetDateTime expirationDate) throws CardException {
        var data = new byte[ID_SIZE + EPOCH_SIZE];
        System.arraycopy(Utils.intToBytes(cardId), 0, data, 0, ID_SIZE);
        System.arraycopy(Utils.dateToBytes(expirationDate), 0, data, ID_SIZE, EPOCH_SIZE);

        var apdu = new CommandAPDU((byte) 0x00, (byte) 0x04, (byte) 0x00, (byte) 0x00, data);
        var response = channel.transmit(apdu);
        System.out.printf("sendCardIdAndExpirationDate: %s\n", response);
    }

    @Override
    public void handleCard(CardChannel channel) throws NoSuchAlgorithmException, CardException, InvalidKeySpecException, SignatureException, InvalidKeyException {
        var scanner = new Scanner(System.in);
        System.out.println("What card ID should be used? (or press Enter to use default)");
        int cardId;
        var input = scanner.nextLine();
        if (input.isEmpty()) {
            cardId = 123;
            System.out.printf("Using default card ID '%s'\n", cardId);
        } else {
            cardId = Integer.parseInt(input);
        }

        System.out.println("When should the card expire (yyyy-mm-dd)? (or press Enter to use default)");
        input = scanner.nextLine();
        OffsetDateTime expirationDate;
        if (input.isEmpty()) {
            expirationDate = OffsetDateTime.of(LocalDate.parse("2033-10-10"), LocalTime.MIDNIGHT, ZoneOffset.UTC);
            System.out.printf("Using default expiration date '%s'\n", expirationDate);
        } else {
            expirationDate = OffsetDateTime.of(LocalDate.parse(input), LocalTime.MIDNIGHT, ZoneOffset.UTC);
        }


        var pubKeyCard = generateKeyMaterial(channel);
        sendCardIdAndExpirationDate(channel, cardId, expirationDate);
        signCard(channel, backendPrivKey, pubKeyCard, cardId, expirationDate);

        System.out.println("Done...\n\n");
    }
}
