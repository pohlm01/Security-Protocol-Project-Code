package nl.ru.sec_protocol.group5;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import java.io.File;
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

    private static RSAPrivateKey backendPrivKey;

    static {
        try {
            backendPrivKey = Utils.readPrivateKey(new File("backend_private.pem"));
        } catch (Exception e) {
            System.exit(1);
        }
    }

    public static void main(String[] args) throws CardException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException {
        InitTerminal initTerminal = new InitTerminal();
        initTerminal.start();
    }

    private void signCard(CardChannel channel, RSAPrivateKey backendPrivKey, RSAPublicKey cardPublicKey, int cardId, LocalDate expirationDate) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, CardException {
        // cardId || expirationDate || K_c || 0x01
        var data = new byte[ID_SIZE + DATE_SIZE + SIGNATURE_SIZE + 1];

        System.arraycopy(Utils.intToBytes(cardId), 0, data, 0, ID_SIZE);
        System.arraycopy(Utils.dateToBytes(expirationDate), 0, data, ID_SIZE, DATE_SIZE);
        System.arraycopy(cardPublicKey.getModulus().toByteArray(), 0, data, ID_SIZE + DATE_SIZE, KEY_SIZE);
        data[ID_SIZE + DATE_SIZE + SIGNATURE_SIZE] = 0x01;

        Signature signer = Signature.getInstance("SHA1withRSA");
        signer.initSign(backendPrivKey);
        signer.update(data);
        var signature = signer.sign();

        // We are limited to send 255 bytes of data, but the signature is 256 bytes long
        // thue we create a new buffer that contains the whole signature except for the first byte.
        // This missing, fist byte is then sent as the `Param1` of the APDU and resembled later in the card.
        // TODO check why we do not have the same problem with the public backend key send to the card.
        var sendBuffer = new byte[SIGNATURE_SIZE - 1];
        System.arraycopy(signature, 1, sendBuffer, 0, SIGNATURE_SIZE - 1);

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
        var pubModulus = backendPubKey.getModulus().toByteArray();

        // make sure we get rid of the byte indicating the sign by cutting of the first byte
        var data = new byte[KEY_SIZE];
        System.arraycopy(pubModulus, 1, data, 0, data.length);

        var apdu = new CommandAPDU((byte) 0x00, (byte) 0x02, (byte) 0x00, (byte) 0x00, data, KEY_SIZE);
        System.out.printf("generateKeyMaterial: %s\n", apdu);

        var response = channel.transmit(apdu);
        System.out.printf("generateKeyMaterial: %s\n", response);

        if (response.getSW() != 0x9000){
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
        System.out.println("What card ID should be used?");
        var cardId = scanner.nextInt();

        System.out.println("When should the card expire (yyyy-mm-dd)?");
        scanner.nextLine();
        LocalDate expirationDate = LocalDate.parse(scanner.nextLine());


        var pubKeyCard = generateKeyMaterial(channel);
        sendCardIdAndExpirationDate(channel, cardId, expirationDate);
        signCard(channel, backendPrivKey, pubKeyCard, cardId, expirationDate);

        System.out.println("Done...\n\n");
    }
}
