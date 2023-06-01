package nl.ru.sec_protocol.group5;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Base64;

import static nl.ru.sec_protocol.group5.Terminal.pubExponent;

public class Utils {
    public final static int ID_SIZE = 4;
    public final static int COUNTER_SIZE = 4;
    public final static int DATE_SIZE = 3;
    public final static int KEY_SIZE = 256;
    public final static int SIGNATURE_SIZE = KEY_SIZE;

    /**
     * @param file File containing the public RSA key to read
     * @author Maximilian Pohl
     */
    public static RSAPublicKey readPublicKey(File file) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        if (file == null) {
            return null;
        }

        KeyFactory factory = KeyFactory.getInstance("RSA");

        try (FileReader keyReader = new FileReader(file);
             PemReader pemReader = new PemReader(keyReader)) {

            PemObject pemObject = pemReader.readPemObject();
            byte[] content = pemObject.getContent();
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(content);
            return (RSAPublicKey) factory.generatePublic(pubKeySpec);
        }
    }

    /**
     * @param file File containing the private RSA key to read
     * @author Maximilian Pohl
     */
    public static RSAPrivateKey readPrivateKey(File file) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        if (file == null) {
            return null;
        }

        KeyFactory factory = KeyFactory.getInstance("RSA");

        try (FileReader keyReader = new FileReader(file);
             PemReader pemReader = new PemReader(keyReader)) {

            PemObject pemObject = pemReader.readPemObject();
            byte[] content = pemObject.getContent();
            PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(content);
            return (RSAPrivateKey) factory.generatePrivate(privKeySpec);
        }
    }

    /**
     * Converts the given date into some internal byte representation.
     * <p>
     * We use the following representation:
     * <ul>
     *  <li>First byte: day</li>
     *  <li>Second byte: month</li>
     *  <li>Third byte: current year - 2000</li>
     * </ul>
     *
     * @param date date to convert
     * @author Maximilian Pohl
     */
    public static byte[] dateToBytes(LocalDate date) {
        byte day = (byte) date.getDayOfMonth();
        byte month = (byte) date.getMonth().getValue();
        byte year = (byte) (date.getYear() - 2000);

        return new byte[]{day, month, year};
    }

    /**
     * Converts the given int into a byte array of length 4.
     *
     * @param i int to convert
     * @author Maximilian Pohl
     */
    public static byte[] intToBytes(int i) {
        ByteBuffer bb = ByteBuffer.allocate(4);
        bb.putInt(i);
        return bb.array();
    }

    /**
     * Converts the modulus given as byte array into an RSA public key using the default public exponent 65537
     *
     * @param modulus modulus of the public RSA key
     * @author Maximilian Pohl
     */
    public static RSAPublicKey bytesToPubKey(byte[] modulus) throws NoSuchAlgorithmException, InvalidKeySpecException {
        BigInteger m = new BigInteger(1, modulus, 0, KEY_SIZE);

        RSAPublicKeySpec publicSpec = new RSAPublicKeySpec(m, pubExponent);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) factory.generatePublic(publicSpec);
    }

    /**
     * Signs the given data with the given private RSA key using the SHA1 with RSA and PKCS#1 padding
     *
     * @param content content to sign
     * @param key private RSA key used for signing
     * @author Maximilian Pohl
     */
    public static byte[] sign(byte[] content, RSAPrivateKey key) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signer = Signature.getInstance("SHA1withRSA");
        signer.initSign(key);
        signer.update(content);
        return signer.sign();
    }

    /**
     * Inverts the function {@link #dateToBytes(LocalDate)} function
     *
     * @param date date represented as byte array of length 3
     * @param offset offset of there in the array the date starts
     * @return date recovered from the byte array
     * @author Maximilian Pohl
     */
    public static LocalDate bytesToDate(byte[] date, int offset) {
        return LocalDate.of(date[offset + 2] + 2000, date[offset + 1], date[offset]);
    }


    /**
     * Inverts the function {@link #intToBytes(int)} function
     *
     * @param data int represented as byte array of length 4
     * @param offset offset of there in the array the int starts
     * @return int recovered from the byte array
     * @author Maximilian Pohl
     */
    public static int bytesToInt(byte[] data, int offset) {
        ByteBuffer wrapped_id = ByteBuffer.wrap(data, offset, COUNTER_SIZE);
        return wrapped_id.getInt();
    }

    /**
     * parses a CRL and checks if it is expired
     *
     * @return a list of all blocked card IDs
     * @author Maximilian Pohl
     */
    public static ArrayList<Integer> parseCrl() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        var result = new ArrayList<Integer>();

        if (!checkCrlSignature()) {
            System.out.println("Invalid CRL signature");
            System.exit(1);
        }

        try (var reader = new BufferedReader(new FileReader("CRL"))) {
            var expirationDate = LocalDate.parse(reader.readLine());
            if (expirationDate.isBefore(LocalDate.now())) {
                System.out.println("CRL is expired");
                System.exit(1);
            }

            while (true) {
                var line = reader.readLine();
                try {
                    var cardId = Integer.parseInt(line);
                    result.add(cardId);
                } catch (Exception e) {
                    break;
                }
            }
        } catch (Exception e) {
            System.out.println("failed reading CRL");
            e.printStackTrace();
        }
        return result;
    }

    /**
     * checks the CRL signature
     *
     * @return true if the signature is valid, false otherwise
     * @author Maximilian Pohl
     */
    private static boolean checkCrlSignature() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        var backendPubKey = readPublicKey(new File("backend_public.pem"));

        try (var crl = new FileInputStream("CRL")) {
            var content = crl.readAllBytes();

            // the -1 ensures we ignore the '\n' between the card IDs and the signature
            var dataToVerify = new byte[(int) (content.length - 344 - 1)];

            System.arraycopy(content, 0, dataToVerify, 0, dataToVerify.length);
            var encodedSignature = new byte[344];
            var signature = new byte[256];

            // the +1 ensures we ignore the '\n' between the card IDs and the signature
            System.arraycopy(content, dataToVerify.length + 1, encodedSignature, 0, 344);
            signature = Base64.getDecoder().decode(encodedSignature);
            return verifySignature(signature, dataToVerify, backendPubKey);
        } catch (Exception e) {
            System.out.println("Failed reading CRL. Make sure you created a valid CRL first. Use the Backend for that.");
            e.printStackTrace();
        }
        return false;
    }

    /**
     * generic method to verify a signature
     *
     * @param signature byte array containing the signature
     * @param signedData data that should have been signed
     * @param publicKey public key corresponding to the private key the data have been signed with
     * @return true if the signature is valid, false otherwise
     * @author Maximilian Pohl
     */
    private static boolean verifySignature(byte[] signature, byte[] signedData, RSAPublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sig_object = Signature.getInstance("SHA1withRSA");
        sig_object.initVerify(publicKey);

        sig_object.update(signedData);

        return sig_object.verify(signature);
    }
}
