package nl.ru.sec_protocol.group5;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
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

import static nl.ru.sec_protocol.group5.Terminal.pubExponent;

public class Utils {
    public final static int ID_SIZE = 4;
    public final static int COUNTER_SIZE = 4;
    public final static int DATE_SIZE = 3;
    public final static int KEY_SIZE = 256;
    public final static int SIGNATURE_SIZE = KEY_SIZE;

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

    public static byte[] dateToBytes(LocalDate date) {
        byte day = (byte) date.getDayOfMonth();
        byte month = (byte) date.getMonth().getValue();
        byte year = (byte) (date.getYear() - 2000);

        return new byte[]{day, month, year};
    }

    public static byte[] intToBytes(int i) {
        ByteBuffer bb = ByteBuffer.allocate(4);
        bb.putInt(i);
        return bb.array();
    }

    public static RSAPublicKey bytesToPubKey(byte[] modulus) throws NoSuchAlgorithmException, InvalidKeySpecException {
        BigInteger m = new BigInteger(1, modulus, 0, KEY_SIZE);

        RSAPublicKeySpec publicSpec = new RSAPublicKeySpec(m, pubExponent);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) factory.generatePublic(publicSpec);
    }

    public static byte[] sign(byte[] content, RSAPrivateKey key) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signer = Signature.getInstance("SHA1withRSA");
        signer.initSign(key);
        signer.update(content);
        return signer.sign();
    }

    public static LocalDate bytesToDate(byte[] date, int offset) {
        return LocalDate.of(date[offset + 2] + 2000, date[offset + 1], date[offset]);
    }

    public static int bytesToInt(byte[] data, int offset){
        ByteBuffer wrapped_id = ByteBuffer.wrap(data, offset, COUNTER_SIZE);
        return wrapped_id.getInt();
    }
}
