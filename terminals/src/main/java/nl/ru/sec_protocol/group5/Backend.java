package nl.ru.sec_protocol.group5;

import java.io.*;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.time.LocalDate;
import java.util.Base64;
import java.util.Scanner;

public class Backend {
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, SignatureException, InvalidKeyException {
        while (true) {
            System.out.println("What would you like to do. Please choose by typing in a number");
            System.out.println("  1. Generate Terminal keys");
            System.out.println("  2. Sign Terminal");
            System.out.println("  3. exit");

            var scanner = new Scanner(System.in);
            switch (scanner.nextInt()) {
                case 1 -> generateTerminalKeys();
                case 2 -> signTerminal();
                case 3 -> System.exit(0);
                default -> {
                }
            }
        }
    }

    private static void generateTerminalKeys() throws NoSuchAlgorithmException, IOException {
        System.out.println("What kind terminal should the keys be generated for?");
        System.out.println("  1. POS (filename: `pos_{public/private}.pem`)");
        System.out.println("  2. Reload (filename: `reload_{public/private}.pem`)");
        System.out.println("  3. Give your own filename (filename: `<your_input>_{public/private}.pem`)");

        String filename_pub;
        String filename_priv;
        var scanner = new Scanner(System.in);
        switch (scanner.nextInt()) {
            case 1 -> {
                filename_pub = "pos_public.pem";
                filename_priv = "pos_private.pem";
            }
            case 2 -> {
                filename_pub = "reload_public.pem";
                filename_priv = "reload_private.pem";
            }
            default -> {
                System.out.println("Please provide a name");
                var name = scanner.nextLine();
                filename_pub = name + "_public.pem";
                filename_priv = name + "_private.pem";
            }
        }


        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        RSAPublicKey pub = (RSAPublicKey) kp.getPublic();
        RSAPrivateKey pvt = (RSAPrivateKey) kp.getPrivate();

        Base64.Encoder encoder = Base64.getEncoder();

        try (Writer out = new FileWriter(filename_priv)) {
            out.write("-----BEGIN RSA PRIVATE KEY-----\n");
            out.write(encoder.encodeToString(pvt.getEncoded()));
            out.write("\n-----END RSA PRIVATE KEY-----\n");
        }

        try (var out = new FileWriter(filename_pub)) {
            out.write("-----BEGIN RSA PUBLIC KEY-----\n");
            out.write(encoder.encodeToString(pub.getEncoded()));
            out.write("\n-----END RSA PUBLIC KEY-----\n");
        }

        System.out.println("Done...\n\n");
    }

    enum TerminalType {
        None,
        Pos,
        Reload,
    }

    /**
     * @author Maximilian Pohl
     */
    private static void signTerminal() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        System.out.println("What kind terminal should the signature be generated for?");
        System.out.println("  1. POS");
        System.out.println("  2. Reload");

        TerminalType distinguishingByte = TerminalType.None;
        var scanner = new Scanner(System.in);
        switch (scanner.nextInt()) {
            case 1 -> distinguishingByte = TerminalType.Pos;
            case 2 -> distinguishingByte = TerminalType.Reload;
            default -> {
                System.out.println("Invalid input");
                System.exit(1);
            }
        }

        System.out.println("What terminal ID should be used?");
        var terminalId = scanner.nextInt();

        System.out.println("When should the terminal signature expire (yyyy-mm-dd)?");

        scanner.nextLine();
        LocalDate expirationDate = LocalDate.parse(scanner.nextLine());

        System.out.println("Use default path for the public key?");
        System.out.println("  1. Yes (filename: `{pos/reload}_public.pem)`");
        System.out.println("  2. No (specify own filename)");

        String filename_pub;
        if (scanner.nextInt() == 1) {
            filename_pub = distinguishingByte == TerminalType.Pos ? "pos_public.pem" : "reload_public.pem";
        } else {
            System.out.println("Please provide a name");
            var name = scanner.nextLine();
            filename_pub = name + "_public.pem";
        }

        // 4 byte terminalID || 3 byte expirationDate || 256 byte pubKeyTerminal || 1 byte distinguishingByte
        var dataToSign = new byte[4 + 3 + 256 + 1];

        System.arraycopy(Utils.intToBytes(terminalId), 0, dataToSign, 0, 4);
        System.arraycopy(Utils.dateToBytes(expirationDate), 0, dataToSign, 4, 3);
        System.arraycopy(Utils.readPublicKey(new File(filename_pub)).getModulus().toByteArray(), 1, dataToSign, 7, 256);
        dataToSign[4 + 3 + 256] = distinguishingByte == TerminalType.Pos ? (byte) 0x02 : (byte) 0x03;

        var backendPrivKey = Utils.readPrivateKey(new File("backend_private.pem"));
        var signature = Utils.sign(dataToSign, backendPrivKey);

        var signatureFilename = distinguishingByte == TerminalType.Pos ? "pos_signature" : "reload_signature";
        File outputFile = new File(signatureFilename);
        try (FileOutputStream outputStream = new FileOutputStream(outputFile)) {
            outputStream.write(signature);
        }
        System.out.println("Done...\n\n");
    }
}
