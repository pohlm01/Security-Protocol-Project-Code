package nl.ru.sec_protocol.group5;

import javax.smartcardio.*;

import jnasmartcardio.Smartcardio;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.time.LocalDate;
import java.time.LocalTime;
import java.util.Arrays;
import java.util.Date;

import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;

public class Terminal {

    private final Card card;

    public static void main(String[] args) throws CardException, NoSuchAlgorithmException, NoSuchProviderException {
        Security.addProvider(new Smartcardio());
        CardTerminals terminals = TerminalFactory.getInstance("PC/SC", null, Smartcardio.PROVIDER_NAME).terminals();

        java.util.List<CardTerminal> terminal_list = terminals.list();
        CardTerminal terminal = terminal_list.get(0);
        Card card = terminal.connect("*");

        Terminal t = new Terminal(card);
        t.initialize_card(12345, LocalDate.now());

//        System.out.println(Arrays.toString(card.getATR().getBytes()));
//        System.out.println(new String(card.getATR().getHistoricalBytes()));
    }

    Terminal(Card card) {
        this.card = card;
    }

    public void initialize_card(int card_id, LocalDate expiration_date) throws NoSuchAlgorithmException, CardException {
        var channel = card.getBasicChannel();

//        var ec_key_generator = KeyPairGenerator.getInstance("EC");
//
//        ec_key_generator.initialize();
//        var key_pair = ec_key_generator.generateKeyPair();
//        System.out.println(key_pair.getPublic().toString());


        var data = new byte[]{};

//        var apdu = new CommandAPDU(0, '1', 0, 0, data, 192 / 8);
        byte[] aid = new byte[]{0x2D, 0x54, 0x45, 0x53, 0x54, 0x70};
//        byte[] aid = new byte[]{0x70, 0x54, 0x53, 0x45, 0x54, 0x2D};
        CommandAPDU apdu = new CommandAPDU(0x80, 0x02, 0x00, 0x00, aid, 256);
        CommandAPDU select_aid = new CommandAPDU((byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, aid);
        System.out.println(select_aid);

        var response = channel.transmit(select_aid);
        System.out.println(response);

        apdu = new CommandAPDU((byte) 0x00, (byte) 0x02, (byte) 0x00, (byte) 0x00, 2048 / 8);
        response = channel.transmit(apdu);
        System.out.println(response);
        System.out.println(Arrays.toString(response.getData()));

    }
}
