package nl.ru.sec_protocol.group5;

import javax.smartcardio.*;
import jnasmartcardio.Smartcardio;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

public class Terminal {
    public static void main(String[] args) throws CardException, NoSuchAlgorithmException, NoSuchProviderException {
        Security.addProvider(new Smartcardio());
        CardTerminals terminals = TerminalFactory.getInstance("PC/SC", null, Smartcardio.PROVIDER_NAME).terminals();

        java.util.List<CardTerminal> terminal_list = terminals.list();
        CardTerminal terminal = terminal_list.get(0);
        Card card = terminal.connect("*");
        System.out.println(card.getATR());
    }
}
