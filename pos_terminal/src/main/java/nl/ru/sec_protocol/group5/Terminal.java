package nl.ru.sec_protocol.group5;

import javax.smartcardio.*;
public class Terminal {
    public static void main(String[] args) throws CardException {
        CardTerminals terminals = TerminalFactory.getDefault().terminals();
        java.util.List<CardTerminal> terminal_list = terminals.list();
        CardTerminal terminal = terminal_list.get(0);
        Card card = terminal.connect("*");
        System.out.println(card.getATR());
    }
}
