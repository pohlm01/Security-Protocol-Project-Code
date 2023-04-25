package nl.ru.sec_protocol.group5;

import javax.smartcardio.*;
public class Terminal {
    public static void main(String[] args) throws CardException {
        var terminals = TerminalFactory.getDefault().terminals();
        var terminal_list = terminals.list();
        System.out.println(terminal_list.isEmpty());
        CardTerminal terminal = terminal_list.get(0);
        Card card = terminal.connect("*");
        System.out.println(card.getATR());
    }
}
