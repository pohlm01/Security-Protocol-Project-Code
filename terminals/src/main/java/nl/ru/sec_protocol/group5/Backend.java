package nl.ru.sec_protocol.group5;

import java.util.Scanner;

public class Backend {
    public static void main(String[] args) {
        while (true) {
            System.out.println("What would you like to do. Please choose by typing in a number");
            System.out.println("  1. Generate Terminal keys");
            System.out.println("  2. Sign Terminal");

            var scanner = new Scanner(System.in);
            switch (scanner.nextInt()) {
                case 1 -> generateTerminalKeys();
                case 2 -> signTerminal();
                default -> {
                }
            }
        }
    }

    private static void generateTerminalKeys() {
        System.out.println("What kind terminal should the keys be generated for?");
        System.out.println("  1. POS (filename: `pos_{public/private}.pem`)");
        System.out.println("  2. Reload (filename: `reload_{public/private}.pem`)");
        System.out.println("  3. Give your own filename (filename: `<your_input>_{public/private}.pem`)");

        // TODO
    }

    private static void signTerminal() {
        System.out.println("What kind terminal should the keys be generated for?");
        System.out.println("  1. POS");
        System.out.println("  2. Reload");

        // TODO

        System.out.println("What terminal ID should be used?");

        // TODO

        System.out.println("When should the card expire?");

        // TODO

        System.out.println("Use default path for the public key?");
        System.out.println("  1. Yes (filename: `{pos/reload}_public.pem)`");
        System.out.println("  2. No (specify own filename)");

        // TODO

        // TODO create signature and save it in a reasonable format

    }

}
