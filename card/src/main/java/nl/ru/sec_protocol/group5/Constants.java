package nl.ru.sec_protocol.group5;

public class Constants {
    public final static byte[] PUBLIC_EXPONENT = new byte[]{0x01, 0x00, 0x01};
    public final static byte[] ZERO = new byte[]{0x00, 0x00, 0x00, 0x00};

    public final static short ID_SIZE = 4;
    public final static short COUNTER_SIZE = 4;
    public final static short DATE_SIZE = 3;
    public final static short KEY_SIZE = 256;
    public final static short SIGNATURE_SIZE = KEY_SIZE;

    public final static short OFFSET_PUB_KEY = ID_SIZE + DATE_SIZE;
    public final static short OFFSET_DOMAIN_SEPARATOR = OFFSET_PUB_KEY + KEY_SIZE;

    protected final static byte TERMINAL_TYPE_POS = 0x02;
    protected final static byte TERMINAL_TYPE_RELOAD = 0x03;

    public final static byte INIT = 0;
    public final static byte TERMINAL_META_EXCHANGED = 1;
    public final static byte PUB_KEYS_EXCHANGED = 2;
    public final static byte TERMINAL_PASSIVELY_AUTHENTICATED = 3;
    public final static byte TERMINAL_ACTIVELY_AUTHENTICATED = 4;
    public final static byte RELOAD_AMOUNT_RECEIVED = 5;
    public final static byte RELOAD_AMOUNT_AUTHENTICATED = 6;
    public final static byte POS_AMOUNT_AUTHENTICATED = 7;
    public final static byte FINISHED = 8;
}