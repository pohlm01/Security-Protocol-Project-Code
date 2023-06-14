package nl.ru.sec_protocol.group5;

public class Constants {
    public final static byte[] PUBLIC_EXPONENT = new byte[]{0x01, 0x00, 0x01};
    public final static byte[] MAX = new byte[]{(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF};
    public final static byte[] ONE = new byte[]{0x00, 0x00, 0x00, 0x01};

    public final static short ID_SIZE = 4;
    public final static short COUNTER_SIZE = 4;
    public final static short EPOCH_SIZE = 4;
    public final static short KEY_SIZE = 256;
    public final static short SIGNATURE_SIZE = KEY_SIZE;

    public final static short OFFSET_PUB_KEY = ID_SIZE + EPOCH_SIZE;
    public final static short OFFSET_DOMAIN_SEPARATOR = OFFSET_PUB_KEY + KEY_SIZE;
    public final static short AMOUNT_SIZE = 4;

    protected final static byte TERMINAL_TYPE_POS = 0x02;
    protected final static byte TERMINAL_TYPE_RELOAD = 0x03;

    public final static byte INIT = 0;
    public final static byte TERMINAL_META_EXCHANGED = 1;
    public final static byte PUB_KEYS_EXCHANGED = 2;
    public final static byte TERMINAL_PASSIVELY_AUTHENTICATED = 3;
    public final static byte TERMINAL_ACTIVELY_AUTHENTICATED = 4;
    public final static byte AMOUNT_RECEIVED = 5;
    public final static byte RELOAD_AMOUNT_AUTHENTICATED = 6;
    public final static byte FINISHED = 7;
}
