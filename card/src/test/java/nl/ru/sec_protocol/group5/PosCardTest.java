package nl.ru.sec_protocol.group5;

import com.licel.jcardsim.io.JavaxSmartCardInterface;
import com.licel.jcardsim.samples.HelloWorldApplet;
import com.licel.jcardsim.base.Simulator;
import javacard.framework.*;
import junit.framework.TestCase;
import javacard.framework.JCSystem.*;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public class PosCardTest extends TestCase {
    public void test() {
//        JCSystem.makeTransientByteArray((short) 4, (byte) 6);
//        System.out.println(System.getProperty("java.library.path"));
////        System.load("/home/max/IdeaProjects/pos/card/sdk/lib/api.jar");
//        //1. create simulator
//        Simulator simulator = new Simulator();
//        //2. install applet
//        byte[] aid = new byte[]{1, 2, 3, 4, 5, 6};
//
//        AID appletAID = new AID(aid, (short) 0, (byte) 6);
//        simulator.installApplet(appletAID, HelloWorldApplet.class);
//        //3. select applet
//        simulator.selectApplet(appletAID);
//        //4. send apdu
//        byte[] apdu = new byte[]{1, 1, 0, 0};
//        byte[] response = simulator.transmitCommand(apdu);
////        ResponseAPDU test = new ResponseAPDU(apdu);
//        //5. check response
////        assertEquals(0x9000, test.getSW());
    }
}
