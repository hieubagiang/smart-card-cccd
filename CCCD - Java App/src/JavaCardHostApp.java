
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import com.sun.javacard.apduio.*;

/**
 *
 * @author mallik
 */
public class JavaCardHostApp {

    private Socket sock;
    private OutputStream os;
    private InputStream is;
    private Apdu apdu;
    private CadClientInterface cad;

    public JavaCardHostApp() {
        apdu = new Apdu();
    }

    public void establishConnectionToSimulator() {
        try {
            //prgramm socket for the connection with simulator
            sock = new Socket("localhost", 9025);
            os = sock.getOutputStream();
            is = sock.getInputStream();
            //Initialize the instance card acceptance device
            cad = CadDevice.getCadClientInstance(CadDevice.PROTOCOL_T1, is, os);
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    public void closeConnection() {
        try {
            sock.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void pwrUp() {
        try {
            if (cad != null) {
                //to power up the card
                cad.powerUp();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void pwrDown() {
        try {
            if (cad != null) {
                //power down the card
                cad.powerDown();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void setTheAPDUCommands(byte[] cmnds) {
        if (cmnds.length > 4 || cmnds.length == 0) {
            System.err.println("inavlid commands");
        } else {
            //set the APDU header
            apdu.command = cmnds;
            System.out.println("CLA: " + atrToHex(cmnds[0]));
            System.out.println("INS: " + atrToHex(cmnds[1]));
            System.out.println("P1: " + atrToHex(cmnds[2]));
            System.out.println("P2: " + atrToHex(cmnds[3]));
        }
    }
    
    public void setTheDataLengthExtendedAPDU(short ln) {
        //set the length of the data command
        apdu.Lc = ln;
        System.out.println("Lc: " + shortToHex(ln));
    }

    public void setTheDataIn(byte[] data) {
        if (data.length != apdu.Lc) {
            System.err.println("The number of data in the array are more than expected");
        } else {
            //set the data to be sent to the applets
            apdu.dataIn = data;
            for (int dataIndx = 0; dataIndx < data.length; dataIndx++) {
                System.out.println("dataIn" + dataIndx + ": " + atrToHex(data[dataIndx]));
            }

        }
    }

    public void setExpctdLengthExtendedAPDU(short ln) {
        //expected length of the data in the response APDU
        apdu.Le = ln;
        System.out.println("Le: " + shortToHex(ln));
    }

    public void exchangeTheAPDUWithSimulator() {

        try {
            //Exchange the APDUs
            apdu.setDataIn(apdu.dataIn, apdu.Lc);
            cad.exchangeApdu(apdu);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public byte[] decodeDataOut() {
        byte[] dOut = apdu.getDataOut();
        
        for (int dataIndx = 0; dataIndx < dOut.length; dataIndx++) {
            System.out.println("dataOut" + dataIndx + ": " + atrToHex(dOut[dataIndx]));
        }
        
        return dOut;
    }

    public byte[] decodeStatus() {
        byte[] statByte = apdu.getSw1Sw2();
        System.out.println("SW1: " + atrToHex(statByte[0]));
        System.out.println("SW2: " + atrToHex(statByte[1]));
        return statByte;
    }


    public static String atrToHex(byte num) {
        char[] hexDigits = new char[2];
        hexDigits[0] = Character.forDigit((num >> 4) & 0xF, 16);
        hexDigits[1] = Character.forDigit((num & 0xF), 16);
        return new String(hexDigits);
    }
    
     public static String shortToHex(short num) {
        StringBuilder result = new StringBuilder();
        result.append(String.format("%02x", num));
        return result.toString();
    }

     public byte[] getResponseData() {
        byte[] dout = apdu.getResponseApduBytes();
        
        for (int i = 0; i < dout.length; i++) {
            System.out.println("Response" + i + ": " + atrToHex(dout[i]));
        }
 
        return dout;
    }
     
    public boolean isAuthenticationSuccessed(){
        return true;
    }
}