



import java.util.List;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

/**
 *
 * @author Tung
 */
public class JCIDEHelper {
    
    private Card card;
    private TerminalFactory factory;
    private CardTerminal terminal;
    private CardChannel channel;
    private List<CardTerminal> terminals;
    private ResponseAPDU response;
    
    public JCIDEHelper(){
    }

    
    public void connectCard(byte[] header, byte[] data){
        try {
            factory = TerminalFactory.getDefault();
            terminals = factory.terminals().list();
            System.out.println("is card empty: "+terminals.isEmpty());
            System.out.println(terminals);
            terminal = terminals.get(0);
            System.out.println("isCardPresent()" + terminal.isCardPresent());
            card= terminal.connect("*");
            sendApdu(header, data);
        }catch (Exception e){
            System.out.println("Error :" + e);
        }
    }
    
    public void disconnect(){
        try {
            card.disconnect(false);
        }catch (Exception e){
            System.out.println("Error :" + e);
        }
    }
    
    //send apdu  
           
    public void sendApdu(byte[] header, byte[] data){
        try {
            int cla, ins, p1, p2;
            cla = (int)header[0]&0xff;
            ins = (int)header[1]&0xff;
            p1 = (int)header[2]&0xff;
            p2 = (int)header[3]&0xff;
            channel = card.getBasicChannel();
            response = channel.transmit(new CommandAPDU(cla, ins, p1, p2, data, data.length));
        } catch (CardException e) {
            System.out.println("Error :" + e);
        }
    }
    
    //get Outdata
    public byte[] getData() {
        if (response!=null) {
            return response.getData();
        }
        else {
            return null;
        }
    }    
    
    //get status words
    public int getStatusWord() {
        return response.getSW();
    }
    
    public boolean isAuthenticationSuccessed(){
        return true;
    }
    
}
