import java.io.IOException;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.Key;
import java.util.Scanner;

public class HybridConnectionPolicy extends AsymmetricConnectionPolicy {
    @Override
    public void init() {
        Logger.log("Initializing hybrid connection...");
        cryptographyMethod = new AsymmetricCryptographyMethod();
        cryptographyMethod.init();
        Logger.log("Done" + "\n");
    }

    @Override
    public boolean handshake(Socket socket, String phoneNumber) {
        Logger.log("Performing handshake...");
        boolean res = false;

        try {
            Scanner in = new Scanner(socket.getInputStream());
            
            super.handshake(socket, phoneNumber);

            String sessionKey = cryptographyMethod.decrypt(in.nextLine()); //generate session key
            String IV = cryptographyMethod.decrypt(in.nextLine()); //generate IV key

            cryptographyMethod = new SymmetricCryptographyMethod(sessionKey, IV);
            cryptographyMethod.init();

            Logger.log("Done" + "\n");
            res = true;

        } catch (IOException e) {
            Logger.log("Failed" + "\n");
            e.printStackTrace();
        }
        return res;
    }
}
