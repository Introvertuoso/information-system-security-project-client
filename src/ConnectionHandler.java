import java.io.IOException;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Scanner;

public class ConnectionHandler {

    private final Socket socket;
    private final ConnectionPolicy connectionPolicy;
    private String data;

    ConnectionHandler(Socket socket, ConnectionPolicy connectionPolicy) {
        this.data = "";
        this.socket = socket;
        this.connectionPolicy = connectionPolicy;
        this.connectionPolicy.init();
    }

    public void run(){
        Logger.log("Connected: " + socket + "\n");
        try {
            Scanner in = new Scanner(socket.getInputStream());
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

            if (!connectionPolicy.handshake(socket)) {
                Logger.log("Failed to perform handshake." + "\n");
            } else {
//                while (in.hasNextLine()) {
//                    out.println(connectionPolicy.cryptographyMethod.encrypt(data));
//                    data = connectionPolicy.cryptographyMethod.decrypt(in.nextLine());
//                    System.out.println(data);
//
//                }
                //TODO: get input from the user
                out.println(connectionPolicy.cryptographyMethod.encrypt("HI YOU LITTLE SHIT"));
                data = connectionPolicy.cryptographyMethod.decrypt(in.nextLine());
                System.out.println(data);
            }

        } catch (Exception e) {
            Logger.log("Error: " + socket + "\n");
        } finally {
            try {
                socket.close();
                Logger.log("Closed: " + socket + "\n");

            } catch (IOException e) {
                Logger.log("Failed to close socket.\n");
            }
        }
    }



}
