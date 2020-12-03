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

    public void run() {
        Logger.log("Connected: " + socket);
        try {
            Scanner in = new Scanner(socket.getInputStream());
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            Scanner CLI = new Scanner(System.in);

            System.out.println("\nEnter your phone number: ");
            String phoneNumber = CLI.nextLine();

            if (!connectionPolicy.handshake(socket, phoneNumber)) {
                Logger.log("Failed to perform handshake.");
            } else {
                System.out.println("\nEnter your commands below ");
                while (CLI.hasNextLine()) {
                    Message message = new Message(new Task(CLI.nextLine()), new Certificate("certificate"));
                    message.packData();
                    out.println(connectionPolicy.cryptographyMethod.encrypt(message.getData()));
                    data = connectionPolicy.cryptographyMethod.decrypt(in.nextLine());
                    System.out.println("\n" + data);
                }

            }

        } catch (Exception e) {
            Logger.log(e.getMessage());
        } finally {
            try {
                socket.close();
                Logger.log("Closed: " + socket);

            } catch (IOException e) {
                Logger.log(e.getMessage());
            }
        }
    }

}
