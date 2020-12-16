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
        try {
            Scanner in = new Scanner(socket.getInputStream());
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            Scanner CLI = new Scanner(System.in);

            System.out.println("\nEnter your phone number: ");
            String phoneNumber = CLI.nextLine();
            System.out.println();

            if (!connectionPolicy.handshake(socket, phoneNumber)) {
                Logger.log("Failed to perform handshake.");
            } else {
                System.out.println("\nEnter your commands below\n");
                System.out.print("> ");
                while (CLI.hasNextLine()) {
                    Message message = new Message(
                            new Task(CLI.nextLine()),
                            this.connectionPolicy.clientCertificate,
                            null
                    );
//                    System.out.println(message.getTask().toString());
                    this.connectionPolicy.sign(message);
                    message.packData();
                    out.println(connectionPolicy.cryptographyMethod.encrypt(message.getData()));
                    String raw = connectionPolicy.cryptographyMethod.decrypt(in.nextLine());
                    Message response = new Message(raw);
                    response.unpackData();
                    if (!this.connectionPolicy.validate(response)) {
                        Logger.log("Signature invalid.");
                    } else {
                        data = response.getTask().toString().trim();
                        if (data.equals(Logger.TERMINATE)) {
                            throw new Exception("");
                        } else {
                            System.out.println("\n" + data);
                        }
                    }
                    System.out.print("\n> ");
                }
            }

        } catch (Exception e) {
            Logger.log(e.getMessage());
        } finally {
            try {
                socket.close();
                Logger.log("Connection terminated.\n");

            } catch (IOException e) {
                Logger.log(e.getMessage());
            }
        }
    }
}
