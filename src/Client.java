import java.io.IOException;
import java.net.Socket;

public class Client {


    //TODO: parameters should be taken from the user
    public static void main(String[] args) {

        try {
            Socket socket = new Socket("localhost",11111);
            ConnectionPolicy connectionPolicy = new HybridConnectionPolicy();

            ConnectionHandler client = new ConnectionHandler(socket,connectionPolicy);
            client.run();

        } catch (IOException e) {
            e.printStackTrace();
        }

    }


}