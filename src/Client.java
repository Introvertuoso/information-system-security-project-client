import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Scanner;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

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