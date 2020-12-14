import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;
import java.util.Scanner;

public class AsymmetricConnectionPolicy extends ConnectionPolicy {
    @Override
    public void init() {
        Logger.log("Initializing asymmetric connection...");
        this.cryptographyMethod = new AsymmetricCryptographyMethod();
        this.cryptographyMethod.init();
    }

    @Override
    public boolean handshake(Socket socket, String phoneNumber) {
        Logger.log("Performing handshake...");
        boolean res = false;
        try {
            Scanner in = new Scanner(socket.getInputStream());
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);


            Pair<String,String> keys = getUserKeys(phoneNumber);

            String publicKey = keys.getKey();         //generate the public key
            String privateKey = keys.getValue();     //generate the private key

            out.println(publicKey);
            String serverPublicKey = in.nextLine();

            ((AsymmetricCryptographyMethod) cryptographyMethod).setEncryptionKey(serverPublicKey);
            ((AsymmetricCryptographyMethod) cryptographyMethod).setDecryptionKey(privateKey);

            res = true;

        } catch (IOException e) {
            Logger.log(e.getMessage());
        }
        return res;
    }

    @Override
    public boolean validate(Message message) {
        return false;
    }

    @Override
    public boolean sign(Message message) {
        return false;
    }

    public Pair<String, String> generateKeyPair(){
        Logger.log("Generating key pair...");
        KeyPairGenerator kpg;
        String publicKey = null;
        String privateKey = null;
        try {
            kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(1024);
            KeyPair kp = kpg.generateKeyPair();
            publicKey = Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());
            privateKey = Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded());
            return new Pair<String, String>(publicKey, privateKey);

        } catch (Exception e) {
            Logger.log(e.getMessage());
        }
        return null;
    }

    public Pair<String,String> getUserKeys(String phoneNumber){
        Logger.log("Checking user credentials...");
        try {
            List<String> lines = Files.readAllLines(Path.of("files/users.txt"));
            for (String line : lines) {
                String[] temp = line.split("\0");
                if (temp[0].equals(phoneNumber) )
                    return new Pair<>(temp[1],temp[2]);
            }
            Pair<String, String> keys = generateKeyPair();
            String temp[] = {phoneNumber ,keys.getKey(),keys.getValue() };
            String line =  String.join("\0", temp)+'\n';
            FileWriter writer = new FileWriter("files/users.txt",true);
            writer.write(line);
            writer.close();

            return keys;

        } catch (IOException e) {
            Logger.log(e.getMessage());
        }

        return  generateKeyPair();
    }

}
