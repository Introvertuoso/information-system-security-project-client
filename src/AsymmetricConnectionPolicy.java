import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
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
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encodedhash = digest.digest(message.getTask().toString().getBytes(StandardCharsets.UTF_8));

            String contentDigest = bytesToHex(encodedhash) ;
            String signatureDigest = cryptographyMethod.decrypt(message.getSignature(),
                    ((AsymmetricCryptographyMethod) cryptographyMethod).getEncryptionKey());

            if(contentDigest.equals(signatureDigest))
                return true;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return false;
    }



    @Override
    public boolean sign(Message message) {
        try {
            MessageDigest digest  =  MessageDigest.getInstance("SHA-256");
            byte[] contentDigestBytes = digest.digest(message.getTask().toString().getBytes(StandardCharsets.UTF_8));
            String contentDigest = bytesToHex(contentDigestBytes);
            String signature = cryptographyMethod.encrypt(contentDigest,
                    ((AsymmetricCryptographyMethod) cryptographyMethod).getDecryptionKey());
            message.setSignature(signature);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }


        return true;
    }

    public String bytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder(2 * hash.length);
        for (int i = 0; i < hash.length; i++) {
            String hex = Integer.toHexString(0xff & hash[i]);
            if(hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
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
