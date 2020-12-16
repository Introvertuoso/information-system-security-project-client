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
        boolean res = false;
        try {
            Scanner in = new Scanner(socket.getInputStream());
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

            Pair<Certificate,String> keys = getUserCredentials(phoneNumber);

            clientCertificate = keys.getKey();
            String publicKey = clientCertificate.getCsr().getPublicKey();
            String privateKey = keys.getValue();

            Logger.log("Performing handshake...");
            out.println(publicKey);
            String serverPublicKey = in.nextLine();

            Certificate serverCertificate = new Certificate(in.nextLine());

            ((AsymmetricCryptographyMethod) cryptographyMethod).setEncryptionKey(serverPublicKey);
            ((AsymmetricCryptographyMethod) cryptographyMethod).setDecryptionKey(privateKey);

            if (!validate(serverCertificate)) {
                Logger.log("Server certificate invalid.");
            }
            else {
                out.println(clientCertificate.toString());
                clientCertificate = new Certificate(in.nextLine());
                res = true;
            }

        } catch (IOException e) {
            Logger.log(e.getMessage());
        }
        return res;
    }

    @Override
    public boolean validate(Message message) {
        // TODO: abstract signature verification with hash
        Logger.log("Validating signature...");
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encodedhash = digest.digest(message.getTask().toString().getBytes(StandardCharsets.UTF_8));

            String contentDigest = bytesToHex(encodedhash) ;
            String signatureDigest = cryptographyMethod.decrypt(message.getSignature(),
                    AsymmetricCryptographyMethod.loadPublicKey(
                            ((AsymmetricCryptographyMethod) cryptographyMethod).getEncryptionKey())
            );

            if(contentDigest.equals(signatureDigest))
                return true;
        } catch (NoSuchAlgorithmException e) {
            Logger.log(e.getMessage());
        }

        return false;
    }

    public boolean validate(Certificate certificate) {
        Logger.log("Validating server certificate...");
        String assumedServerPublicKey = ((AsymmetricCryptographyMethod)this.cryptographyMethod).getEncryptionKey();
        String localCAPublicKey = "";

        try {
            localCAPublicKey = Files.readAllLines(Path.of("CA/Built_in_CA.txt")).get(2);

        } catch (IOException e) {
            Logger.log("IO issues encountered.");
        }
        return
                verifySignatureHash(certificate.getCsr().toString(), certificate.getSignature(), localCAPublicKey) &&
                        (certificate.getCsr().getPublicKey().equals(assumedServerPublicKey));
    }

    @Override
    public boolean sign(Message message) {
        Logger.log("Signing message...");
        try {
            MessageDigest digest  =  MessageDigest.getInstance("SHA-256");
            byte[] contentDigestBytes = digest.digest(message.getTask().toString().getBytes(StandardCharsets.UTF_8));
            String contentDigest = bytesToHex(contentDigestBytes);
            String signature = cryptographyMethod.encrypt(contentDigest,
                    AsymmetricCryptographyMethod.loadPrivateKey(
                            ((AsymmetricCryptographyMethod) cryptographyMethod).getDecryptionKey())
            );
            message.setSignature(signature);

        } catch (NoSuchAlgorithmException e) {
            Logger.log(e.getMessage());
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

    public Pair<Certificate,String> getUserCredentials(String phoneNumber){
        Logger.log("Obtaining key pair...");
        try {
            List<String> lines = Files.readAllLines(Path.of("files/users.txt"));
            for (String line : lines) {
                String[] temp = line.split("\0", 2);
                Certificate certificate = new Certificate(temp[1]);
                if (certificate.getCsr().getPhoneNumber().equals(phoneNumber))
                    return new Pair<>(certificate, temp[0]);
            }
            Pair<String, String> keys = generateKeyPair();
            Certificate certificate = new Certificate(
                    new CSR("localhost", phoneNumber, keys.getKey(), "2025", "")
            );
            String[] temp = {keys.getValue(), certificate.toString()};
            String line =  String.join("\0", temp) + '\n';
            FileWriter writer = new FileWriter("files/users.txt",true);
            writer.write(line);
            writer.close();

            return new Pair<>(certificate, temp[0]);

        } catch (IOException e) {
            Logger.log(e.getMessage());
        }

        return new Pair<>(new Certificate(""), "");
    }

    public boolean verifySignatureHash(String document, String signature, String key) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encodedhash = digest.digest(document.getBytes(StandardCharsets.UTF_8));

            String contentDigest = bytesToHex(encodedhash) ;
            String signatureDigest = cryptographyMethod.decrypt(signature,
                    AsymmetricCryptographyMethod.loadPublicKey(key)
            );

            if(contentDigest.equals(signatureDigest))
                return true;

        } catch (NoSuchAlgorithmException e) {
            Logger.log(e.getMessage());
        }

        return false;
    }

}
