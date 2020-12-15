import java.io.IOException;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

public class HybridConnectionPolicy extends AsymmetricConnectionPolicy {
    ICryptographyMethod methodUsedInHandshake;

    @Override
    public void init() {
        Logger.log("Initializing hybrid connection...");
        cryptographyMethod = new AsymmetricCryptographyMethod();
        cryptographyMethod.init();
    }

    @Override
    public boolean handshake(Socket socket, String phoneNumber) {
        boolean res = false;

        try {
            Scanner in = new Scanner(socket.getInputStream());
            
            super.handshake(socket, phoneNumber);

            String sessionKey = cryptographyMethod.decrypt(in.nextLine()); //generate session key
            String IV = cryptographyMethod.decrypt(in.nextLine()); //generate IV key

            methodUsedInHandshake = cryptographyMethod;
            cryptographyMethod = new SymmetricCryptographyMethod(sessionKey, IV);
            cryptographyMethod.init();

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
            String signatureDigest = methodUsedInHandshake.decrypt(message.getSignature(),
                    ((AsymmetricCryptographyMethod) methodUsedInHandshake).getEncryptionKey());

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
            String signature = methodUsedInHandshake.encrypt(contentDigest,
                    ((AsymmetricCryptographyMethod) methodUsedInHandshake).getDecryptionKey());
            message.setSignature(signature);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }


        return true;
    }

}
