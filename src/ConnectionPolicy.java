import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public abstract class ConnectionPolicy {
    protected ICryptographyMethod cryptographyMethod;
    protected Certificate clientCertificate;

    public abstract void init();
    public abstract boolean handshake(Socket socket, String phoneNumber);
    public abstract boolean validate(Message message);
    public abstract boolean sign(Message message);

    public String generateKey(int keySize){
        Logger.log("Generating key...");
        KeyGenerator gen;
        String SK = "";
        try {
            gen = KeyGenerator.getInstance("AES");
            gen.init(keySize); /* 128-bit AES */
            SecretKey secretKey = gen.generateKey();
            byte[] bytes = secretKey.getEncoded();
            SK = String.format("%032X", new BigInteger(+1, bytes));


        } catch (NoSuchAlgorithmException e) {
            Logger.log(e.getMessage());
        }
        return SK;
    }

    public String generateIV() {
        Logger.log("Generating initial vector...");
        byte[] iv = new byte[128/8];
        SecureRandom srandom = new SecureRandom();
        srandom.nextBytes(iv);
        return Base64.getEncoder().encodeToString(iv);
    }

    public Certificate getClientCertificate() {
        return clientCertificate;
    }

    public void setClientCertificate(Certificate clientCertificate) {
        this.clientCertificate = clientCertificate;
    }
}
