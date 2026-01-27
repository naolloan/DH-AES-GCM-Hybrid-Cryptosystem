import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class TCPServer {

    private static final int PORT = 1234;

    public static void main(String[] args) throws Exception {

        ServerSocket serverSocket = new ServerSocket(PORT);
        System.out.println("Server listening on port " + PORT);

        Socket socket = serverSocket.accept();
        System.out.println("Client connected.");

        DataInputStream in = new DataInputStream(socket.getInputStream());
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());

        /* =======================
           DIFFIE–HELLMAN SETUP
           ======================= */

        BigInteger p = new BigInteger(in.readUTF());
        BigInteger g = new BigInteger(in.readUTF());
        BigInteger A = new BigInteger(in.readUTF());

        SecureRandom random = new SecureRandom();
        BigInteger b = new BigInteger(2046, random);       // private
        BigInteger B = g.modPow(b, p);                     // public

        out.writeUTF(B.toString());

        BigInteger sharedSecret = A.modPow(b, p);

        /* =======================
           DERIVE AES KEY
           ======================= */

        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] keyBytes = sha256.digest(sharedSecret.toByteArray());
        SecretKey aesKey = new SecretKeySpec(keyBytes, 0, 16, "AES");

        System.out.println("Secure session established.\n");
        

        /* =======================
           ENCRYPTED CHAT
           ======================= */

        while (true) {
            String message = receiveEncrypted(in, aesKey);

            if (message.equals("close")) {
                break;
            }

            System.out.println("Received: " + message);
            sendEncrypted(out, aesKey, "Echo: " + message);
        }

        socket.close();
        serverSocket.close();
    }

    /* ---------- Encryption ---------- */

    private static void sendEncrypted(DataOutputStream out, SecretKey key, String msg) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);

        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        byte[] ciphertext = cipher.doFinal(msg.getBytes());

        out.writeInt(iv.length);
        out.write(iv);
        out.writeInt(ciphertext.length);
        out.write(ciphertext);
    }

    private static String receiveEncrypted(DataInputStream in, SecretKey key) throws Exception {
        int ivLen = in.readInt();
        byte[] iv = new byte[ivLen];
        in.readFully(iv);

        int ctLen = in.readInt();
        byte[] ciphertext = new byte[ctLen];
        in.readFully(ciphertext);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));

        return new String(cipher.doFinal(ciphertext));
    }
}

