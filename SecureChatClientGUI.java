import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.net.*;
import java.math.BigInteger;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class SecureChatClientGUI extends JFrame {

    private JTextArea chatArea;
    private JTextField inputField;
    private JButton sendButton;

    private DataInputStream in;
    private DataOutputStream out;
    private SecretKey aesKey;

    public SecureChatClientGUI() throws Exception {
        setTitle("Secure TCP Chat");
        setSize(500, 400);
        setDefaultCloseOperation(EXIT_ON_CLOSE);

        chatArea = new JTextArea();
        chatArea.setEditable(false);

        inputField = new JTextField();
        sendButton = new JButton("Send");

        JPanel bottom = new JPanel(new BorderLayout());
        bottom.add(inputField, BorderLayout.CENTER);
        bottom.add(sendButton, BorderLayout.EAST);

        add(new JScrollPane(chatArea), BorderLayout.CENTER);
        add(bottom, BorderLayout.SOUTH);

        setupConnection();
        setupActions();
        startListenerThread();

        setVisible(true);
    }

    /* =======================
       CONNECTION + DH + AES
       ======================= */
    private void setupConnection() throws Exception {
        Socket socket = new Socket(InetAddress.getLocalHost(), 1234);

        in = new DataInputStream(socket.getInputStream());
        out = new DataOutputStream(socket.getOutputStream());

        SecureRandom random = new SecureRandom();
        BigInteger p = BigInteger.probablePrime(2048, random);
        BigInteger g = BigInteger.valueOf(2);

        BigInteger a = new BigInteger(2046, random);
        BigInteger A = g.modPow(a, p);

        out.writeUTF(p.toString());
        out.writeUTF(g.toString());
        out.writeUTF(A.toString());

        BigInteger B = new BigInteger(in.readUTF());
        BigInteger sharedSecret = B.modPow(a, p);

        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] keyBytes = sha256.digest(sharedSecret.toByteArray());
        aesKey = new SecretKeySpec(keyBytes, 0, 16, "AES");

        chatArea.append("🔐 Secure session established\n");
    }

    /* =======================
       GUI ACTIONS
       ======================= */
    private void setupActions() {
        sendButton.addActionListener(e -> sendMessage());
        inputField.addActionListener(e -> sendMessage());
    }

    private void sendMessage() {
        try {
            String msg = inputField.getText().trim();
            if (msg.isEmpty()) return;

            sendEncrypted(msg);
            chatArea.append("You: " + msg + "\n");
            inputField.setText("");

            if (msg.equals("close")) {
                System.exit(0);
            }
        } catch (Exception ex) {
            chatArea.append("❌ Error sending message\n");
        }
    }

    /* =======================
       BACKGROUND LISTENER
       ======================= */
    private void startListenerThread() {
        new Thread(() -> {
            try {
                while (true) {
                    String msg = receiveEncrypted();
                    SwingUtilities.invokeLater(() ->
                        chatArea.append("Server: " + msg + "\n")
                    );
                }
            } catch (Exception e) {
                chatArea.append("🔌 Connection closed\n");
            }
        }).start();
    }

    /* =======================
       ENCRYPTION HELPERS
       ======================= */
    private void sendEncrypted(String msg) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);

        cipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));
        byte[] ct = cipher.doFinal(msg.getBytes());

        out.writeInt(iv.length);
        out.write(iv);
        out.writeInt(ct.length);
        out.write(ct);
    }

    private String receiveEncrypted() throws Exception {
        int ivLen = in.readInt();
        byte[] iv = new byte[ivLen];
        in.readFully(iv);

        int ctLen = in.readInt();
        byte[] ct = new byte[ctLen];
        in.readFully(ct);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));

        return new String(cipher.doFinal(ct));
    }

    public static void main(String[] args) throws Exception {
        SwingUtilities.invokeLater(() -> {
            try {
                new SecureChatClientGUI();
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
    }
}

