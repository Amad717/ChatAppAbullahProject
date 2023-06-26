import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.net.Socket;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

public class SimpleSecureChatClient {
    private static final int SERVER_PORT = 5000;

    private SecretKey secretKey;
    private JTextArea chatArea;
    private JTextField inputField;
    private ObjectOutputStream outputStream;

    public SimpleSecureChatClient() {
        // initEncryption();

        String keyString = "HyoWrRBIm8aJA9caGjPduQ=="; // Your key string
        
        // Convert the key string to bytes
        byte[] keyBytes = keyString.getBytes(StandardCharsets.UTF_8);
        
        // Create a SecretKey object from the key bytes
        secretKey = new SecretKeySpec(keyBytes, "AES");

        JFrame frame = new JFrame("Simple Secure Chat - Client");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(400, 400);
        frame.setLocationRelativeTo(null);

        JPanel contentPane = new JPanel();
        contentPane.setBorder(new EmptyBorder(10, 10, 10, 10));
        contentPane.setLayout(new BorderLayout(10, 10));

        chatArea = new JTextArea();
        chatArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(chatArea);
        contentPane.add(scrollPane, BorderLayout.CENTER);

        inputField = new JTextField();
        JButton sendButton = new JButton("Send");
        sendButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                sendMessage();
            }
        });

        JPanel inputPanel = new JPanel(new BorderLayout());
        inputPanel.add(inputField, BorderLayout.CENTER);
        inputPanel.add(sendButton, BorderLayout.EAST);

        contentPane.add(inputPanel, BorderLayout.SOUTH);
        frame.setContentPane(contentPane);
        frame.setVisible(true);

        connectToServer();
    }

    private void initEncryption() {
        try {
            secretKey = generateSecretKey();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private SecretKey generateSecretKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        return keyGenerator.generateKey();
    }

    private void connectToServer() {
        try {
            String serverIp = JOptionPane.showInputDialog("Enter server IP address:");
            Socket socket = new Socket(serverIp, SERVER_PORT);
            outputStream = new ObjectOutputStream(socket.getOutputStream());
            outputStream.writeObject(secretKey);

            Thread receiveThread = new Thread(new ReceiveMessage(socket));
            receiveThread.start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void sendMessage() {
        try {
            String message = inputField.getText().trim();
            if (!message.isEmpty()) {
                Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
                byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
                int blockSize = cipher.getBlockSize();
                int paddedLength = (messageBytes.length / blockSize + 1) * blockSize;
                byte[] paddedMessage = new byte[paddedLength];
                System.arraycopy(messageBytes, 0, paddedMessage, 0, messageBytes.length);
                byte[] encryptedMessage = cipher.doFinal(paddedMessage);
                outputStream.writeObject(encryptedMessage);

                chatArea.append("Me: " + message + "\n");
                inputField.setText("");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private class ReceiveMessage implements Runnable {
        private Socket socket;

        public ReceiveMessage(Socket socket) {
            this.socket = socket;
        }

        @Override
        public void run() {
            try {
                ObjectInputStream inputStream = new ObjectInputStream(socket.getInputStream());
                Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
                cipher.init(Cipher.DECRYPT_MODE, secretKey);

                while (true) {
                    Object receivedObject = inputStream.readObject();

                    if (receivedObject instanceof byte[]) {
                        byte[] encryptedMessage = (byte[]) receivedObject;
                        byte[] decryptedMessage = cipher.doFinal(encryptedMessage);
                        String message = new String(decryptedMessage, StandardCharsets.UTF_8).trim();
                        chatArea.append("Server: " + message + "\n");
                    } else {
                        // Handle other types of objects received, if applicable
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                new SimpleSecureChatClient();
            }
        });
    }
}