import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.security.SecureRandom;
import java.util.Base64;

public class AESEncryptionGUI {

    // Instance variables
    private SecretKey secretKey = null;
    private IvParameterSpec ivParameterSpec = null;
    private String filePath = "";

    // Constructor
    public AESEncryptionGUI() {
        // Create GUI components
        JFrame frame = new JFrame("AES Encryption/Decryption");
        frame.setSize(500, 400);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setLayout(new BorderLayout());

        // Text area to display file content
        JTextArea textArea = new JTextArea();
        textArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(textArea);
        frame.add(scrollPane, BorderLayout.CENTER);

        // Buttons for file selection, encryption, and decryption
        JPanel panel = new JPanel();
        JButton selectFileButton = new JButton("Select File");
        JButton encryptButton = new JButton("Encrypt");
        JButton decryptButton = new JButton("Decrypt");

        // Add buttons to panel
        panel.add(selectFileButton);
        panel.add(encryptButton);
        panel.add(decryptButton);
        frame.add(panel, BorderLayout.SOUTH);

        // Action listener for Select File button
        selectFileButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                JFileChooser fileChooser = new JFileChooser();
                int returnValue = fileChooser.showOpenDialog(frame);
                if (returnValue == JFileChooser.APPROVE_OPTION) {
                    filePath = fileChooser.getSelectedFile().getAbsolutePath();
                    try {
                        String content = readFile(filePath);
                        textArea.setText(content);
                    } catch (IOException ex) {
                        JOptionPane.showMessageDialog(frame, "Error reading the file.");
                    }
                }
            }
        });

        // Action listener for Encrypt button
        encryptButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                if (filePath.isEmpty()) {
                    JOptionPane.showMessageDialog(frame, "Please select a file to encrypt.");
                    return;
                }
                try {
                    // Generate AES key and IV (instance variables)
                    secretKey = generateAESKey();
                    ivParameterSpec = generateIV();

                    // Read the content from the selected file
                    String fileContent = readFile(filePath);
                    
                    // Encrypt the content
                    String encryptedContent = encrypt(fileContent, secretKey, ivParameterSpec);
                    String encryptedFilePath = filePath + ".encrypted";
                    
                    // Write encrypted content to a new file
                    writeFile(encryptedContent, encryptedFilePath);
                    textArea.setText("File encrypted successfully! Encrypted file saved as: " + encryptedFilePath);
                    
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(frame, "Error during encryption: " + ex.getMessage());
                }
            }
        });

        // Action listener for Decrypt button
        decryptButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                if (filePath.isEmpty()) {
                    JOptionPane.showMessageDialog(frame, "Please select a file to decrypt.");
                    return;
                }
                try {
                    // Read the content from the selected encrypted file
                    String encryptedContent = readFile(filePath);
                    
                    // Decrypt the content
                    String decryptedContent = decrypt(encryptedContent, secretKey, ivParameterSpec);
                    String decryptedFilePath = filePath + ".decrypted";
                    
                    // Write decrypted content to a new file
                    writeFile(decryptedContent, decryptedFilePath);
                    textArea.setText("File decrypted successfully! Decrypted file saved as: " + decryptedFilePath);
                    
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(frame, "Error during decryption: " + ex.getMessage());
                }
            }
        });

        // Show the window
        frame.setVisible(true);
    }

    // Method to generate a random AES key
    public static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); // 128-bit AES key
        return keyGen.generateKey();
    }

    // Method to generate a random IV (Initialization Vector) for AES
    public static IvParameterSpec generateIV() {
        byte[] iv = new byte[16]; // AES block size is 16 bytes
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    // Encrypt a string using AES
    public static String encrypt(String plaintext, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); // AES in CBC mode with PKCS5 padding
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes); // Encoding encrypted bytes to Base64 for display/storage
    }

    // Decrypt a string using AES
    public static String decrypt(String ciphertext, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] decodedBytes = Base64.getDecoder().decode(ciphertext); // Decode from Base64 to bytes
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes);
    }

    // Method to read a file and return its content as a string
    public static String readFile(String filePath) throws IOException {
        return new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(filePath)));
    }

    // Method to write content to a file
    public static void writeFile(String content, String filePath) throws IOException {
        java.nio.file.Files.write(java.nio.file.Paths.get(filePath), content.getBytes());
    }

    public static void main(String[] args) {
        // Create an instance of AESEncryptionGUI to run the program
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                new AESEncryptionGUI();
            }
        });
    }
}