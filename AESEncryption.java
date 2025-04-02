import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.util.Base64;
import java.security.SecureRandom;
import java.io.*;

public class AESEncryption {

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
        try {
            // Example: File encryption and decryption
            String inputFilePath = "input.txt"; // Path to input file
            String encryptedFilePath = "encrypted.txt"; // Path for encrypted file
            String decryptedFilePath = "decrypted.txt"; // Path for decrypted file

            // Read content from the input file
            String fileContent = readFile(inputFilePath);
            System.out.println("Original Text:\n" + fileContent);

            // Generate AES key and IV
            SecretKey secretKey = generateAESKey();
            IvParameterSpec ivParameterSpec = generateIV();

            // Encrypt the file content
            String encryptedContent = encrypt(fileContent, secretKey, ivParameterSpec);
            writeFile(encryptedContent, encryptedFilePath);
            System.out.println("\nEncrypted Text written to: " + encryptedFilePath);

            // Decrypt the file content
            String decryptedContent = decrypt(encryptedContent, secretKey, ivParameterSpec);
            writeFile(decryptedContent, decryptedFilePath);
            System.out.println("\nDecrypted Text written to: " + decryptedFilePath);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}