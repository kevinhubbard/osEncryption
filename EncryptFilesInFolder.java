/*import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.nio.file.*;
import java.util.Base64;
import java.util.Scanner;

public class EncryptFilesInFolder {

    // Encrypt the byte array using AES and return the encrypted content with IV prepended
    public static String encrypt(byte[] fileContent, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] ivBytes = new byte[16]; // 128-bit IV (AES block size)
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] encryptedBytes = cipher.doFinal(fileContent);

        // Combine IV + encrypted data
        byte[] ivAndEncryptedData = new byte[ivBytes.length + encryptedBytes.length];
        System.arraycopy(ivBytes, 0, ivAndEncryptedData, 0, ivBytes.length);
        System.arraycopy(encryptedBytes, 0, ivAndEncryptedData, ivBytes.length, encryptedBytes.length);

        return Base64.getEncoder().encodeToString(ivAndEncryptedData);  // Return as Base64 string
    }

    // Generate a new AES key and save it to a file
    public static void generateAndSaveKey(String keyFilePath) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);  // Use AES-256
        SecretKey secretKey = keyGenerator.generateKey();
        // Save the AES key to a file
        try (ObjectOutputStream keyOut = new ObjectOutputStream(new FileOutputStream(keyFilePath))) {
            keyOut.writeObject(secretKey);  // Serialize the SecretKey object
        }
    }

    // Read the AES key from the file
    public static SecretKey readKeyFromFile(String keyFilePath) throws IOException, ClassNotFoundException {
        try (ObjectInputStream keyIn = new ObjectInputStream(new FileInputStream(keyFilePath))) {
            return (SecretKey) keyIn.readObject();  // Deserialize the SecretKey object
        }
    }

    // Encrypt all files in the folder
    public static void encryptFilesInFolder(String folderPath, SecretKey secretKey) throws IOException {
        File folder = new File(folderPath);
        File[] files = folder.listFiles((dir, name) -> !name.equals("encryption.key"));  // Exclude the encryption key file

        for (File file : files) {
            if (file.isFile()) {
                try {
                    // Read file content as binary (byte array)
                    byte[] fileContent = Files.readAllBytes(file.toPath());
                    String encryptedContent = encrypt(fileContent, secretKey);

                    // Save the encrypted content with a ".encrypted" extension
                    String encryptedFilePath = file.getAbsolutePath() + ".encrypted";
                    Files.write(Paths.get(encryptedFilePath), encryptedContent.getBytes());

                    // Save the file extension for later decryption
                    String extensionFilePath = file.getAbsolutePath() + ".ext";
                    Files.write(Paths.get(extensionFilePath), file.getName().getBytes());

                    // Remove the original file after encryption
                    file.delete();
                    //System.out.println("Encrypted and removed: " + file.getAbsolutePath());
                } catch (Exception e) {
                    System.err.println("Error encrypting file " + file.getAbsolutePath() + ": " + e.getMessage());
                }
            }
        }
    }

    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("Usage: java EncryptFilesInFolder <folderPath>");
            return;
        }

        String folderPath = args[0];
        String keyFilePath = "encryption.key";  // Save the key to a file in the project directory

        try {
            // Generate and save the AES key
            generateAndSaveKey(keyFilePath);

            // Read the generated AES key from the file
            SecretKey secretKey = readKeyFromFile(keyFilePath);

            // Start the timer
            long startTime = System.currentTimeMillis();

            // Encrypt all files in the folder
            encryptFilesInFolder(folderPath, secretKey);

            // End the timer
            long endTime = System.currentTimeMillis();
            long timeTaken = (endTime - startTime);  
            System.out.println("Encryption completed in " + timeTaken + " milliseconds.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}*/


import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.nio.file.*;
import java.util.Base64;
import java.util.Scanner;

public class EncryptFilesInFolder {

    // Encrypt the byte array using AES and return the encrypted content with IV prepended
    public static String encrypt(byte[] fileContent, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] ivBytes = new byte[16]; // 128-bit IV (AES block size)
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] encryptedBytes = cipher.doFinal(fileContent);

        // Combine IV + encrypted data
        byte[] ivAndEncryptedData = new byte[ivBytes.length + encryptedBytes.length];
        System.arraycopy(ivBytes, 0, ivAndEncryptedData, 0, ivBytes.length);
        System.arraycopy(encryptedBytes, 0, ivAndEncryptedData, ivBytes.length, encryptedBytes.length);

        return Base64.getEncoder().encodeToString(ivAndEncryptedData);  // Return as Base64 string
    }

    // Generate a new AES key and save it to a file
    public static void generateAndSaveKey(String keyFilePath) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);  // Use AES-256
        SecretKey secretKey = keyGenerator.generateKey();
        // Save the AES key to a file
        try (ObjectOutputStream keyOut = new ObjectOutputStream(new FileOutputStream(keyFilePath))) {
            keyOut.writeObject(secretKey);  // Serialize the SecretKey object
        }
    }

    // Read the AES key from the file
    public static SecretKey readKeyFromFile(String keyFilePath) throws IOException, ClassNotFoundException {
        try (ObjectInputStream keyIn = new ObjectInputStream(new FileInputStream(keyFilePath))) {
            return (SecretKey) keyIn.readObject();  // Deserialize the SecretKey object
        }
    }

    // Encrypt all files in the folder
    public static void encryptFilesInFolder(String folderPath, SecretKey secretKey) throws IOException {
        File folder = new File(folderPath);
        File[] files = folder.listFiles((dir, name) -> !name.equals("encryption.key"));  // Exclude the encryption key file

        for (File file : files) {
            if (file.isFile()) {
                try {
                    // Read file content as binary (byte array)
                    byte[] fileContent = Files.readAllBytes(file.toPath());
                    String encryptedContent = encrypt(fileContent, secretKey);

                    // Save the encrypted content with a ".encrypted" extension
                    String encryptedFilePath = file.getAbsolutePath() + ".encrypted";
                    Files.write(Paths.get(encryptedFilePath), encryptedContent.getBytes());

                    // Save the file extension for later decryption
                    String extensionFilePath = file.getAbsolutePath() + ".ext";
                    Files.write(Paths.get(extensionFilePath), file.getName().getBytes());

                    // Remove the original file after encryption
                    file.delete();
                    System.out.println("Encrypted and removed: " + file.getAbsolutePath());
                } catch (Exception e) {
                    System.err.println("Error encrypting file " + file.getAbsolutePath() + ": " + e.getMessage());
                }
            }
        }
    }

    public static void main(String[] args) {
        // Instead of command-line argument, we prompt for user input
        Scanner scanner = new Scanner(System.in);
        System.out.println("Please enter the folder path to encrypt:");
        String folderPath = scanner.nextLine(); // Read folder path from user input

        String keyFilePath = "encryption.key";  // Save the key to a file in the project directory

        try {
            // Generate and save the AES key
            generateAndSaveKey(keyFilePath);

            // Read the generated AES key from the file
            SecretKey secretKey = readKeyFromFile(keyFilePath);

            // Start the timer
            long startTime = System.currentTimeMillis();

            // Encrypt all files in the folder
            encryptFilesInFolder(folderPath, secretKey);

            // End the timer
            long endTime = System.currentTimeMillis();
            long timeTaken = (endTime - startTime);  
            System.out.println("Encryption completed in " + timeTaken + " milliseconds.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}