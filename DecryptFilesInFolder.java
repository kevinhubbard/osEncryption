import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.nio.file.*;
import java.util.Base64;

public class DecryptFilesInFolder {

    // Decrypt the Base64-encoded string using AES and return the decrypted byte content
    public static byte[] decrypt(String encryptedContent, SecretKey key) throws Exception {
        byte[] ivAndEncryptedData = Base64.getDecoder().decode(encryptedContent);  // Decode the Base64 string

        // Extract the IV (the first 16 bytes) and the actual encrypted data
        byte[] ivBytes = new byte[16];
        System.arraycopy(ivAndEncryptedData, 0, ivBytes, 0, ivBytes.length);
        IvParameterSpec iv = new IvParameterSpec(ivBytes);

        byte[] encryptedBytes = new byte[ivAndEncryptedData.length - ivBytes.length];
        System.arraycopy(ivAndEncryptedData, ivBytes.length, encryptedBytes, 0, encryptedBytes.length);

        // Decrypt using the extracted IV
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        return cipher.doFinal(encryptedBytes);  // Return decrypted byte array
    }

    // Read the AES key from the file
    public static SecretKey readKeyFromFile(String keyFilePath) throws IOException, ClassNotFoundException {
        try (ObjectInputStream keyIn = new ObjectInputStream(new FileInputStream(keyFilePath))) {
            return (SecretKey) keyIn.readObject();  // Deserialize the SecretKey object
        }
    }

    // Decrypt all files in the folder
    public static void decryptFilesInFolder(String folderPath, SecretKey secretKey) throws IOException {
        File folder = new File(folderPath);
        File[] files = folder.listFiles((dir, name) -> name.endsWith(".encrypted"));  // Only encrypted files

        for (File file : files) {
            try {
                // Read the encrypted file content as binary
                byte[] fileContent = Files.readAllBytes(file.toPath());
                String encryptedContent = new String(fileContent);

                // Decrypt the content
                byte[] decryptedContent = decrypt(encryptedContent, secretKey);

                // Read the original extension from the .ext file
                String extensionFilePath = file.getAbsolutePath().replace(".encrypted", ".ext");
                String originalExtension = new String(Files.readAllBytes(Paths.get(extensionFilePath)));

                // Correct the decrypted file path by removing the .encrypted extension and adding the original extension
                String decryptedFilePath = file.getAbsolutePath().replace(".encrypted", "." + originalExtension);

                // Write the decrypted content as binary to the new file
                Files.write(Paths.get(decryptedFilePath), decryptedContent);

                // Remove the encrypted file and the .ext file after decryption
                file.delete();
                new File(extensionFilePath).delete();
                //System.out.println("Decrypted and removed: " + file.getAbsolutePath());
            } catch (Exception e) {
                System.err.println("Error decrypting file " + file.getAbsolutePath() + ": " + e.getMessage());
            }
        }
    }

    public static void main(String[] args) {
        if (args.length != 2) {
            System.out.println("Usage: java DecryptFilesInFolder <keyFilePath> <folderPath>");
            return;
        }

        String keyFilePath = args[0];
        String folderPath = args[1];

        try {
            // Read the AES key from the file
            SecretKey secretKey = readKeyFromFile(keyFilePath);

            // Start the timer
            long startTime = System.currentTimeMillis();

            // Decrypt all files in the folder
            decryptFilesInFolder(folderPath, secretKey);

            // End the timer
            long endTime = System.currentTimeMillis();
            long timeTaken = (endTime - startTime);
            System.out.println("Decryption completed in " + timeTaken + " milliseconds.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}