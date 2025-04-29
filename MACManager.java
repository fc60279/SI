import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.logging.*;

public class MACManager {
    private static final String MAC_FILE = "users.mac";
    private static final String MAC_ALGORITHM = "HmacSHA256";
    private static final Logger logger = Logger.getLogger("MACManager");

    static {
        try {
            FileHandler fileHandler = new FileHandler("mac.log");
            fileHandler.setFormatter(new SimpleFormatter());
            logger.addHandler(fileHandler);
            logger.setLevel(Level.INFO);
        } catch (IOException e) {
            System.err.println("Failed to setup logging: " + e.getMessage());
        }
    }

    public static SecretKey deriveKey(String adminPassword) throws Exception {
        if (adminPassword == null || adminPassword.isEmpty()) {
            throw new IllegalArgumentException("Admin password cannot be empty");
        }
        
        try {
            logger.info("Deriving MAC key from admin password");
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(adminPassword.getBytes());
            return new SecretKeySpec(hash, MAC_ALGORITHM);
        } catch (Exception e) {
            logger.severe("Error deriving key: " + e.getMessage());
            throw new Exception("Failed to derive key: " + e.getMessage(), e);
        }
    }

    public static String calculateMAC(String content, SecretKey key) throws Exception {
        if (content == null) {
            throw new IllegalArgumentException("Content cannot be null");
        }
        if (key == null) {
            throw new IllegalArgumentException("Key cannot be null");
        }
        
        try {
            logger.fine("Calculating MAC for content");
            Mac mac = Mac.getInstance(MAC_ALGORITHM);
            mac.init(key);
            byte[] macBytes = mac.doFinal(content.getBytes());
            String result = Base64.getEncoder().encodeToString(macBytes);
            logger.fine("MAC calculated successfully");
            return result;
        } catch (Exception e) {
            logger.severe("Error calculating MAC: " + e.getMessage());
            throw new Exception("Failed to calculate MAC: " + e.getMessage(), e);
        }
    }

    public static boolean verifyMAC(String content, String storedMAC, SecretKey key) throws Exception {
        if (content == null || storedMAC == null || key == null) {
            logger.warning("Null parameters in verifyMAC");
            return false;
        }
        
        try {
            String calculatedMAC = calculateMAC(content, key);
            boolean result = calculatedMAC.equals(storedMAC);
            if (result) {
                logger.info("MAC verification successful");
            } else {
                logger.warning("MAC verification failed");
            }
            return result;
        } catch (Exception e) {
            logger.severe("Error verifying MAC: " + e.getMessage());
            throw new Exception("Failed to verify MAC: " + e.getMessage(), e);
        }
    }

    public static void saveMAC(String mac) throws IOException {
        if (mac == null || mac.isEmpty()) {
            throw new IllegalArgumentException("MAC cannot be empty");
        }
        
        try {
            logger.info("Saving MAC to file: " + MAC_FILE);
            try (PrintWriter writer = new PrintWriter(new FileWriter(MAC_FILE))) {
                writer.println(mac);
            }
            logger.info("MAC saved successfully");
        } catch (IOException e) {
            logger.severe("Error saving MAC: " + e.getMessage());
            throw e;
        }
    }

    public static String loadMAC() throws IOException {
        File file = new File(MAC_FILE);
        if (!file.exists()) {
            logger.warning("MAC file not found: " + MAC_FILE);
            return null;
        }
        
        try {
            logger.info("Loading MAC from file: " + MAC_FILE);
            try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
                String mac = reader.readLine();
                if (mac == null || mac.isEmpty()) {
                    logger.warning("MAC file is empty");
                    return null;
                }
                logger.info("MAC loaded successfully");
                return mac;
            }
        } catch (IOException e) {
            logger.severe("Error loading MAC: " + e.getMessage());
            throw e;
        }
    }

    public static boolean fileNeedsMAC() {
        boolean exists = new File(MAC_FILE).exists();
        logger.info("Checking if MAC file exists: " + exists);
        return !exists;
    }
} 