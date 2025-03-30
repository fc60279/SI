import java.io.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.cert.*;
import java.util.logging.*;

public class CryptoUtils {
    private static final String KEYSTORE_TYPE = "PKCS12";
    private static final String KEY_ALGORITHM = "RSA";
    private static final String CIPHER_ALGORITHM = "AES";
    private static final int RSA_KEY_SIZE = 2048;
    private static final int AES_KEY_SIZE = 128;
    private static final Logger logger = Logger.getLogger("CryptoUtils");

    static {
        try {
            FileHandler fileHandler = new FileHandler("crypto.log");
            fileHandler.setFormatter(new SimpleFormatter());
            logger.addHandler(fileHandler);
            logger.setLevel(Level.INFO);
        } catch (IOException e) {
            System.err.println("Failed to setup logging: " + e.getMessage());
        }
    }

    public static KeyStore loadKeyStore(String username, String password) throws Exception {
        String keystoreFile = username + ".keystore";
        KeyStore keystore = KeyStore.getInstance(KEYSTORE_TYPE);
        
        try (FileInputStream fis = new FileInputStream(keystoreFile)) {
            keystore.load(fis, password.toCharArray());
            logger.info("Loaded keystore for user: " + username);
            return keystore;
        } catch (FileNotFoundException e) {
            throw new Exception("Keystore not found for user: " + username);
        } catch (Exception e) {
            throw new Exception("Failed to load keystore: " + e.getMessage());
        }
    }

    public static byte[] encryptFile(byte[] fileData, SecretKey key) throws Exception {
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedData = cipher.doFinal(fileData);
            logger.info("File encrypted successfully");
            return encryptedData;
        } catch (Exception e) {
            throw new Exception("Failed to encrypt file: " + e.getMessage());
        }
    }

    public static byte[] decryptFile(byte[] encryptedData, SecretKey key) throws Exception {
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] decryptedData = cipher.doFinal(encryptedData);
            logger.info("File decrypted successfully");
            return decryptedData;
        } catch (Exception e) {
            throw new Exception("Failed to decrypt file: " + e.getMessage());
        }
    }

    public static byte[] signFile(byte[] fileData, PrivateKey privateKey) throws Exception {
        try {
            Signature signature = Signature.getInstance("SHA256with" + KEY_ALGORITHM);
            signature.initSign(privateKey);
            signature.update(fileData);
            byte[] signatureBytes = signature.sign();
            logger.info("File signed successfully");
            return signatureBytes;
        } catch (Exception e) {
            throw new Exception("Failed to sign file: " + e.getMessage());
        }
    }

    public static boolean verifySignature(byte[] fileData, byte[] signatureBytes, PublicKey publicKey) throws Exception {
        try {
            Signature signature = Signature.getInstance("SHA256with" + KEY_ALGORITHM);
            signature.initVerify(publicKey);
            signature.update(fileData);
            boolean valid = signature.verify(signatureBytes);
            logger.info("Signature verification result: " + valid);
            return valid;
        } catch (Exception e) {
            throw new Exception("Failed to verify signature: " + e.getMessage());
        }
    }

    public static SecretKey generateAESKey() throws Exception {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(CIPHER_ALGORITHM);
            keyGen.init(AES_KEY_SIZE);
            SecretKey key = keyGen.generateKey();
            logger.info("Generated new AES key");
            return key;
        } catch (Exception e) {
            throw new Exception("Failed to generate AES key: " + e.getMessage());
        }
    }

    public static byte[] encryptAESKey(SecretKey aesKey, PublicKey publicKey) throws Exception {
        try {
            Cipher cipher = Cipher.getInstance(KEY_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedKey = cipher.doFinal(aesKey.getEncoded());
            logger.info("AES key encrypted successfully");
            return encryptedKey;
        } catch (Exception e) {
            throw new Exception("Failed to encrypt AES key: " + e.getMessage());
        }
    }

    public static SecretKey decryptAESKey(byte[] encryptedKey, PrivateKey privateKey) throws Exception {
        try {
            Cipher cipher = Cipher.getInstance(KEY_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] keyBytes = cipher.doFinal(encryptedKey);
            SecretKey aesKey = new SecretKeySpec(keyBytes, CIPHER_ALGORITHM);
            logger.info("AES key decrypted successfully");
            return aesKey;
        } catch (Exception e) {
            throw new Exception("Failed to decrypt AES key: " + e.getMessage());
        }
    }

    public static byte[] readFile(String filename) throws Exception {
        try {
            File file = new File(filename);
            byte[] fileData = new byte[(int) file.length()];
            try (FileInputStream fis = new FileInputStream(file)) {
                fis.read(fileData);
            }
            logger.info("Read file: " + filename);
            return fileData;
        } catch (Exception e) {
            throw new Exception("Failed to read file " + filename + ": " + e.getMessage());
        }
    }

    public static void writeFile(String filename, byte[] data) throws Exception {
        try (FileOutputStream fos = new FileOutputStream(filename)) {
            fos.write(data);
            logger.info("Wrote file: " + filename);
        } catch (Exception e) {
            throw new Exception("Failed to write file " + filename + ": " + e.getMessage());
        }
    }
} 