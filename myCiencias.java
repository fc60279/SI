import java.io.*;
import java.net.*;
import java.security.*;
import java.util.logging.*;
import javax.crypto.SecretKey;

public class myCiencias {
    private final String serverAddress;
    private final int serverPort;
    private final String emitterUser;
    private final String studentUser;
    private final Logger logger;
    private Socket socket;
    private DataOutputStream out;
    private DataInputStream in;
    private KeyStore emitterKeyStore;
    private static final String KEYSTORE_PASSWORD = "123456";

    public myCiencias(String serverAddress, int serverPort, String emitterUser, String studentUser) {
        this.serverAddress = serverAddress;
        this.serverPort = serverPort;
        this.emitterUser = emitterUser;
        this.studentUser = studentUser;
        this.logger = Logger.getLogger("myCiencias");
        setupLogging();
        if (emitterUser != null) {
            loadEmitterKeyStore();
        }
    }

    private void loadEmitterKeyStore() {
        try {
            emitterKeyStore = CryptoUtils.loadKeyStore(emitterUser, KEYSTORE_PASSWORD);
        } catch (Exception e) {
            logger.severe("Failed to load emitter keystore: " + e.getMessage());
            System.exit(1);
        }
    }

    private void setupLogging() {
        try {
            FileHandler fileHandler = new FileHandler("client.log");
            fileHandler.setFormatter(new SimpleFormatter());
            logger.addHandler(fileHandler);
            logger.setLevel(Level.INFO);
        } catch (IOException e) {
            System.err.println("Failed to setup logging: " + e.getMessage());
        }
    }

    private void connect() throws IOException {
        socket = new Socket(serverAddress, serverPort);
        out = new DataOutputStream(socket.getOutputStream());
        in = new DataInputStream(socket.getInputStream());
        logger.info("Connected to server at " + serverAddress + ":" + serverPort);
    }

    public void encryptAndSendFiles(String[] filenames) {
        try {
            connect();
            
            // Get student's certificate
            out.writeUTF("GET_CERT:" + studentUser);
            String response = in.readUTF();
            if (!response.startsWith("SUCCESS:")) {
                throw new Exception("Failed to get student certificate: " + response);
            }
            
            String certB64 = response.substring(8);
            byte[] certBytes = java.util.Base64.getDecoder().decode(certB64);
            java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
            java.security.cert.Certificate cert = cf.generateCertificate(new ByteArrayInputStream(certBytes));
            
            for (String filename : filenames) {
                try {
                    logger.info("Processing file for encryption: " + filename);
                    
                    // Read file
                    byte[] fileData = CryptoUtils.readFile(filename);
                    
                    // Generate and encrypt AES key
                    SecretKey aesKey = CryptoUtils.generateAESKey();
                    byte[] encryptedKey = CryptoUtils.encryptAESKey(aesKey, cert.getPublicKey());
                    
                    // Encrypt file
                    byte[] encryptedData = CryptoUtils.encryptFile(fileData, aesKey);
                    
                    // Send to server
                    out.writeUTF("STORE_ENCRYPTED:" + studentUser + ":" + filename);
                    out.writeInt(encryptedData.length);
                    out.write(encryptedData);
                    out.writeInt(encryptedKey.length);
                    out.write(encryptedKey);
                    
                    response = in.readUTF();
                    if (!response.startsWith("SUCCESS:")) {
                        throw new Exception("Failed to store encrypted file: " + response);
                    }
                    
                    logger.info("Successfully encrypted and sent file: " + filename);
                } catch (Exception e) {
                    logger.severe("Error processing file " + filename + ": " + e.getMessage());
                    // Continue with next file
                }
            }
        } catch (Exception e) {
            logger.severe("Error in encryptAndSendFiles: " + e.getMessage());
        } finally {
            disconnect();
        }
    }

    public void signAndSendFiles(String[] filenames) {
        try {
            connect();
            
            PrivateKey privateKey = (PrivateKey) emitterKeyStore.getKey(emitterUser, KEYSTORE_PASSWORD.toCharArray());
            
            for (String filename : filenames) {
                try {
                    logger.info("Processing file for signing: " + filename);
                    
                    // Read and sign file
                    byte[] fileData = CryptoUtils.readFile(filename);
                    byte[] signature = CryptoUtils.signFile(fileData, privateKey);
                    
                    // Send to server
                    out.writeUTF("STORE_SIGNED:" + studentUser + ":" + filename + ":" + emitterUser);
                    out.writeInt(fileData.length);
                    out.write(fileData);
                    out.writeInt(signature.length);
                    out.write(signature);
                    
                    String response = in.readUTF();
                    if (!response.startsWith("SUCCESS:")) {
                        throw new Exception("Failed to store signed file: " + response);
                    }
                    
                    logger.info("Successfully signed and sent file: " + filename);
                } catch (Exception e) {
                    logger.severe("Error processing file " + filename + ": " + e.getMessage());
                    // Continue with next file
                }
            }
        } catch (Exception e) {
            logger.severe("Error in signAndSendFiles: " + e.getMessage());
        } finally {
            disconnect();
        }
    }

    public void signEncryptAndSendFiles(String[] filenames) {
        try {
            connect();
            
            // Get student's certificate
            out.writeUTF("GET_CERT:" + studentUser);
            String response = in.readUTF();
            if (!response.startsWith("SUCCESS:")) {
                throw new Exception("Failed to get student certificate: " + response);
            }
            
            String certB64 = response.substring(8);
            byte[] certBytes = java.util.Base64.getDecoder().decode(certB64);
            java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
            java.security.cert.Certificate cert = cf.generateCertificate(new ByteArrayInputStream(certBytes));
            
            PrivateKey privateKey = (PrivateKey) emitterKeyStore.getKey(emitterUser, KEYSTORE_PASSWORD.toCharArray());
            
            for (String filename : filenames) {
                try {
                    logger.info("Processing file for secure envelope: " + filename);
                    
                    // Read file
                    byte[] fileData = CryptoUtils.readFile(filename);
                    
                    // Sign file
                    byte[] signature = CryptoUtils.signFile(fileData, privateKey);
                    
                    // Generate and encrypt AES key
                    SecretKey aesKey = CryptoUtils.generateAESKey();
                    byte[] encryptedKey = CryptoUtils.encryptAESKey(aesKey, cert.getPublicKey());
                    
                    // Encrypt file
                    byte[] encryptedData = CryptoUtils.encryptFile(fileData, aesKey);
                    
                    // Send to server
                    out.writeUTF("STORE_SECURE:" + studentUser + ":" + filename + ":" + emitterUser);
                    out.writeInt(encryptedData.length);
                    out.write(encryptedData);
                    out.writeInt(encryptedKey.length);
                    out.write(encryptedKey);
                    out.writeInt(signature.length);
                    out.write(signature);
                    
                    response = in.readUTF();
                    if (!response.startsWith("SUCCESS:")) {
                        throw new Exception("Failed to store secure file: " + response);
                    }
                    
                    logger.info("Successfully created secure envelope and sent file: " + filename);
                } catch (Exception e) {
                    logger.severe("Error processing file " + filename + ": " + e.getMessage());
                    // Continue with next file
                }
            }
        } catch (Exception e) {
            logger.severe("Error in signEncryptAndSendFiles: " + e.getMessage());
        } finally {
            disconnect();
        }
    }

    public void getFiles(String[] filenames) {
        try {
            connect();
            
            for (String filename : filenames) {
                try {
                    logger.info("Requesting file: " + filename);
                    
                    out.writeUTF("GET_FILE_INFO:" + studentUser + ":" + filename);
                    String response = in.readUTF();
                    
                    if (!response.startsWith("SUCCESS:")) {
                        throw new Exception("Failed to get file " + filename + ": " + response);
                    }
                    
                    String[] parts = response.substring(8).split(":");
                    String type = parts[0];
                    String emitter = parts.length > 1 ? parts[1] : null;
                    
                    switch (type) {
                        case "ENCRYPTED":
                            handleEncryptedFile(filename);
                            break;
                        case "SIGNED":
                            handleSignedFile(filename, emitter);
                            break;
                        case "SECURE":
                            handleSecureFile(filename, emitter);
                            break;
                        default:
                            throw new Exception("Unknown file type: " + type);
                    }
                } catch (Exception e) {
                    logger.severe("Error processing file " + filename + ": " + e.getMessage());
                    // Continue with next file
                }
            }
        } catch (Exception e) {
            logger.severe("Error in getFiles: " + e.getMessage());
        } finally {
            disconnect();
        }
    }

    private void handleEncryptedFile(String filename) throws Exception {
        // Read encrypted data
        int dataLength = in.readInt();
        byte[] encryptedData = new byte[dataLength];
        in.readFully(encryptedData);
        
        // Read encrypted key
        int keyLength = in.readInt();
        byte[] encryptedKey = new byte[keyLength];
        in.readFully(encryptedKey);
        
        // Load student's private key
        KeyStore studentKeyStore = CryptoUtils.loadKeyStore(studentUser, KEYSTORE_PASSWORD);
        PrivateKey privateKey = (PrivateKey) studentKeyStore.getKey(studentUser, KEYSTORE_PASSWORD.toCharArray());
        
        // Decrypt AES key and file
        SecretKey aesKey = CryptoUtils.decryptAESKey(encryptedKey, privateKey);
        byte[] fileData = CryptoUtils.decryptFile(encryptedData, aesKey);
        
        // Save the file with its original name or with a number suffix if it already exists
        String outputFilename = getUniqueFilename(filename);
        CryptoUtils.writeFile(outputFilename, fileData);
        logger.info("Successfully decrypted file: " + filename + " saved as: " + outputFilename);
    }

    private void handleSignedFile(String filename, String emitterUser) throws Exception {
        // Read file data
        int dataLength = in.readInt();
        byte[] fileData = new byte[dataLength];
        in.readFully(fileData);
        
        // Read signature
        int signatureLength = in.readInt();
        byte[] signature = new byte[signatureLength];
        in.readFully(signature);
        
        // Load emitter's certificate
        KeyStore emitterKeyStore = CryptoUtils.loadKeyStore(emitterUser, KEYSTORE_PASSWORD);
        java.security.cert.Certificate cert = emitterKeyStore.getCertificate(emitterUser);
        
        // Verify signature
        boolean valid = CryptoUtils.verifySignature(fileData, signature, cert.getPublicKey());
        if (!valid) {
            logger.severe("Invalid signature for file: " + filename);
            return;
        }
        
        // Save the file with its original name or with a number suffix if it already exists
        String outputFilename = getUniqueFilename(filename);
        CryptoUtils.writeFile(outputFilename, fileData);
        logger.info("Successfully verified file: " + filename + " saved as: " + outputFilename);
    }

    private void handleSecureFile(String filename, String emitterUser) throws Exception {
        // Read encrypted data
        int dataLength = in.readInt();
        byte[] encryptedData = new byte[dataLength];
        in.readFully(encryptedData);
        
        // Read encrypted key
        int keyLength = in.readInt();
        byte[] encryptedKey = new byte[keyLength];
        in.readFully(encryptedKey);
        
        // Read signature
        int signatureLength = in.readInt();
        byte[] signature = new byte[signatureLength];
        in.readFully(signature);
        
        // Load student's private key
        KeyStore studentKeyStore = CryptoUtils.loadKeyStore(studentUser, KEYSTORE_PASSWORD);
        PrivateKey privateKey = (PrivateKey) studentKeyStore.getKey(studentUser, KEYSTORE_PASSWORD.toCharArray());
        
        // Decrypt AES key and file
        SecretKey aesKey = CryptoUtils.decryptAESKey(encryptedKey, privateKey);
        byte[] fileData = CryptoUtils.decryptFile(encryptedData, aesKey);
        
        // Load emitter's certificate and verify signature
        KeyStore emitterKeyStore = CryptoUtils.loadKeyStore(emitterUser, KEYSTORE_PASSWORD);
        java.security.cert.Certificate cert = emitterKeyStore.getCertificate(emitterUser);
        
        boolean valid = CryptoUtils.verifySignature(fileData, signature, cert.getPublicKey());
        if (!valid) {
            logger.severe("Invalid signature for file: " + filename);
            return;
        }
        
        // Save the file with its original name or with a number suffix if it already exists
        String outputFilename = getUniqueFilename(filename);
        CryptoUtils.writeFile(outputFilename, fileData);
        logger.info("Successfully decrypted and verified file: " + filename + " saved as: " + outputFilename);
    }

    /**
     * Creates a unique filename by adding a number suffix if the file already exists.
     * For example, if "file.txt" exists, it returns "file2.txt", and if that exists too,
     * it returns "file3.txt", and so on.
     */
    private String getUniqueFilename(String filename) {
        File file = new File(filename);
        if (!file.exists()) {
            return filename;
        }
        
        // If file exists, try adding a number before the extension
        String name = filename;
        String extension = "";
        int dotIndex = filename.lastIndexOf('.');
        if (dotIndex > 0) {
            name = filename.substring(0, dotIndex);
            extension = filename.substring(dotIndex);
        }
        
        int counter = 2;
        String newFilename;
        do {
            newFilename = name + counter + extension;
            counter++;
        } while (new File(newFilename).exists());
        
        return newFilename;
    }

    private void disconnect() {
        try {
            if (out != null) out.close();
            if (in != null) in.close();
            if (socket != null) socket.close();
        } catch (IOException e) {
            logger.warning("Error closing connection: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        if (args.length < 3) {
            System.out.println("Usage for sending files:");
            System.out.println("  java myCiencias -a <serverAddress> -u <emitterUser> -e <studentUser> [-c|-s|-b] {<filenames>}+");
            System.out.println("Usage for retrieving files:");
            System.out.println("  java myCiencias -a <serverAddress> -e <studentUser> -g {<filenames>}+");
            System.exit(1);
        }

        String serverArg = null;
        String serverHost = null;
        int serverPort = -1;
        String emitterUser = null;
        String studentUser = null;
        String operation = null;
        String[] filenames = null;

        // Find operation first
        for (int i = 0; i < args.length; i++) {
            if (args[i].equals("-c") || args[i].equals("-s") || args[i].equals("-b") || args[i].equals("-g")) {
                operation = args[i];
                break;
            }
        }

        // Parse other arguments
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            switch (arg) {
                case "-a":
                    if (i + 1 >= args.length) {
                        System.out.println("Missing server address");
                        System.exit(1);
                    }
                    String[] parts = args[++i].split(":");
                    if (parts.length != 2) {
                        System.out.println("Invalid server address format. Use: hostname:port");
                        System.exit(1);
                    }
                    serverHost = parts[0];
                    try {
                        serverPort = Integer.parseInt(parts[1]);
                    } catch (NumberFormatException e) {
                        System.out.println("Invalid port number");
                        System.exit(1);
                    }
                    serverArg = args[i];
                    break;
                case "-u":
                    if (i + 1 >= args.length) {
                        System.out.println("Missing emitter user");
                        System.exit(1);
                    }
                    emitterUser = args[++i];
                    break;
                case "-e":
                    if (i + 1 >= args.length) {
                        System.out.println("Missing student user");
                        System.exit(1);
                    }
                    studentUser = args[++i];
                    break;
                case "-c":
                case "-s":
                case "-b":
                case "-g":
                    if (i + 1 >= args.length) {
                        System.out.println("Missing filenames");
                        System.exit(1);
                    }
                    filenames = new String[args.length - i - 1];
                    System.arraycopy(args, i + 1, filenames, 0, filenames.length);
                    i = args.length;
                    break;
            }
        }

        // Validate required arguments
        if (serverHost == null || serverPort == -1) {
            System.out.println("Server address (-a) is required");
            System.exit(1);
        }
        if (studentUser == null) {
            System.out.println("Student user (-e) is required");
            System.exit(1);
        }
        if (operation == null || filenames == null || filenames.length == 0) {
            System.out.println("Operation (-c, -s, -b, or -g) and filenames are required");
            System.exit(1);
        }
        if (!operation.equals("-g") && emitterUser == null) {
            System.out.println("Emitter user (-u) is required for operations -c, -s, and -b");
            System.exit(1);
        }

        myCiencias client = new myCiencias(serverHost, serverPort, emitterUser, studentUser);

        switch (operation) {
            case "-c":
                client.encryptAndSendFiles(filenames);
                break;
            case "-s":
                client.signAndSendFiles(filenames);
                break;
            case "-b":
                client.signEncryptAndSendFiles(filenames);
                break;
            case "-g":
                client.getFiles(filenames);
                break;
        }
    }
} 