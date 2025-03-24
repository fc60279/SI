import java.io.*;
import java.net.*;
import java.security.*;
import java.util.concurrent.*;
import java.util.logging.*;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class myCienciasServer {
    private final int port;
    private final ExecutorService executorService;
    private final Logger logger;
    private volatile boolean running;
    private ServerSocket serverSocket;
    private final String baseDirectory = "server_files";

    public myCienciasServer(int port) {
        this.port = port;
        this.executorService = Executors.newCachedThreadPool();
        this.logger = Logger.getLogger("myCienciasServer");
        setupLogging();
        createBaseDirectory();
    }

    private void setupLogging() {
        try {
            FileHandler fileHandler = new FileHandler("server.log");
            fileHandler.setFormatter(new SimpleFormatter());
            logger.addHandler(fileHandler);
            logger.setLevel(Level.INFO);
        } catch (IOException e) {
            System.err.println("Failed to setup logging: " + e.getMessage());
        }
    }

    private void createBaseDirectory() {
        File directory = new File(baseDirectory);
        if (!directory.exists()) {
            directory.mkdirs();
        }
    }

    private String getStudentDirectory(String studentUser) {
        String dir = baseDirectory + File.separator + studentUser;
        new File(dir).mkdirs();
        return dir;
    }

    public void start() {
        running = true;
        try {
            serverSocket = new ServerSocket(port);
            logger.info("Server started on port " + port);
            System.out.println("Server started on port " + port);
            
            while (running) {
                try {
                    Socket clientSocket = serverSocket.accept();
                    logger.info("New client connected from " + clientSocket.getInetAddress());
                    executorService.submit(() -> handleClient(clientSocket));
                } catch (IOException e) {
                    if (running) {
                        logger.severe("Error accepting client connection: " + e.getMessage());
                    }
                }
            }
        } catch (IOException e) {
            logger.severe("Error starting server: " + e.getMessage());
        }
    }

    private void handleClient(Socket clientSocket) {
        try (
            DataInputStream in = new DataInputStream(clientSocket.getInputStream());
            DataOutputStream out = new DataOutputStream(clientSocket.getOutputStream())
        ) {
            boolean clientConnected = true;
            
            while (clientConnected && running) {
                try {
                    String command = in.readUTF();
                    logger.info("Received command: " + command);
                    
                    String[] parts = command.split(":");
                    switch (parts[0]) {
                        case "GET_CERT":
                            if (parts.length >= 2) {
                                String user = parts[1];
                                handleGetCertificate(user, out);
                            }
                            break;
                        case "STORE_ENCRYPTED":
                            if (parts.length >= 3) {
                                String studentUser = parts[1];
                                String filename = parts[2];
                                handleStoreEncrypted(studentUser, filename, in, out);
                            }
                            break;
                        case "STORE_SIGNED":
                            if (parts.length >= 4) {
                                String studentUser = parts[1];
                                String filename = parts[2];
                                String emitterUser = parts[3];
                                handleStoreSigned(studentUser, filename, emitterUser, in, out);
                            }
                            break;
                        case "STORE_SECURE":
                            if (parts.length >= 4) {
                                String studentUser = parts[1];
                                String filename = parts[2];
                                String emitterUser = parts[3];
                                handleStoreSecure(studentUser, filename, emitterUser, in, out);
                            }
                            break;
                        case "GET_FILE_INFO":
                            if (parts.length >= 3) {
                                String studentUser = parts[1];
                                String filename = parts[2];
                                handleGetFileInfo(studentUser, filename, out);
                            } else {
                                logger.severe("Invalid GET_FILE_INFO command: " + command);
                                out.writeUTF("ERROR:Invalid command format");
                            }
                            break;
                        case "DISCONNECT":
                            clientConnected = false;
                            break;
                        default:
                            logger.warning("Unknown command: " + command);
                            out.writeUTF("ERROR:Unknown command");
                    }
                } catch (EOFException | SocketException e) {
                    // Client disconnected
                    clientConnected = false;
                }
            }
            
            logger.info("Client disconnected");
        } catch (Exception e) {
            logger.severe("Error handling client: " + e.getMessage());
        }
    }

    private void handleGetCertificate(String username, DataOutputStream out) throws Exception {
        try {
            KeyStore keystore = CryptoUtils.loadKeyStore(username, "123456");
            X509Certificate cert = (X509Certificate) keystore.getCertificate(username);
            String certB64 = Base64.getEncoder().encodeToString(cert.getEncoded());
            out.writeUTF("SUCCESS:" + certB64);
        } catch (Exception e) {
            logger.severe("Error getting certificate for " + username + ": " + e.getMessage());
            out.writeUTF("ERROR:" + e.getMessage());
        }
    }

    private void handleStoreEncrypted(String studentUser, String filename, DataInputStream in, DataOutputStream out) throws Exception {
        try {
            String dir = getStudentDirectory(studentUser);
            logger.info("Storing encrypted file for student " + studentUser + ": " + filename);
            
            // Read encrypted data
            int dataLength = in.readInt();
            byte[] encryptedData = new byte[dataLength];
            in.readFully(encryptedData);
            
            // Read encrypted key
            int keyLength = in.readInt();
            byte[] encryptedKey = new byte[keyLength];
            in.readFully(encryptedKey);
            
            // Save files
            String encryptedFile = dir + File.separator + filename + ".encrypted";
            String keyFile = dir + File.separator + filename + ".secretKey." + studentUser;
            
            try (FileOutputStream fos = new FileOutputStream(encryptedFile)) {
                fos.write(encryptedData);
            }
            try (FileOutputStream fos = new FileOutputStream(keyFile)) {
                fos.write(encryptedKey);
            }
            
            logger.info("Successfully stored encrypted file: " + filename);
            out.writeUTF("SUCCESS:File stored");
        } catch (Exception e) {
            logger.severe("Error storing encrypted file: " + e.getMessage());
            out.writeUTF("ERROR:" + e.getMessage());
        }
    }

    private void handleStoreSigned(String studentUser, String filename, String emitterUser, DataInputStream in, DataOutputStream out) throws Exception {
        try {
            String dir = getStudentDirectory(studentUser);
            logger.info("Storing signed file for student " + studentUser + " from emitter " + emitterUser + ": " + filename);
            
            // Read file data
            int dataLength = in.readInt();
            byte[] fileData = new byte[dataLength];
            in.readFully(fileData);
            
            // Read signature
            int signatureLength = in.readInt();
            byte[] signature = new byte[signatureLength];
            in.readFully(signature);
            
            // Save files
            String signedFile = dir + File.separator + filename + ".signed";
            String signatureFile = dir + File.separator + filename + ".signature." + emitterUser;
            
            try (FileOutputStream fos = new FileOutputStream(signedFile)) {
                fos.write(fileData);
            }
            try (FileOutputStream fos = new FileOutputStream(signatureFile)) {
                fos.write(signature);
            }
            
            logger.info("Successfully stored signed file: " + filename);
            out.writeUTF("SUCCESS:File stored");
        } catch (Exception e) {
            logger.severe("Error storing signed file: " + e.getMessage());
            out.writeUTF("ERROR:" + e.getMessage());
        }
    }

    private void handleStoreSecure(String studentUser, String filename, String emitterUser, DataInputStream in, DataOutputStream out) throws Exception {
        try {
            String dir = getStudentDirectory(studentUser);
            logger.info("Storing secure file for student " + studentUser + " from emitter " + emitterUser + ": " + filename);
            
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
            
            // Save files
            String baseFilename = dir + File.separator + filename;
            String secureFile = baseFilename + ".secure";
            String keyFile = baseFilename + ".secretKey." + studentUser;
            String signatureFile = baseFilename + ".signature." + emitterUser;
            
            try (FileOutputStream fos = new FileOutputStream(secureFile)) {
                fos.write(encryptedData);
            }
            try (FileOutputStream fos = new FileOutputStream(keyFile)) {
                fos.write(encryptedKey);
            }
            try (FileOutputStream fos = new FileOutputStream(signatureFile)) {
                fos.write(signature);
            }
            
            logger.info("Successfully stored secure file: " + filename);
            out.writeUTF("SUCCESS:File stored");
        } catch (Exception e) {
            logger.severe("Error storing secure file: " + e.getMessage());
            out.writeUTF("ERROR:" + e.getMessage());
        }
    }

    private void handleGetFileInfo(String studentUser, String filename, DataOutputStream out) throws Exception {
        try {
            String dir = getStudentDirectory(studentUser);
            logger.info("Getting file info for student " + studentUser + ": " + filename);
            
            File secureFile = new File(dir + File.separator + filename + ".secure");
            File encryptedFile = new File(dir + File.separator + filename + ".encrypted");
            File signedFile = new File(dir + File.separator + filename + ".signed");
            
            // Verificar se existem os arquivos necessários para determinar o tipo
            boolean hasSecureFile = secureFile.exists();
            boolean hasEncryptedFile = encryptedFile.exists();
            boolean hasSignedFile = signedFile.exists();
            
            // Verificar se existe a chave cifrada para arquivos cifrados
            File secretKeyFile = new File(dir + File.separator + filename + ".secretKey." + studentUser);
            boolean hasSecretKey = secretKeyFile.exists();
            
            // Verificar se existe uma assinatura
            File[] signatureFiles = new File(dir).listFiles((d, name) -> 
                name.startsWith(filename + ".signature."));
            boolean hasSignatureFile = (signatureFiles != null && signatureFiles.length > 0);
            
            if (hasSecureFile && hasSignatureFile && hasSecretKey) {
                // Arquivo seguro (assinado e cifrado)
                String emitter = signatureFiles[0].getName().substring(
                    (filename + ".signature.").length());
                out.writeUTF("SUCCESS:SECURE:" + emitter);
                sendSecureFile(studentUser, filename, out);
            } else if (hasEncryptedFile && hasSecretKey) {
                // Arquivo cifrado
                out.writeUTF("SUCCESS:ENCRYPTED");
                sendEncryptedFile(studentUser, filename, out);
            } else if (hasSignedFile && hasSignatureFile) {
                // Arquivo assinado
                String emitter = signatureFiles[0].getName().substring(
                    (filename + ".signature.").length());
                out.writeUTF("SUCCESS:SIGNED:" + emitter);
                sendSignedFile(studentUser, filename, out);
            } else {
                // Verificar a presença de qualquer arquivo relacionado
                boolean hasAnyFile = new File(dir).listFiles((d, name) -> 
                    name.startsWith(filename + ".")).length > 0;
                
                if (hasAnyFile) {
                    // Há arquivos, mas não no formato esperado
                    logger.warning("File structure for " + filename + " is incomplete or invalid");
                    out.writeUTF("ERROR:Invalid file structure");
                } else {
                    logger.warning("File not found: " + filename);
                    out.writeUTF("ERROR:File not found");
                }
            }
        } catch (Exception e) {
            logger.severe("Error getting file info: " + e.getMessage());
            out.writeUTF("ERROR:" + e.getMessage());
        }
    }

    private void sendEncryptedFile(String studentUser, String filename, DataOutputStream out) throws Exception {
        String dir = getStudentDirectory(studentUser);
        logger.info("Sending encrypted file to student " + studentUser + ": " + filename);
        
        // Send encrypted data
        byte[] encryptedData = CryptoUtils.readFile(dir + File.separator + filename + ".encrypted");
        out.writeInt(encryptedData.length);
        out.write(encryptedData);
        
        // Send encrypted key
        byte[] encryptedKey = CryptoUtils.readFile(dir + File.separator + filename + ".secretKey." + studentUser);
        out.writeInt(encryptedKey.length);
        out.write(encryptedKey);
        
        logger.info("Successfully sent encrypted file: " + filename);
    }

    private void sendSignedFile(String studentUser, String filename, DataOutputStream out) throws Exception {
        String dir = getStudentDirectory(studentUser);
        logger.info("Sending signed file to student " + studentUser + ": " + filename);
        
        // Send file data
        byte[] fileData = CryptoUtils.readFile(dir + File.separator + filename + ".signed");
        out.writeInt(fileData.length);
        out.write(fileData);
        
        // Find and send signature
        File[] signatureFiles = new File(dir).listFiles((d, name) -> 
            name.startsWith(filename + ".signature."));
        if (signatureFiles != null && signatureFiles.length > 0) {
            byte[] signature = CryptoUtils.readFile(signatureFiles[0].getPath());
            out.writeInt(signature.length);
            out.write(signature);
            logger.info("Successfully sent signed file: " + filename);
        } else {
            throw new FileNotFoundException("Signature file not found");
        }
    }

    private void sendSecureFile(String studentUser, String filename, DataOutputStream out) throws Exception {
        String dir = getStudentDirectory(studentUser);
        logger.info("Sending secure file to student " + studentUser + ": " + filename);
        
        // Send encrypted data
        byte[] encryptedData = CryptoUtils.readFile(dir + File.separator + filename + ".secure");
        out.writeInt(encryptedData.length);
        out.write(encryptedData);
        
        // Send encrypted key
        byte[] encryptedKey = CryptoUtils.readFile(dir + File.separator + filename + ".secretKey." + studentUser);
        out.writeInt(encryptedKey.length);
        out.write(encryptedKey);
        
        // Find and send signature
        File[] signatureFiles = new File(dir).listFiles((d, name) -> 
            name.startsWith(filename + ".signature."));
        if (signatureFiles != null && signatureFiles.length > 0) {
            byte[] signature = CryptoUtils.readFile(signatureFiles[0].getPath());
            out.writeInt(signature.length);
            out.write(signature);
            logger.info("Successfully sent secure file: " + filename);
        } else {
            throw new FileNotFoundException("Signature file not found");
        }
    }

    public void shutdown() {
        running = false;
        try {
            if (serverSocket != null) {
                serverSocket.close();
            }
        } catch (IOException e) {
            logger.warning("Error closing server socket: " + e.getMessage());
        }
        executorService.shutdown();
        try {
            if (!executorService.awaitTermination(60, TimeUnit.SECONDS)) {
                executorService.shutdownNow();
            }
        } catch (InterruptedException e) {
            executorService.shutdownNow();
        }
    }

    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("Usage: java myCienciasServer <port>");
            System.exit(1);
        }

        int port = Integer.parseInt(args[0]);
        myCienciasServer server = new myCienciasServer(port);
        
        // Add shutdown hook
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("\nShutting down server...");
            server.shutdown();
        }));
        
        server.start();
    }
}