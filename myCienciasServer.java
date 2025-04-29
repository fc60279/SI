import java.io.*;
import java.net.*;
import java.security.*;
import java.util.concurrent.*;
import java.util.logging.*;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Scanner;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class myCienciasServer {
    private final int port;
    private final ExecutorService executorService;
    private final Logger logger;
    private volatile boolean running;
    private ServerSocket serverSocket;
    private final String baseDirectory = "server_files";
    private UserManager userManager = null;

    public myCienciasServer(int port) {
        this.port = port;
        this.executorService = Executors.newCachedThreadPool();
        this.logger = Logger.getLogger("myCienciasServer");
        
        setupLogging();
        createBaseDirectory();
        
        // Ask for admin password
        Scanner scanner = new Scanner(System.in);
        System.out.println("=== myCiencias Server ===");
        System.out.println("Starting server with password file integrity verification.");
        System.out.print("Enter admin password: ");
        String adminPassword = scanner.nextLine();
        
        if (adminPassword.isEmpty()) {
            System.out.println("Error: Admin password cannot be empty");
            System.exit(1);
        }
        
        try {
            logger.info("Initializing user manager with password file integrity check");
            this.userManager = new UserManager(adminPassword);
            logger.info("User manager initialized successfully");
            System.out.println("Password file integrity check passed. Server ready.");
        } catch (Exception e) {
            logger.severe("Error initializing user manager: " + e.getMessage());
            System.err.println("Error initializing user manager: " + e.getMessage());
            System.exit(1);
        }
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
        try (DataInputStream in = new DataInputStream(clientSocket.getInputStream());
             DataOutputStream out = new DataOutputStream(clientSocket.getOutputStream())) {
            
            while (!clientSocket.isClosed() && clientSocket.isConnected()) {
                try {
                    String command = in.readUTF();
                    logger.info("Received command: " + command);
                    
                    try {
                        String[] parts = command.split(":");
                        switch (parts[0]) {
                            case "LOGIN":
                                if (parts.length >= 3) {
                                    String username = parts[1];
                                    String password = parts[2];
                                    if (userManager.authenticateUser(username, password)) {
                                        out.writeUTF("SUCCESS:Login successful");
                                    } else {
                                        out.writeUTF("ERROR:Invalid credentials");
                                    }
                                }
                                break;
                                
                            case "GET_CERTIFICATE":
                                if (parts.length >= 2) {
                                    String user = parts[1];
                                    handleGetCertificate(user, out);
                                }
                                break;
                                
                            case "SEND_FILE":
                                if (parts.length >= 4) {
                                    String sender = parts[1];
                                    String receiver = parts[2];
                                    String filename = parts[3];
                                    handleSendFile(sender, filename, in, out);
                                }
                                break;
                                
                            case "GET_FILE":
                                if (parts.length >= 3) {
                                    String user = parts[1];
                                    String filename = parts[2];
                                    handleGetFile(user, filename, out);
                                }
                                break;
                                
                            case "LIST_FILES":
                                if (parts.length >= 2) {
                                    String user = parts[1];
                                    handleListFiles(user, out);
                                }
                                break;
                                
                            case "DELETE_FILE":
                                if (parts.length >= 3) {
                                    String user = parts[1];
                                    String filename = parts[2];
                                    handleDeleteFile(user, filename, out);
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
                                    String user = parts[1];
                                    String filename = parts[2];
                                    handleGetFileInfo(user, filename, out);
                                }
                                break;
                                
                            case "REGISTER":
                                if (parts.length >= 3) {
                                    String username = parts[1];
                                    String password = parts[2];
                                    handleRegisterUser(username, password, out);
                                } else {
                                    out.writeUTF("ERROR:Missing username or password");
                                }
                                break;
                                
                            default:
                                out.writeUTF("ERROR:Unknown command");
                        }
                    } catch (Exception e) {
                        logger.log(Level.SEVERE, "Error handling command: " + command, e);
                        try {
                            out.writeUTF("ERROR:" + e.getMessage());
                        } catch (IOException ioe) {
                            logger.log(Level.SEVERE, "Failed to send error message", ioe);
                            break; // Exit the loop if we can't communicate with client
                        }
                    }
                } catch (EOFException e) {
                    // Client has closed the connection, exit the loop gracefully
                    logger.info("Client disconnected: " + clientSocket.getInetAddress());
                    break;
                } catch (IOException e) {
                    // Other IO errors 
                    logger.log(Level.WARNING, "IO error with client: " + clientSocket.getInetAddress(), e);
                    break;
                }
            }
        } catch (IOException e) {
            // Errors during stream creation
            logger.log(Level.WARNING, "Error setting up client connection", e);
        } finally {
            try {
                if (!clientSocket.isClosed()) {
                    clientSocket.close();
                }
            } catch (IOException e) {
                logger.log(Level.WARNING, "Error closing client socket", e);
            }
            logger.info("Client handler finished for: " + clientSocket.getInetAddress());
        }
    }

    private void handleGetCertificate(String user, DataOutputStream out) throws IOException {
        try {
            String certPath = getCertificatePath(user);
            File certFile = new File(certPath);
            
            if (!certFile.exists()) {
                out.writeUTF("ERROR:Certificate not found for user: " + user);
                return;
            }
            
            byte[] certBytes = Files.readAllBytes(certFile.toPath());
            String certBase64 = Base64.getEncoder().encodeToString(certBytes);
            
            out.writeUTF("SUCCESS:" + certBase64);
        } catch (IOException e) {
            logger.log(Level.SEVERE, "Error handling certificate request", e);
            out.writeUTF("ERROR:Failed to read certificate");
        }
    }

    private String getCertificatePath(String user) {
        // Primeiro procura no diretório "certificates"
        String certPath = "certificates/" + user + ".cer";
        File certFile = new File(certPath);
        if (certFile.exists()) {
            return certPath;
        }
        
        // Se não encontrar, procura no diretório atual
        certPath = user + ".cer";
        certFile = new File(certPath);
        if (certFile.exists()) {
            return certPath;
        }
        
        // Se não encontrar, tenta exportar o certificado da keystore
        try {
            String keyStorePath = user + ".keystore";
            if (new File(keyStorePath).exists()) {
                logger.info("Exportando certificado de " + user + " da keystore");
                ProcessBuilder pb = new ProcessBuilder(
                    "keytool", 
                    "-exportcert", 
                    "-alias", user,
                    "-file", certPath,
                    "-keystore", keyStorePath,
                    "-storepass", "123456"
                );
                Process p = pb.start();
                int exitCode = p.waitFor();
                if (exitCode == 0 && new File(certPath).exists()) {
                    logger.info("Certificado exportado com sucesso para " + certPath);
                    return certPath;
                }
            }
        } catch (Exception e) {
            logger.log(Level.WARNING, "Falha ao exportar certificado", e);
        }
        
        // Retorna o caminho padrão, mesmo que o arquivo não exista
        return "certificates/" + user + ".cer";
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

    private void handleGetFile(String user, String filename, DataOutputStream out) throws IOException {
        try {
            File file = new File(getStudentDirectory(user) + File.separator + filename);
            if (!file.exists()) {
                out.writeUTF("ERROR:File not found");
                return;
            }
            
            byte[] fileBytes = Files.readAllBytes(file.toPath());
            String fileBase64 = Base64.getEncoder().encodeToString(fileBytes);
            
            out.writeUTF("SUCCESS:" + fileBase64);
        } catch (IOException e) {
            logger.log(Level.SEVERE, "Error handling file request", e);
            out.writeUTF("ERROR:Failed to read file");
        }
    }

    private void handleSendFile(String sender, String filename, DataInputStream in, DataOutputStream out) throws IOException {
        try {
            String fileBase64 = in.readUTF();
            byte[] fileBytes = Base64.getDecoder().decode(fileBase64);
            
            String dir = getStudentDirectory(sender);
            
            File file = new File(dir, filename);
            Files.write(file.toPath(), fileBytes);
            
            out.writeUTF("SUCCESS:File stored successfully");
        } catch (IOException e) {
            logger.log(Level.SEVERE, "Error handling file storage", e);
            out.writeUTF("ERROR:Failed to store file");
        }
    }

    private void handleListFiles(String user, DataOutputStream out) throws IOException {
        try {
            File userDir = new File(getStudentDirectory(user));
            if (!userDir.exists()) {
                out.writeUTF("SUCCESS:[]");
                return;
            }
            
            File[] files = userDir.listFiles();
            if (files == null) {
                out.writeUTF("SUCCESS:[]");
                return;
            }
            
            List<String> fileList = Arrays.stream(files)
                .map(File::getName)
                .collect(Collectors.toList());
            
            String response = "SUCCESS:" + String.join(",", fileList);
            out.writeUTF(response);
        } catch (IOException e) {
            logger.log(Level.SEVERE, "Error listing files", e);
            out.writeUTF("ERROR:Failed to list files");
        }
    }

    private void handleDeleteFile(String user, String filename, DataOutputStream out) throws IOException {
        try {
            File file = new File(getStudentDirectory(user) + File.separator + filename);
            if (!file.exists()) {
                out.writeUTF("ERROR:File not found");
                return;
            }
            
            if (file.delete()) {
                out.writeUTF("SUCCESS:File deleted successfully");
            } else {
                out.writeUTF("ERROR:Failed to delete file");
            }
        } catch (IOException e) {
            logger.log(Level.SEVERE, "Error deleting file", e);
            out.writeUTF("ERROR:Failed to delete file");
        }
    }

    private void handleRegisterUser(String username, String password, DataOutputStream out) throws Exception {
        try {
            userManager.registerUser(username, password);
            out.writeUTF("SUCCESS:User registered successfully");
        } catch (Exception e) {
            logger.severe("Error registering user: " + e.getMessage());
            out.writeUTF("ERROR:" + e.getMessage());
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

        int port;
        try {
            port = Integer.parseInt(args[0]);
        } catch (NumberFormatException e) {
            System.out.println("Error: Port must be a valid number");
            System.exit(1);
            return; // Unreachable but needed for compilation
        }

        myCienciasServer server = null;
        try {
            server = new myCienciasServer(port);
            
            // Add shutdown hook
            final myCienciasServer finalServer = server;
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                System.out.println("\nShutting down server...");
                finalServer.shutdown();
            }));
            
            server.start();
        } catch (Exception e) {
            System.err.println("Fatal error starting server: " + e.getMessage());
            if (server != null) {
                server.shutdown();
            }
            System.exit(1);
        }
    }
}