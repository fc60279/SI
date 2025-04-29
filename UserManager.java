import java.io.*;
import java.security.*;
import java.util.*;
import java.util.logging.*;
import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;

public class UserManager {
    private static final String USERS_FILE = "users.txt";
    private static final Logger logger = Logger.getLogger("UserManager");
    private Map<String, UserInfo> users;
    private SecretKey macKey;

    private static class UserInfo {
        String username;
        String hashedPassword;
        String salt;

        UserInfo(String username, String hashedPassword, String salt) {
            this.username = username;
            this.hashedPassword = hashedPassword;
            this.salt = salt;
        }
    }

    public UserManager(String adminPassword) throws Exception {
        this.users = new HashMap<>();
        this.macKey = MACManager.deriveKey(adminPassword);
        loadUsers();
    }

    private void loadUsers() throws Exception {
        File file = new File(USERS_FILE);
        if (!file.exists()) {
            logger.info("Users file not found. Creating new users file with admin user.");
            createAdminUser();
            return;
        }

        // Read file content
        String content;
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append("\n");
            }
            content = sb.toString().trim();
        }

        // Verify MAC
        String storedMAC = MACManager.loadMAC();
        if (storedMAC == null) {
            System.out.println("WARNING: No MAC found to protect the password file.");
            System.out.println("The integrity of the password file cannot be verified.");
            System.out.print("Do you want to calculate and store a MAC for the password file? (y/n): ");
            Scanner scanner = new Scanner(System.in);
            String response = scanner.nextLine().toLowerCase();
            if (response.equals("y")) {
                logger.info("Calculating new MAC for users file");
                String mac = MACManager.calculateMAC(content, macKey);
                MACManager.saveMAC(mac);
                logger.info("MAC saved successfully");
                System.out.println("MAC calculated and stored successfully.");
            } else {
                logger.severe("User declined to calculate MAC. Server terminating.");
                System.out.println("Server will terminate due to missing MAC protection.");
                System.exit(1);
            }
        } else {
            logger.info("Verifying MAC for users file");
            if (!MACManager.verifyMAC(content, storedMAC, macKey)) {
                logger.severe("MAC verification failed. Password file integrity compromised.");
                System.out.println("ERROR: MAC verification failed!");
                System.out.println("The password file may have been tampered with or corrupted.");
                System.out.println("Server will terminate to protect security.");
                System.exit(1);
            }
            logger.info("MAC verification successful");
        }

        // Parse users
        for (String line : content.split("\n")) {
            String[] parts = line.split(":");
            if (parts.length == 3) {
                users.put(parts[0], new UserInfo(parts[0], parts[1], parts[2]));
            }
        }
        logger.info("Loaded " + users.size() + " users from file");
    }

    private void createAdminUser() throws Exception {
        Scanner scanner = new Scanner(System.in);
        System.out.println("No users file found. Creating admin user.");
        System.out.print("Enter admin username (default: admin): ");
        String username = scanner.nextLine().trim();
        if (username.isEmpty()) {
            username = "admin";
        }
        
        System.out.print("Enter admin password: ");
        String password = scanner.nextLine();

        String salt = generateSalt();
        String hashedPassword = hashPassword(password, salt);

        users.put(username, new UserInfo(username, hashedPassword, salt));
        logger.info("Created admin user: " + username);
        saveUsers();
        
        System.out.println("Admin user created successfully.");
    }

    private void saveUsers() throws Exception {
        StringBuilder content = new StringBuilder();
        for (UserInfo user : users.values()) {
            content.append(user.username).append(":")
                  .append(user.hashedPassword).append(":")
                  .append(user.salt).append("\n");
        }
        String contentStr = content.toString().trim();

        // Save users file
        try (PrintWriter writer = new PrintWriter(new FileWriter(USERS_FILE))) {
            writer.print(contentStr);
        }
        logger.info("Saved " + users.size() + " users to file");

        // Calculate and save MAC
        String mac = MACManager.calculateMAC(contentStr, macKey);
        MACManager.saveMAC(mac);
        logger.info("Updated MAC for users file");
    }

    private String generateSalt() {
        byte[] salt = new byte[32];
        try {
            SecureRandom random = SecureRandom.getInstanceStrong();
            random.nextBytes(salt);
        } catch (NoSuchAlgorithmException e) {
            logger.severe("Error generating salt: " + e.getMessage());
        }
        return Base64.getEncoder().encodeToString(salt);
    }

    private String hashPassword(String password, String salt) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] saltBytes = Base64.getDecoder().decode(salt);
            byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);
            
            // Combine password and salt
            byte[] combined = new byte[passwordBytes.length + saltBytes.length];
            System.arraycopy(passwordBytes, 0, combined, 0, passwordBytes.length);
            System.arraycopy(saltBytes, 0, combined, passwordBytes.length, saltBytes.length);
            
            // Hash the combined bytes
            byte[] hash = digest.digest(combined);
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            logger.severe("Error hashing password: " + e.getMessage());
            return null;
        }
    }

    public boolean authenticateUser(String username, String password) {
        UserInfo user = users.get(username);
        if (user == null) {
            return false;
        }

        String hashedInput = hashPassword(password, user.salt);
        return hashedInput != null && hashedInput.equals(user.hashedPassword);
    }

    public boolean userExists(String username) {
        return users.containsKey(username);
    }

    public void addUser(String username, String password) throws Exception {
        if (userExists(username)) {
            throw new IllegalArgumentException("User already exists");
        }

        String salt = generateSalt();
        String hashedPassword = hashPassword(password, salt);
        users.put(username, new UserInfo(username, hashedPassword, salt));
        saveUsers();
    }
    
    public void registerUser(String username, String password) throws Exception {
        logger.info("Registering new user: " + username);
        addUser(username, password);
        logger.info("User registered successfully: " + username);
    }
} 