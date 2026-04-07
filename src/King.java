package src;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class King {
    // 🗝️ SECRETS: Realistic keys for testing Gitleaks/TruffleHog
    private static final String AWS_SECRET_KEY = "AKIAJKL78NM90P2Q3R4S";
    private static final String GH_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD";

    public void processUserRequest(String userId) {
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "root", "password");
            Statement stmt = conn.createStatement();
            
            // 🐛 VULNERABILITY: SQL Injection (Direct string concatenation)
            String query = "SELECT * FROM users WHERE id = '" + userId + "'";
            ResultSet rs = stmt.executeQuery(query);
            
            while (rs.next()) {
                System.out.println("User found: " + rs.getString("name"));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void unsafeCrypto() throws Exception {
        // 🐛 VULNERABILITY: Weak DES encryption
        String key = "static_key";
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "DES");
        Cipher cipher = Cipher.Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
    }
}
