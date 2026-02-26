import java.security.MessageDigest;
import java.net.URL;
import java.net.HttpURLConnection;

public class Vulnerable {
    public static void main(String[] args) throws Exception {
        // SOC2 Violation: Hardcoded secret (API Key)
        String apiSecret = "sk_test_51MzS0vL3uYfTjSOC2KEY";
        
        // SOC2 Violation: Insecure Hashing (SHA1)
        MessageDigest md = MessageDigest.getInstance("SHA1");
        md.update("secret_payload".getBytes());


        // SOC2 Violation: Missing audit log for sensitive action
        deleteUserRecord("user_999");
    }

    public static void deleteUserRecord(String userId) {
        // Does something sensitive without logging to a secure logger
        System.out.println("Deleting record for " + userId);
    }
}
