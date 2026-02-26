import java.security.MessageDigest;
import java.net.URL;
import java.net.HttpURLConnection;

public class Vulnerable {
    public static void main(String[] args) throws Exception {
        // SOC2 Violation: Hardcoded secret (API Key)
        String apiSecret = "sk_test_51MzS0vL3uYfTjSOC2KEY";
        


        // SOC2 Violation: Missing audit log for sensitive action
        deleteUserRecord("user_999");
    }

}
