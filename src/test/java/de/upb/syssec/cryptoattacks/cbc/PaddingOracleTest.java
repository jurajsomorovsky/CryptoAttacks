package de.upb.syssec.cryptoattacks.cbc;

import de.upb.syssec.cryptoattacks.helpers.Utility;
import java.security.SecureRandom;
import junit.framework.TestCase;

public class PaddingOracleTest extends TestCase {

    public void test() throws Exception {
        byte[] iv = new byte[16];
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(iv);

        PaddingOracle o = new PaddingOracle();
        byte[] data = o.encrypt("test".getBytes(), iv);
        System.out.println(o.decrypt(data, iv));

        byte[] x = new byte[16];
        byte[] decrypted = new byte[16];

        sr.nextBytes(iv);
        for (int i = 1; i <= 16; i++) {
            int lastIV = 0;
            boolean foundPad = false;
            while (!foundPad) {
                iv[16 - i] = (byte) lastIV;
                System.out.println(Utility.bytesToHex(data));
                System.out.println("AES");

                if (o.decrypt(data, iv)) {
                    decrypted[16 - i] = (byte) i;
                    foundPad = true;
                    x[16 - i] = (byte) (lastIV ^ i);
                    System.out.println(Utility.bytesToHex(x, 16 - i, 16));

                } else {
                    decrypted[16 - i] = o.decrypt(data, iv, i);
                    System.out.println(Utility.bytesToHex(x, 16 - i + 1, 16));

                }

                System.out.println("XOR");
                System.out.println(Utility.bytesToHex(iv, 16 - i, 16));
                System.out.println(" = ");

                System.out.println(Utility.bytesToHex(decrypted, 16 - i, 16));
                lastIV++;
                System.out.println();
                System.out.println();
            }
            x[16 - i] = (byte) (iv[16 - i] ^ i);
            for (int j = 1; j <= i; j++) {
                iv[16 - j] = (byte) ((i + 1) ^ x[16 - j]);
                decrypted[16 - j] = (byte) (i + 1);
            }

        }
    }
}
