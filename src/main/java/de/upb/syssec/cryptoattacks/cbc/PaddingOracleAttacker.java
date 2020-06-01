package de.upb.syssec.cryptoattacks.cbc;

import de.upb.syssec.cryptoattacks.helpers.Utility;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

public class PaddingOracleAttacker {

    String cipherString = "";
    String ivString = "";
    String xString = "";
    String resultString = "";
    boolean finished = false;
    boolean interruptAfterRound = false;
    boolean interrupted = false;
    byte[] originalIv;
    byte[] x;
    int round = 0;
    byte[] iv;
    PaddingOracle o;
    byte[] data;
    byte[] decrypted;
            
    public void initialize(String text, byte[] iv) throws Exception {
        originalIv = Arrays.copyOf(iv, 16);

        o = new PaddingOracle();
        data = o.encrypt(text.getBytes(), iv);
        cipherString = Utility.bytesToHex(data).trim();
        ivString = Utility.bytesToHex(iv).trim();
        this.iv = new byte[16];
        for (int i = 0; i < 16; i++) {
            this.iv[i] = iv[i];
        }
    }
    
    public void attack() throws Exception {
        SecureRandom sr = new SecureRandom();

        x = new byte[16];
        decrypted = new byte[16];
        round = 1;

        sr.nextBytes(iv);
        nextRound();
    }

    public byte[] getResult() {
        byte[] r = new byte[16];
        for (int i = 0; i < 16; i++) {
            r[i] = (byte) (originalIv[i] ^ x[i]);
        }
        return r;
    }

    public void nextRound() throws InterruptedException, IllegalBlockSizeException, 
            BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        int lastIV = 0;
        boolean foundPad = false;
        while (!foundPad) {
            iv[16 - round] = (byte) lastIV;

            if (o.decrypt(data, iv)) {
                decrypted[16 - round] = (byte) round;
                foundPad = true;
                x[16 - round] = (byte) (lastIV ^ round);
                xString = Utility.bytesToHex(x, 16 - round, 16);

            } else {
                decrypted[16 - round] = o.decrypt(data, iv, round);
                xString = Utility.bytesToHex(x, 16 - round + 1, 16);

            }

            ivString = Utility.bytesToHex(iv, 16 - round, 16);

            resultString = Utility.bytesToHex(decrypted, 16 - round, 16);
            Thread.sleep(10);
            lastIV++;
        }
        x[16 - round] = (byte) (iv[16 - round] ^ round);
        for (int j = 1; j <= round; j++) {
            iv[16 - j] = (byte) ((round + 1) ^ x[16 - j]);
            decrypted[16 - j] = (byte) (round + 1);
        }
        round++;
        if(round > 16) {
            finished = true;
            System.out.println("finished");
        } else if(interruptAfterRound) {
            interrupted = true;
        } else {
            nextRound();
        }
    }

    public String getCipherString() {
        return cipherString;
    }

    public String getIvString() {
        return ivString;
    }

    public String getxString() {
        return xString;
    }

    public String getResultString() {
        return resultString;
    }

    public boolean isInterruptAfterRound() {
        return interruptAfterRound;
    }

    public boolean isInterrupted() {
        return interrupted;
    }

    public byte[] getOriginalIv() {
        return originalIv;
    }

    public byte[] getX() {
        return x;
    }

    public int getRound() {
        return round;
    }

    public byte[] getIv() {
        return iv;
    }

    public PaddingOracle getO() {
        return o;
    }

    public byte[] getData() {
        return data;
    }

    public byte[] getDecrypted() {
        return decrypted;
    }

    public void setInterruptAfterRound(boolean interruptAfterRound) {
        this.interruptAfterRound = interruptAfterRound;
    }
    
    
    
}