/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package de.upb.syssec.cryptoattacks.cbc;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public class PaddingOracle {

    Cipher cipher;
    Cipher cipher2;
    SecureRandom sr;
    SecretKey sk;

    public PaddingOracle() throws NoSuchAlgorithmException,
            NoSuchPaddingException {
        cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher2 = Cipher.getInstance("AES/CBC/NoPadding");
        sr = new SecureRandom();

        byte[] key = new byte[16];
        sr.nextBytes(key);

        sk = new SecretKeySpec(key, "AES");
    }

    public byte[] encrypt(byte[] data, byte[] iv) throws
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        IvParameterSpec ivspec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, sk, ivspec);

        return cipher.doFinal(data);
    }

    public boolean decrypt(byte[] data, byte[] iv) throws InvalidKeyException,
            IllegalBlockSizeException, InvalidAlgorithmParameterException {
        IvParameterSpec ivspec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, sk, ivspec);
        try {
            cipher.doFinal(data);
        } catch (BadPaddingException bpe) {
            return false;
        }
        return true;
    }

    public byte decrypt(byte[] data, byte[] iv, int position)
            throws InvalidKeyException, BadPaddingException,
            IllegalBlockSizeException, InvalidAlgorithmParameterException {
        IvParameterSpec ivspec = new IvParameterSpec(iv);
        cipher2.init(Cipher.DECRYPT_MODE, sk, ivspec);
        byte[] res = cipher2.doFinal(data);
        return res[res.length-position];
    }
}