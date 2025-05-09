/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package de.upb.syssec.cryptoattacks.helpers;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

/**
 *
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public class Utility {

    /**
     * Valid Hex Chars.
     */
    private final static char[] HEXCHARS = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };    

    /**
     * Converts a byte array into its hex string representation.
     *
     * @param bytes Bytes to convert
     * @return Hex string of delivered byte array
     */
    public static String bytesToHex(final byte[] bytes) {
        StringBuilder builder = new StringBuilder(bytes.length * 2);

        for (int i = 0; i < bytes.length; i++) {
            // unsigned right shift of the MSBs
            builder.append(HEXCHARS[(bytes[i] & 0xff) >>> 4]);
            // handling the LSBs
            builder.append(HEXCHARS[bytes[i] & 0xf]);
            builder.append(' ');
        }

        return builder.toString();
    }
    
    /**
     * Converts a byte array into its hex string representation.
     *
     * @param bytes Bytes to convert
     * @return Hex string of delivered byte array
     */
    public static String bytesToHex(final byte[] bytes, int start, int stop) {
        StringBuilder builder = new StringBuilder(bytes.length * 2);

        for (int i = 0; i < start; i++) {
            builder.append("xx ");
        }        
        
        for (int i = start; i < stop; i++) {
            // unsigned right shift of the MSBs
            builder.append(HEXCHARS[(bytes[i] & 0xff) >>> 4]);
            // handling the LSBs
            builder.append(HEXCHARS[bytes[i] & 0xf]);
            builder.append(' ');
        }
        
        for (int i = stop; i < bytes.length; i++) {
            builder.append("xx ");
        }

        return builder.toString().trim();
    }
    
        /**
     * Computes the Greatest Common Divisor of two integers.
     *
     * @param a First Integer
     * @param b Second Integer
     * @return Greatest Common Divisor of both integers
     */
    public static int findGCD(int a, int b) {
        if (b == 0) {
            return a;
        }
        return findGCD(b, a % b);
    }

    /**
     * Computes the Greatest Common Divisor of two BigIntegers.
     *
     * @param a First BigInteger
     * @param b Second BigInteger
     * @return Greatest Common Divisor of both BigIntegers
     */
    public static BigInteger findGCD(BigInteger a, BigInteger b) {
        if (b.compareTo(BigInteger.ZERO) == 0) {
            return a;
        }
        return findGCD(b, a.mod(b));
    }

    /**
     * Computes the Least Common Multiple of two integers.
     *
     * @param a First Integer
     * @param b Second Integer
     * @return Least Common Multiple of both integers
     */
    public static int findLCM(int a, int b) {
        int result = 0;
        int num1, num2;
        if (a > b) {
            num1 = a;
            num2 = b;
        } else {
            num1 = b;
            num2 = a;
        }
        for (int i = 1; i <= num2; i++) {
            if ((num1 * i) % num2 == 0) {
                result = i * num1;
                return result;
            }
        }

        return result;
    }

    /**
     * Computes the Least Common Multiple of two BigIntegers.
     *
     * @param ba First BigInteger
     * @param bb Second BigInteger
     * @return Least Common Multiple of both BigIntegers
     */
    public static BigInteger findLCM(BigInteger ba, BigInteger bb) {
        BigInteger result = BigInteger.ZERO;
        long a = ba.longValue();
        long b = bb.longValue();
        long num1, num2;
        if (a > b) {
            num1 = a;
            num2 = b;
        } else {
            num1 = b;
            num2 = a;
        }
        for (int i = 1; i <= num2; i++) {
            if ((num1 * i) % num2 == 0) {
                result = BigInteger.valueOf(i * num1);
                return result;
            }
        }

        return result;
    }

    /**
     * Computes the Least Common Multiple of a list of BigIntegers.
     *
     * @param numbers List of BigIntegers
     * @return Least Common Multiple of all BigIntegers contained in the list
     */
    public static BigInteger findLCM(List<BigInteger> numbers) {
        BigInteger result = numbers.get(0);
        for (int i = 1; i < numbers.size(); i++) {
            result = findLCM(result, numbers.get(i));
        }
        return result;
    }

    /**
     * Corrects the length of a byte array to a multiple of a passed blockSize.
     *
     * @param array Array which size should be corrected
     * @param blockSize Blocksize - the resulting array length will be a
     * multiple of it
     * @param removeSignByte If set to TRUE leading sign bytes will be removed
     * @return Size corrected array (maybe padded or stripped the sign byte)
     */
    public static byte[] correctSize(final byte[] array, int blockSize,
            boolean removeSignByte) {
        int remainder = array.length % blockSize;
        byte[] result = array;
        byte[] tmp;

        if (removeSignByte && remainder > 0 && result[0] == 0x0) {
            // extract signing byte if present
            tmp = new byte[result.length - 1];
            System.arraycopy(result, 1, tmp, 0, tmp.length);
            result = tmp;
            remainder = tmp.length % blockSize;
        }

        if (remainder > 0) {
            // add zeros to fit size
            tmp = new byte[result.length + blockSize - remainder];
            System.arraycopy(result, 0, tmp, blockSize - remainder,
                    result.length);
            result = tmp;
        }

        return result;
    }

    public static void printBytes(final String label, final byte[] bytes) {

        System.out.print(label + "\n[");

        for (int i = 0; i < bytes.length - 1; i++) {
            System.out.print(Integer.toString(bytes[i]) + ", ");
        }

        System.out.println(Integer.toString(bytes[bytes.length - 1]) + "]");
    }

    public static byte[] getPaddedBytesForSignature(byte[] hash, int blockSize) {
        // works only for sha256 !!!!!
        int[] identifier = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
        byte[] result = new byte[blockSize];
        result[0] = 0;
        result[1] = 1;
        for (int i = 2; i < blockSize - hash.length - identifier.length - 1; i++) {
            result[i] = (byte) 255;
        }
        result[blockSize - hash.length - identifier.length - 1] = 0;
        for (int i = 0; i < identifier.length; i++) {
            result[i + blockSize - hash.length - identifier.length] = (byte) identifier[i];
        }
        System.arraycopy(hash, 0, result, blockSize - hash.length, hash.length);

        return result;
    }
}
