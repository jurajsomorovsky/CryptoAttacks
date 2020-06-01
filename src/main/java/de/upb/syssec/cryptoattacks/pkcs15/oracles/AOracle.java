package de.upb.syssec.cryptoattacks.pkcs15.oracles;

import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Oracle template for Bleichenbacher attack.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 *
 * Jun 12, 2012
 */
public abstract class AOracle {

    /*
     * number of queries issued to oracle
     */
    protected long numberOfQueries;
    /*
     * block size of the encryption algorithm
     */
    protected int blockSize;
    /*
     * public key of the oracle
     */
    protected RSAPublicKey publicKey;
    /*
     * a boolean value indicating if the oracle is a plaintext oracle (oracle
     * used for testing purposes) or a real oracle needing to decrypt each
     * ciphertext.
     */
    protected boolean isPlaintextOracle = false;
    /**
     * oracle type according to the Crypto'12 paper
     */
    protected OracleType oracleType = null;

    /**
     * Oracle types defined in the Crypto'12 paper + specific oracles found
     * during our research
     *
     * TTT checks only 0x00 0x02 ...
     *
     * FFF checks 0x00 0x02 on the beginning, the first 8 bytes cannot include
     * 0x00 and the 0x00 byte has to be set on a correct position
     */
    public enum OracleType {

        TTT, TFT, FTT, FFT, FFF, JSSE
    }

    /**
     * Gets the blocksize of the encryption algorithm.
     *
     * @return Blocksize
     */
    public int getBlockSize() {
        return this.blockSize;
    }

    /**
     * Gets the total number of queries performed by this oracle.
     *
     * @return Number of queries
     */
    public long getNumberOfQueries() {
        return this.numberOfQueries;
    }

    /**
     * Gets the public key of this oracle.
     *
     * @return Public key
     */
    public PublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * Checks for PKCS conformity - 00 02 padding 00 pms
     *
     * @param msg Encrypted message to check for conformity
     * @return True if PKCS conforming, else false
     */
    public abstract boolean checkPKCSConformity(final byte[] msg);

    /**
     * Returns true if the oracle is a plaintext oracle (does not decrypt the
     * data received)
     *
     * @return isPlaintextOracle
     */
    public boolean isPlaintextOracle() {
        return isPlaintextOracle;
    }

    /**
     * Returns the oracle type
     *
     * @return
     */
    public OracleType getOracleType() {
        return oracleType;
    }
    
    /**
     * Resets number of queries for the next measurement
     */
    public void resetNumberOfQueries() {
        numberOfQueries = 0;
    }
}
