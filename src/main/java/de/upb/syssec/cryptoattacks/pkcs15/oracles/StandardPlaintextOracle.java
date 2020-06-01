/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package de.upb.syssec.cryptoattacks.pkcs15.oracles;

import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

/**
 *
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class StandardPlaintextOracle extends ATestOracle {
    
    public StandardPlaintextOracle(final PublicKey pubKey, 
            ATestOracle.OracleType oracleType, int blockSize) {
        this.publicKey = (RSAPublicKey) pubKey;
        this.oracleType = oracleType;
        this.isPlaintextOracle = true;
        this.blockSize = blockSize;
    }

    @Override
    public boolean checkPKCSConformity(byte[] msg) {
        numberOfQueries++;
        return checkDecryptedBytes(msg);
    }

}
