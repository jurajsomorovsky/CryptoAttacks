package de.upb.syssec.cryptoattacks.pkcs15;

import de.upb.syssec.cryptoattacks.pkcs15.oracles.AOracle;
import de.upb.syssec.cryptoattacks.pkcs15.oracles.ATestOracle;
import de.upb.syssec.cryptoattacks.pkcs15.oracles.StandardOracle;
import de.upb.syssec.cryptoattacks.pkcs15.oracles.StandardPlaintextOracle;
import java.security.*;
import javax.crypto.Cipher;
import junit.framework.TestCase;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class BleichenbacherAttackPlaintextTest extends TestCase {

    private static final int PREMASTER_SECRET_LENGTH = 48;
    /**
     * Initialize the log4j logger.
     */
    static final Logger logger = LogManager.getLogger(BleichenbacherAttackPlaintextTest.class.getName());

    public final void testBleichenbacherAttack()
            throws Exception {
        
//
//        Security.addProvider(new BouncyCastleProvider());
//        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
//        keyPairGenerator.initialize(512);
//        KeyPair keyPair = keyPairGenerator.genKeyPair();
//
//        SecureRandom sr = new SecureRandom();
//        byte[] plainBytes = new byte[PREMASTER_SECRET_LENGTH];
//        sr.nextBytes(plainBytes);
//        byte[] cipherBytes;
//
//        Cipher cipher = Cipher.getInstance("RSA/NONE/PKCS1Padding");
//        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
//        cipherBytes = cipher.doFinal(plainBytes);
//
//        AOracle oracle = new StandardOracle(keyPair.getPrivate(), keyPair.getPublic(),
//                ATestOracle.OracleType.TTT);
//
//        BleichenbacherAttack attacker = new BleichenbacherAttack(cipherBytes,
//                oracle, true);
//        attacker.attack();
//
    }

}
