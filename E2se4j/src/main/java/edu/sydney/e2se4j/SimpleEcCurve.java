package edu.sydney.e2se4j;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;

public class SimpleEcCurve {

    public X9ECParameters ecParameters;
    public ECDomainParameters ecDomainParameters;
    public BigInteger n;
    public ECPoint G;
    private int length4Hash;

    public SimpleEcCurve(String curveName) {
        ecParameters = CustomNamedCurves.getByName(curveName);
        ecDomainParameters = new ECDomainParameters(ecParameters.getCurve(), ecParameters.getG(), ecParameters.getN());
        n = ecDomainParameters.getN();
        G = ecDomainParameters.getG();
        length4Hash = (n.bitLength() + 128) / 8 + 1;
    }

    public ECPoint hash2Curve(byte[] message, MessageDigest hash) throws NoSuchAlgorithmException {
        byte[] messageHashBytes = hash.digest(message);
        BigInteger messageHash = new BigInteger(1, messageHashBytes).mod(n);
        while (true) {
            ECFieldElement x = ecDomainParameters.getCurve().fromBigInteger(messageHash);
            ECFieldElement y = x.square().add(ecDomainParameters.getCurve().getA()).multiply(x).add(ecDomainParameters.getCurve().getB()).sqrt();
            if (y == null) {
                messageHash = messageHash.add(BigInteger.ONE).mod(n);
                continue;
            }
            ECPoint ecPoint = ecDomainParameters.getCurve().createPoint(x.toBigInteger(), y.toBigInteger());
            ecPoint = ecPoint.multiply(ecDomainParameters.getCurve().getCofactor());
            if (ecPoint == null || !ecPoint.isValid()) {
                messageHash = messageHash.add(BigInteger.ONE).mod(n);
                continue;
            }
            return ecPoint;
        }
    }

    public BigInteger randomBigInteger(SecureRandom random) {
        BigInteger randomInt;
        do {
            randomInt = new BigInteger(n.bitLength(), random);
        } while (randomInt.compareTo(n) >= 0);
        return randomInt;
    }

    /**
     * @return
     */
    // public BigInteger hashToGroup (byte [] message, MessageDigest hash ){
    public BigInteger hashToGroup2(byte[] input, byte[] clientSecret) {
        HMacKDF hkdf;
        if (clientSecret == null) {
            hkdf = new HMacKDF("HMACSHA512", input);
        } else {
            hkdf = new HMacKDF("HMACSHA512", input, clientSecret);
        }

        BigInteger p = n;
        int groupSize = p.bitLength();
        int bytesToGenerate = (groupSize + 7) / 8;
        int extraBits = bytesToGenerate * 8 - groupSize;
        BigInteger iterationCounter = BigInteger.ONE;

        while (true) {
            byte[] tBytes = hkdf.createKey(iterationCounter.toByteArray(), bytesToGenerate);
            BigInteger t = (new BigInteger(1, tBytes)).shiftRight(extraBits);
            if (t.compareTo(p) < 0 && t.compareTo(BigInteger.ZERO) > 0) {
                return t;
            }

            iterationCounter = iterationCounter.add(BigInteger.ONE);
        }
    }
}
