package org.bouncycastle.tsp.ers;

import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.util.Arrays;


/**
 * Hash value of the concatenated hash values of 2 {@link ERSData} objects.
 */
public class ERSConcatenatedHashData
    extends ERSCachingData
{
    private final ERSData ersData1;
    private final ERSData ersData2;

    public ERSConcatenatedHashData(ERSData ersData1, ERSData ersData2) {
        this.ersData1 = ersData1;
        this.ersData2 = ersData2;
    }

    @Override
    protected byte[] calculateHash(DigestCalculator digestCalculator) {
        // calculate the hash value of the concatenated hash values of ersData1 and ersData2
        return ERSUtil.calculateDigest(digestCalculator, Arrays.concatenate(ersData1.getHash(digestCalculator), ersData2.getHash(digestCalculator)));
    }
}
