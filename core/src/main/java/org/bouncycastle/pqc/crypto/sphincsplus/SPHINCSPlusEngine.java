package org.bouncycastle.pqc.crypto.sphincsplus;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.generators.MGF1BytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.MGFParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;

abstract class SPHINCSPlusEngine
{
    final boolean robust;

    final int N;

    final int WOTS_W;
    final int WOTS_LOGW;
    final int WOTS_LEN;
    final int WOTS_LEN1;
    final int WOTS_LEN2;

    final int D;
    final int A; // FORS_HEIGHT
    final int K; // FORS_TREES
    final int H; // FULL_HEIGHT
    final int H_PRIME;  // H / D

    final int T; // T = 1 << A

    protected static byte[] xor(byte[] m, byte[] mask)
    {
        byte[] r = Arrays.clone(m);
        for (int t = 0; t < m.length; t++)
        {
            r[t] ^= mask[t];
        }
        return r;
    }

    public SPHINCSPlusEngine(boolean robust, int n, int w, int d, int a, int k, int h)
    {
        this.N = n;

        /* SPX_WOTS_LEN2 is floor(log(len_1 * (w - 1)) / log(w)) + 1; we precompute */
        if (w == 16)
        {
            WOTS_LOGW = 4;
            WOTS_LEN1 = (8 * N / WOTS_LOGW);
            if (N <= 8)
            {
                WOTS_LEN2 = 2;
            }
            else if (N <= 136)
            {
                WOTS_LEN2 = 3;
            }
            else if (N <= 256)
            {
                WOTS_LEN2 = 4;
            }
            else
            {
                throw new IllegalArgumentException("cannot precompute SPX_WOTS_LEN2 for n outside {2, .., 256}");
            }
        }
        else if (w == 256)
        {
            WOTS_LOGW = 8;
            WOTS_LEN1 = (8 * N / WOTS_LOGW);
            if (N <= 1)
            {
                WOTS_LEN2 = 1;
            }
            else if (N <= 256)
            {
                WOTS_LEN2 = 2;
            }
            else
            {
                throw new IllegalArgumentException("cannot precompute SPX_WOTS_LEN2 for n outside {2, .., 256}");
            }
        }
        else
        {
            throw new IllegalArgumentException("wots_w assumed 16 or 256");
        }
        this.WOTS_W = w;
        this.WOTS_LEN = WOTS_LEN1 + WOTS_LEN2;

        this.robust = robust;
        this.D = d;
        this.A = a;
        this.K = k;
        this.H = h;
        this.H_PRIME = h / d;
        this.T = 1 << a;
    }

    abstract byte[] F(byte[] pkSeed, ADRS adrs, byte[] m1);

    abstract byte[] H(byte[] pkSeed, ADRS adrs, byte[] m1, byte[] m2);

    abstract IndexedDigest H_msg(byte[] prf, byte[] pkSeed, byte[] pkRoot, byte[] message);

    abstract byte[] T_l(byte[] pkSeed, ADRS adrs, byte[] m);

    abstract byte[] PRF(byte[] pkSeed, byte[] skSeed, ADRS adrs);

    abstract byte[] PRF_msg(byte[] prf, byte[] randomiser, byte[] message);

    static class Sha2Engine
        extends SPHINCSPlusEngine
    {
        private final byte[] padding = new byte[128];
        private final Digest treeDigest;
        private final HMac treeHMac;
        private final MGF1BytesGenerator mgf1;
        private final byte[] hmacBuf;
        private final Digest msgDigest;

        private Memoable msgMemo;
        private final byte[] msgDigestBuf;
        private final int bl;

        private SHA256Digest sha256 = new SHA256Digest();
        private final byte[] sha256Buf = new byte[sha256.getDigestSize()];

        private Memoable sha256Memo;

        private boolean msgStateSaved = false;
        private boolean sha256StateSaved = false;

        public Sha2Engine(boolean robust, int n, int w, int d, int a, int k, int h)
        {
            super(robust, n, w, d, a, k, h);

            this.treeDigest = new SHA256Digest();
            if (n == 16)
            {
                this.msgDigest = new SHA256Digest();
                this.treeHMac = new HMac(new SHA256Digest());
                this.mgf1 = new MGF1BytesGenerator(new SHA256Digest());
                this.bl = 64;
            }
            else
            {
                this.msgDigest = new SHA512Digest();
                this.treeHMac = new HMac(new SHA512Digest());
                this.mgf1 = new MGF1BytesGenerator(new SHA512Digest());
                this.bl = 128;
            }


            this.hmacBuf = new byte[treeHMac.getMacSize()];
            this.msgDigestBuf = new byte[msgDigest.getDigestSize()];
        }

        public byte[] F(byte[] pkSeed, ADRS adrs, byte[] m1)
        {
            byte[] compressedADRS = compressedADRS(adrs);

            if (robust)
            {
                m1 = bitmask256(Arrays.concatenate(pkSeed, compressedADRS), m1);
            }

            if(!sha256StateSaved)
            {
                sha256.update(pkSeed, 0, pkSeed.length);
                sha256.update(padding, 0, 64 - pkSeed.length); // toByte(0, 64 - n)
                sha256Memo = sha256.copy();
                sha256StateSaved = true;
            }
            sha256.reset(sha256Memo);

            sha256.update(compressedADRS, 0, compressedADRS.length);
            sha256.update(m1, 0, m1.length);
            sha256.doFinal(sha256Buf, 0);


            return Arrays.copyOfRange(sha256Buf, 0, N);
        }

        public byte[] H(byte[] pkSeed, ADRS adrs, byte[] m1, byte[] m2)
        {
            byte[] compressedADRS = compressedADRS(adrs);

            if(!msgStateSaved)
            {
                msgDigest.update(pkSeed, 0, pkSeed.length);
                msgDigest.update(padding, 0, 64 - pkSeed.length); // toByte(0, 64 - n)
                msgMemo = ((Memoable)msgDigest).copy();
//                msgStateSaved = true;
            }
//            ((Memoable)msgDigest).reset(sha256Memo);


            msgDigest.update(compressedADRS, 0, compressedADRS.length);
            if (robust)
            {
                byte[] m1m2 = bitmask(Arrays.concatenate(pkSeed, compressedADRS), m1, m2);
                msgDigest.update(m1m2, 0, m1m2.length);
            }
            else
            {
                msgDigest.update(m1, 0, m1.length);
                msgDigest.update(m2, 0, m2.length);
            }
            msgDigest.doFinal(msgDigestBuf, 0);

            return Arrays.copyOfRange(msgDigestBuf, 0, N);
        }

        IndexedDigest H_msg(byte[] prf, byte[] pkSeed, byte[] pkRoot, byte[] message)
        {
            int forsMsgBytes = ((A * K) + 7) / 8;
            int leafBits = H / D;
            int treeBits = H - leafBits;
            int leafBytes = (leafBits + 7) / 8;
            int treeBytes = (treeBits + 7) / 8;
            int m = forsMsgBytes + leafBytes + treeBytes;
            byte[] out = new byte[m];
            byte[] dig = new byte[msgDigest.getDigestSize()];

            msgDigest.update(prf, 0, prf.length);
            msgDigest.update(pkSeed, 0, pkSeed.length);
            msgDigest.update(pkRoot, 0, pkRoot.length);
            msgDigest.update(message, 0, message.length);
            msgDigest.doFinal(dig, 0);

            out = bitmask(Arrays.concatenate(prf, pkSeed, dig), out);

            // tree index
            // currently, only indexes up to 64 bits are supported
            byte[] treeIndexBuf = new byte[8];
            System.arraycopy(out, forsMsgBytes, treeIndexBuf, 8 - treeBytes, treeBytes);
            long treeIndex = Pack.bigEndianToLong(treeIndexBuf, 0);
            treeIndex &= (~0L) >>> (64 - treeBits);

            byte[] leafIndexBuf = new byte[4];
            System.arraycopy(out, forsMsgBytes + treeBytes, leafIndexBuf, 4 - leafBytes, leafBytes);

            int leafIndex = Pack.bigEndianToInt(leafIndexBuf, 0);
            leafIndex &= (~0) >>> (32 - leafBits);

            return new IndexedDigest(treeIndex, leafIndex, Arrays.copyOfRange(out, 0, forsMsgBytes));
        }

        public byte[] T_l(byte[] pkSeed, ADRS adrs, byte[] m)
        {
            byte[] compressedADRS = compressedADRS(adrs);
            if (robust)
            {
                m = bitmask(Arrays.concatenate(pkSeed, compressedADRS), m);
            }

            if(!msgStateSaved)
            {
                msgDigest.update(pkSeed, 0, pkSeed.length);
                msgDigest.update(padding, 0, 64 - pkSeed.length); // toByte(0, 64 - n)
                msgMemo = ((Memoable)msgDigest).copy();
//                msgStateSaved = true;
            }
//            ((Memoable)msgDigest).reset(sha256Memo);

            msgDigest.update(compressedADRS, 0, compressedADRS.length);
            msgDigest.update(m, 0, m.length);
            msgDigest.doFinal(msgDigestBuf, 0);

            return Arrays.copyOfRange(msgDigestBuf, 0, N);
        }

        byte[] PRF(byte[] pkSeed, byte[] skSeed, ADRS adrs)
        {
            int n = skSeed.length;

            if(!sha256StateSaved)
            {
                sha256.update(pkSeed, 0, pkSeed.length);
                sha256.update(padding, 0, 64 - pkSeed.length); // toByte(0, 64 - n)
                sha256Memo = sha256.copy();
                sha256StateSaved = true;
            }
            sha256.reset(sha256Memo);

            byte[] compressedADRS = compressedADRS(adrs);

            sha256.update(compressedADRS, 0, compressedADRS.length);
            sha256.update(skSeed, 0, skSeed.length);
            sha256.doFinal(sha256Buf, 0);

            return Arrays.copyOfRange(sha256Buf, 0, n);
        }

        public byte[] PRF_msg(byte[] prf, byte[] randomiser, byte[] message)
        {
            treeHMac.init(new KeyParameter(prf));
            treeHMac.update(randomiser, 0, randomiser.length);
            treeHMac.update(message, 0, message.length);
            treeHMac.doFinal(hmacBuf, 0);

            return Arrays.copyOfRange(hmacBuf, 0, N);
        }

        private byte[] compressedADRS(ADRS adrs)
        {
            byte[] rv = new byte[22];
            System.arraycopy(adrs.value, ADRS.OFFSET_LAYER + 3, rv, 0, 1); // LSB layer address
            System.arraycopy(adrs.value, ADRS.OFFSET_TREE + 4, rv, 1, 8); // LS 8 bytes Tree address
            System.arraycopy(adrs.value, ADRS.OFFSET_TYPE + 3, rv, 9, 1); // LSB type
            System.arraycopy(adrs.value, 20, rv, 10, 12);

            return rv;
        }

        protected byte[] bitmask(byte[] key, byte[] m)
        {
            byte[] mask = new byte[m.length];

            mgf1.init(new MGFParameters(key));

            mgf1.generateBytes(mask, 0, mask.length);

            for (int i = 0; i < m.length; ++i)
            {
                mask[i] ^= m[i];
            }

            return mask;
        }

        protected byte[] bitmask(byte[] key, byte[] m1, byte[] m2)
        {
            byte[] mask = new byte[m1.length + m2.length];

            mgf1.init(new MGFParameters(key));

            mgf1.generateBytes(mask, 0, mask.length);

            for (int i = 0; i < m1.length; ++i)
            {
                mask[i] ^= m1[i];
            }
            for (int i = 0; i < m2.length; ++i)
            {
                mask[i + m1.length] ^= m2[i];
            }
            return mask;
        }

        protected byte[] bitmask256(byte[] key, byte[] m)
        {
            byte[] mask = new byte[m.length];

            MGF1BytesGenerator mgf1 = new MGF1BytesGenerator(new SHA256Digest());

            mgf1.init(new MGFParameters(key));

            mgf1.generateBytes(mask, 0, mask.length);

            for (int i = 0; i < m.length; ++i)
            {
                mask[i] ^= m[i];
            }

            return mask;
        }
    }

    static class Shake256Engine
        extends SPHINCSPlusEngine
    {
        private final Xof treeDigest;
        private final Xof maskDigest;

        public Shake256Engine(boolean robust, int n, int w, int d, int a, int k, int h)
        {
            super(robust, n, w, d, a, k, h);

            this.treeDigest = new SHAKEDigest(256);
            this.maskDigest = new SHAKEDigest(256);
        }

        byte[] F(byte[] pkSeed, ADRS adrs, byte[] m1)
        {
            byte[] mTheta = m1;
            if (robust)
            {
                mTheta = bitmask(pkSeed, adrs, m1);
            }

            byte[] rv = new byte[N];

            treeDigest.update(pkSeed, 0, pkSeed.length);
            treeDigest.update(adrs.value, 0, adrs.value.length);
            treeDigest.update(mTheta, 0, mTheta.length);
            treeDigest.doFinal(rv, 0, rv.length);

            return rv;
        }

        byte[] H(byte[] pkSeed, ADRS adrs, byte[] m1, byte[] m2)
        {
            byte[] rv = new byte[N];

            treeDigest.update(pkSeed, 0, pkSeed.length);
            treeDigest.update(adrs.value, 0, adrs.value.length);
            if (robust)
            {
                byte[] m1m2 = bitmask(pkSeed, adrs, m1, m2);

                treeDigest.update(m1m2, 0, m1m2.length);
            }
            else
            {
                treeDigest.update(m1, 0, m1.length);
                treeDigest.update(m2, 0, m2.length);
            }

            treeDigest.doFinal(rv, 0, rv.length);

            return rv;
        }

        IndexedDigest H_msg(byte[] R, byte[] pkSeed, byte[] pkRoot, byte[] message)
        {
            int forsMsgBytes = ((A * K) + 7) / 8;
            int leafBits = H / D;
            int treeBits = H - leafBits;
            int leafBytes = (leafBits + 7) / 8;
            int treeBytes = (treeBits + 7) / 8;
            int m = forsMsgBytes + leafBytes + treeBytes;
            byte[] out = new byte[m];

            treeDigest.update(R, 0, R.length);
            treeDigest.update(pkSeed, 0, pkSeed.length);
            treeDigest.update(pkRoot, 0, pkRoot.length);
            treeDigest.update(message, 0, message.length);

            treeDigest.doFinal(out, 0, out.length);

            // tree index
            // currently, only indexes up to 64 bits are supported
            byte[] treeIndexBuf = new byte[8];
            System.arraycopy(out, forsMsgBytes, treeIndexBuf, 8 - treeBytes, treeBytes);
            long treeIndex = Pack.bigEndianToLong(treeIndexBuf, 0);
            treeIndex &= (~0L) >>> (64 - treeBits);

            byte[] leafIndexBuf = new byte[4];
            System.arraycopy(out, forsMsgBytes + treeBytes, leafIndexBuf, 4 - leafBytes, leafBytes);

            int leafIndex = Pack.bigEndianToInt(leafIndexBuf, 0);
            leafIndex &= (~0) >>> (32 - leafBits);

            return new IndexedDigest(treeIndex, leafIndex, Arrays.copyOfRange(out, 0, forsMsgBytes));
        }

        byte[] T_l(byte[] pkSeed, ADRS adrs, byte[] m)
        {
            byte[] mTheta = m;
            if (robust)
            {
                mTheta = bitmask(pkSeed, adrs, m);
            }

            byte[] rv = new byte[N];

            treeDigest.update(pkSeed, 0, pkSeed.length);
            treeDigest.update(adrs.value, 0, adrs.value.length);
            treeDigest.update(mTheta, 0, mTheta.length);
            treeDigest.doFinal(rv, 0, rv.length);

            return rv;
        }

        byte[] PRF(byte[] pkSeed, byte[] skSeed, ADRS adrs)
        {
            treeDigest.update(pkSeed, 0, pkSeed.length);
            treeDigest.update(adrs.value, 0, adrs.value.length);
            treeDigest.update(skSeed, 0, skSeed.length);

            byte[] prf = new byte[N];
            treeDigest.doFinal(prf, 0, N);
            return prf;
        }

        public byte[] PRF_msg(byte[] prf, byte[] randomiser, byte[] message)
        {
            treeDigest.update(prf, 0, prf.length);
            treeDigest.update(randomiser, 0, randomiser.length);
            treeDigest.update(message, 0, message.length);
            byte[] out = new byte[N];
            treeDigest.doFinal(out, 0, out.length);
            return out;
        }

        protected byte[] bitmask(byte[] pkSeed, ADRS adrs, byte[] m)
        {
            byte[] mask = new byte[m.length];

            maskDigest.update(pkSeed, 0, pkSeed.length);
            maskDigest.update(adrs.value, 0, adrs.value.length);

            maskDigest.doFinal(mask, 0, mask.length);

            for (int i = 0; i < m.length; ++i)
            {
                mask[i] ^= m[i];
            }

            return mask;
        }

        protected byte[] bitmask(byte[] pkSeed, ADRS adrs, byte[] m1, byte[] m2)
        {
            byte[] mask = new byte[m1.length + m2.length];

            maskDigest.update(pkSeed, 0, pkSeed.length);
            maskDigest.update(adrs.value, 0, adrs.value.length);

            maskDigest.doFinal(mask, 0, mask.length);

            for (int i = 0; i < m1.length; ++i)
            {
                mask[i] ^= m1[i];
            }
            for (int i = 0; i < m2.length; ++i)
            {
                mask[i + m1.length] ^= m2[i];
            }

            return mask;
        }
    }
}
