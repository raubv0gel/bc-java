package org.bouncycastle.tsp.ers;

import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.tsp.ArchiveTimeStamp;
import org.bouncycastle.asn1.tsp.PartialHashtree;
import org.bouncycastle.asn1.tsp.TSTInfo;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.util.Arrays;

import java.io.IOException;
import java.math.BigInteger;
import java.util.*;

/**
 * Generator for RFC 4998 Archive Time Stamps.
 */
public class ERSArchiveTimeStampGenerator
{
    private final DigestCalculator digCalc;
    private final List<ERSData> dataObjects = new ArrayList<ERSData>();

    private final ERSRootNodeCalculator rootNodeCalculator = new BinaryTreeRootCalculator();

    public ERSArchiveTimeStampGenerator(DigestCalculator digCalc)
    {
        this.digCalc = digCalc;
    }

    public void addData(ERSData dataObject)
    {
        dataObjects.add(dataObject);
    }

    public void addAllData(List<ERSData> dataObjects)
    {
        this.dataObjects.addAll(dataObjects);
    }

    public ERSArchiveTimeStamp generateArchiveTimeStamp(TimeStampRequestGenerator tspReqGenerator, TimeStamper timeStamper)
            throws TSPException, ERSException
    {
        return generateArchiveTimeStamp(tspReqGenerator, timeStamper, null);
    }

    public ERSArchiveTimeStamp generateArchiveTimeStamp(TimeStampRequestGenerator tspReqGenerator, TimeStamper timeStamper, BigInteger nonce)
            throws TSPException, ERSException
    {
        final PartialHashtree[] reducedHashTree = getPartialHashtrees(dataObjects, digCalc);

        final byte[] rootHash = rootNodeCalculator.computeRootHash(digCalc, reducedHashTree);

        final TimeStampResponse tspResponse;
        try
        {
            // time stamp the rootHash
            tspResponse = timeStamper.stamp(tspReqGenerator.generate(digCalc.getAlgorithmIdentifier(), rootHash, nonce));
            if (tspResponse == null)
            {
                return null;
            }
        }
        catch (final Exception e)
        {
            throw new ERSException(String.format("an exception while time stamping occurred: %s", e.getMessage()), e);
        }

        checkTimeStampResponse(rootHash, tspResponse);

        final ArchiveTimeStamp ats;
        if (reducedHashTree.length == 1)
        {
            // just include the TimeStamp
            ats = new ArchiveTimeStamp(null, null,
                    tspResponse.getTimeStampToken().toCMSSignedData().toASN1Structure());
        }
        else
        {
            ats = new ArchiveTimeStamp(digCalc.getAlgorithmIdentifier(), reducedHashTree,
                    tspResponse.getTimeStampToken().toCMSSignedData().toASN1Structure());
        }

        return new ERSArchiveTimeStamp(ats, digCalc, rootNodeCalculator);
    }

    public ERSArchiveTimeStamp generateRenewedArchiveTimeStamp(ERSEvidenceRecord ersEvidenceRecord, TimeStampRequestGenerator tspReqGenerator, TimeStamper timeStamper)
            throws TSPException, ERSException
    {
        return generateRenewedArchiveTimeStamp(ersEvidenceRecord, tspReqGenerator, timeStamper, null);
    }

    public ERSArchiveTimeStamp generateRenewedArchiveTimeStamp(ERSEvidenceRecord ersEvidenceRecord, TimeStampRequestGenerator tspReqGenerator, TimeStamper timeStamper, BigInteger nonce)
            throws TSPException, ERSException
    {
        final ArchiveTimeStamp lastArchiveTimeStamp= ersEvidenceRecord.getLastArchiveTimeStamp().toASN1Structure();

        if (!digCalc.getAlgorithmIdentifier().equals(lastArchiveTimeStamp.getDigestAlgorithmIdentifier()))
        {
            throw new ERSException("digest algorithm identifiers are not equal");
        }

        final byte[] lastTimeStampContent;
        try
        {
            lastTimeStampContent = ((DLSequence) lastArchiveTimeStamp.getTimeStamp().getContent()).getEncoded(/*ASN1Encoding.DER*/);
        }
        catch (final IOException e)
        {
            throw new ERSException(String.format("an exception occurred while encoding the time stamp: %s", e.getMessage()), e);
        }

        final byte[] lastTimeStampContentHashValue = ERSUtil.calculateDigest(digCalc, lastTimeStampContent);

        final TimeStampResponse tspResponse;
        try
        {
            // time stamp the content of the last time stamp
            tspResponse = timeStamper.stamp(tspReqGenerator.generate(digCalc.getAlgorithmIdentifier(), lastTimeStampContentHashValue, nonce));
            if (tspResponse == null)
            {
                return null;
            }
        }
        catch (final Exception e)
        {
            throw new ERSException(String.format("an exception while time stamping occurred: %s", e.getMessage()), e);
        }

        checkTimeStampResponse(lastTimeStampContentHashValue, tspResponse);

        final ArchiveTimeStamp archiveTimeStamp = new ArchiveTimeStamp(digCalc.getAlgorithmIdentifier(), null, tspResponse.getTimeStampToken().toCMSSignedData().toASN1Structure());
        return new ERSArchiveTimeStamp(archiveTimeStamp, digCalc, rootNodeCalculator);
    }

    public ERSArchiveTimeStamp generateRehashedArchiveTimeStamp(ERSEvidenceRecord ersEvidenceRecord, TimeStampRequestGenerator tspReqGenerator, TimeStamper timeStamper)
            throws TSPException, ERSException
    {
        return generateRehashedArchiveTimeStamp(ersEvidenceRecord, tspReqGenerator, timeStamper, null);
    }

    public ERSArchiveTimeStamp generateRehashedArchiveTimeStamp(ERSEvidenceRecord ersEvidenceRecord, TimeStampRequestGenerator tspReqGenerator, TimeStamper timeStamper, BigInteger nonce)
            throws TSPException, ERSException
    {
        if (!digCalc.getAlgorithmIdentifier().equals(ersEvidenceRecord.getLastArchiveTimeStamp().getDigestAlgorithmIdentifier()))
        {
            throw new ERSException("digest algorithm identifiers are not equal");
        }

        // hash value of encoded ArchiveTimeStampSequence
        final ERSByteData encodedArchiveTimeStampSequence;
        try
        {
            encodedArchiveTimeStampSequence = new ERSByteData(ersEvidenceRecord.toASN1Structure().getArchiveTimeStampSequence().getEncoded());
        }
        catch (final IOException e)
        {
            throw new ERSException(String.format("an exception occurred while encoding the archive time stamp sequence: %s", e.getMessage()), e);
        }

        // concatenate hash value of dataObject with hash value of encodedArchiveTimeStampSequence
        final List<ERSData> concatenatedDataObjects = new ArrayList<>(dataObjects.size());
        for (final ERSData dataObject : dataObjects)
        {
            concatenatedDataObjects.add(new ERSConcatenatedHashData(dataObject, encodedArchiveTimeStampSequence));
        }

        final PartialHashtree[] reducedHashTree = getPartialHashtrees(concatenatedDataObjects, digCalc);

        final byte[] rootHash = rootNodeCalculator.computeRootHash(digCalc, reducedHashTree);

        final TimeStampResponse tspResponse;
        try
        {
            // time stamp the content of the last time stamp
            tspResponse = timeStamper.stamp(tspReqGenerator.generate(digCalc.getAlgorithmIdentifier(), rootHash, nonce));
            if (tspResponse == null)
            {
                return null;
            }
        }
        catch (final Exception e)
        {
            throw new ERSException(String.format("an exception while time stamping occurred: %s", e.getMessage()), e);
        }

        checkTimeStampResponse(rootHash, tspResponse);

        final ArchiveTimeStamp archiveTimeStamp = new ArchiveTimeStamp(digCalc.getAlgorithmIdentifier(), reducedHashTree, tspResponse.getTimeStampToken().toCMSSignedData().toASN1Structure());
        return new ERSArchiveTimeStamp(archiveTimeStamp, digCalc, rootNodeCalculator);
    }

    private void checkTimeStampResponse(byte[] hash, TimeStampResponse tspResponse)
            throws ERSException
    {
        final TSTInfo tstInfo = tspResponse.getTimeStampToken().getTimeStampInfo().toASN1Structure();

        if (!tstInfo.getMessageImprint().getHashAlgorithm().equals(digCalc.getAlgorithmIdentifier()))
        {
            throw new ERSException("time stamp imprint for wrong algorithm");
        }

        if (!Arrays.areEqual(tstInfo.getMessageImprint().getHashedMessage(), hash))
        {
            throw new ERSException("time stamp imprint for wrong root hash");
        }
    }

    private static PartialHashtree[] getPartialHashtrees(List<ERSData> dataObjects, DigestCalculator digCalc)
    {
        final List<byte[]> hashes = ERSUtil.buildHashList(digCalc, dataObjects);
        final PartialHashtree[] trees = new PartialHashtree[hashes.size()];

        final Set<ERSDataGroup> dataGroupSet = new HashSet<ERSDataGroup>();
        for (int i = 0; i != dataObjects.size(); i++)
        {
            if (dataObjects.get(i) instanceof ERSDataGroup)
            {
                dataGroupSet.add((ERSDataGroup)dataObjects.get(i));
            }
        }

        // replace groups
        for (int i = 0; i != hashes.size(); i++)
        {
            final byte[] hash = (byte[])hashes.get(i);
            ERSDataGroup found = null;

            for (final Iterator it = dataGroupSet.iterator(); it.hasNext();)
            {
                final ERSDataGroup data = (ERSDataGroup)it.next();

                final byte[] dHash = data.getHash(digCalc);
                if (Arrays.areEqual(dHash, hash))
                {
                    final List<byte[]> dHashes = data.getHashes(digCalc);
                    trees[i] = new PartialHashtree((byte[][])dHashes.toArray(new byte[dHashes.size()][]));
                    found = data;
                    break;
                }
            }
            if (found == null)
            {
                trees[i] = new PartialHashtree(hash);
            }
            else
            {
                dataGroupSet.remove(found);
            }
        }

        return trees;
    }
}
