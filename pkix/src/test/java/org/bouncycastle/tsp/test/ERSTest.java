package org.bouncycastle.tsp.test;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import junit.framework.Assert;
import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampResponseGenerator;
import org.bouncycastle.tsp.TimeStampTokenGenerator;
import org.bouncycastle.tsp.ers.ArchiveTimeStampValidationException;
import org.bouncycastle.tsp.ers.ERSArchiveTimeStamp;
import org.bouncycastle.tsp.ers.ERSArchiveTimeStampGenerator;
import org.bouncycastle.tsp.ers.ERSByteData;
import org.bouncycastle.tsp.ers.ERSData;
import org.bouncycastle.tsp.ers.ERSDataGroup;
import org.bouncycastle.tsp.ers.ERSDirectoryDataGroup;
import org.bouncycastle.tsp.ers.ERSEvidenceRecord;
import org.bouncycastle.tsp.ers.ERSEvidenceRecordGenerator;
import org.bouncycastle.tsp.ers.ERSFileData;
import org.bouncycastle.tsp.ers.ERSInputStreamData;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;

public class ERSTest
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    public static final byte[] H1_DATA = Strings.toByteArray("This is H1");
    public static final byte[] H2_DATA = Strings.toByteArray("This is H2");
    public static final byte[] H3A_DATA = Strings.toByteArray("This is H3A");
    public static final byte[] H3B_DATA = Strings.toByteArray("This is H3B");
    public static final byte[] H3C_DATA = Strings.toByteArray("This is H3C");
    public static final byte[] H4_DATA = Strings.toByteArray("This is H4");

    public void setUp()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    public void testBasicBuild()
        throws Exception
    {
        ERSData h1Doc = new ERSByteData(H1_DATA);
        ERSData h2Doc = new ERSByteData(H2_DATA);
        ERSDataGroup h3Docs = new ERSDataGroup(
            new ERSData[]{new ERSByteData(H3A_DATA),
                new ERSByteData(H3B_DATA),
                new ERSByteData(H3C_DATA)});

        DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().build();
        DigestCalculator digestCalculator = digestCalculatorProvider.get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256));

        ERSArchiveTimeStampGenerator ersGen = new ERSArchiveTimeStampGenerator(digestCalculator);

        ersGen.addData(h1Doc);
        ersGen.addData(h2Doc);
        ersGen.addData(h3Docs);

        TimeStampRequestGenerator tspReqGen = new TimeStampRequestGenerator();
        tspReqGen.setCertReq(true);

        ERSArchiveTimeStamp ats = ersGen.generateArchiveTimeStamp(tspReqGen, tspReq ->
            {
                Assert.assertTrue(Arrays.areEqual(Hex.decode("98fbf91c1aebdfec514d4a76532ec95f27ebcf4c8b6f7e2947afcbbfe7084cd4"),
                        tspReq.getMessageImprintDigest()));


                String signDN = "O=Bouncy Castle, C=AU";
                KeyPair signKP = TSPTestUtil.makeKeyPair();
                X509Certificate signCert = TSPTestUtil.makeCACertificate(signKP,
                        signDN, signKP, signDN);

                String origDN = "CN=Eric H. Echidna, E=eric@bouncycastle.org, O=Bouncy Castle, C=AU";
                KeyPair origKP = TSPTestUtil.makeKeyPair();
                X509Certificate origCert = TSPTestUtil.makeCertificate(origKP,
                        origDN, signKP, signDN);

                List certList = new ArrayList();
                certList.add(origCert);
                certList.add(signCert);

                Store certs = new JcaCertStore(certList);

                JcaSignerInfoGeneratorBuilder infoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build());

                TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(infoGeneratorBuilder.build(new JcaContentSignerBuilder("MD5withRSA").setProvider(BC).build(origKP.getPrivate()), origCert), new SHA1DigestCalculator(), new ASN1ObjectIdentifier("1.2.3"));

                tsTokenGen.addCertificates(certs);

                TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms.ALLOWED);

                try
                {
                    return tsRespGen.generateGrantedResponse(tspReq, new BigInteger("23"), new Date());
                }
                catch (TSPException e)
                {
                    return tsRespGen.generateRejectedResponse(e);
                }
            }
        );

        ats = new ERSArchiveTimeStamp(ats.getEncoded(), digestCalculatorProvider);

        ats.validatePresent(h1Doc, new Date());
        ats.validatePresent(h2Doc, new Date());
        ats.validatePresent(h3Docs, new Date());

        // check for individual sub-documents
        List<byte[]> h3Hashes = h3Docs.getHashes(digestCalculator);
        for (int i = 0; i != h3Hashes.size(); i++)
        {
            ats.validatePresent((byte[])h3Hashes.get(i), new Date());
        }

        X509CertificateHolder tspCert = ats.getSigningCertificate();

        ats.validate(new JcaSimpleSignerInfoVerifierBuilder().build(tspCert));
    }

    public void testSingleTimeStamp()
        throws Exception
    {
        ERSData h1Doc = new ERSByteData(H1_DATA);
        ERSData h2Doc = new ERSByteData(H2_DATA);
        ERSDataGroup h3Docs = new ERSDataGroup(
            new ERSData[]{new ERSByteData(H3A_DATA),
                new ERSByteData(H3B_DATA),
                new ERSByteData(H3C_DATA)});

        DigestCalculator digestCalculator = new JcaDigestCalculatorProviderBuilder().build().get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256));
        List<byte[]> hashes = h3Docs.getHashes(
            digestCalculator);

        ERSArchiveTimeStampGenerator ersGen = new ERSArchiveTimeStampGenerator(digestCalculator);

        ersGen.addData(h1Doc);

        TimeStampRequestGenerator tspReqGen = new TimeStampRequestGenerator();
        tspReqGen.setCertReq(true);

        ERSArchiveTimeStamp ats = ersGen.generateArchiveTimeStamp(tspReqGen, tspReq ->
            {
                String signDN = "O=Bouncy Castle, C=AU";
                KeyPair signKP = TSPTestUtil.makeKeyPair();
                X509Certificate signCert = TSPTestUtil.makeCACertificate(signKP,
                        signDN, signKP, signDN);

                String origDN = "CN=Eric H. Echidna, E=eric@bouncycastle.org, O=Bouncy Castle, C=AU";
                KeyPair origKP = TSPTestUtil.makeKeyPair();
                X509Certificate origCert = TSPTestUtil.makeCertificate(origKP,
                        origDN, signKP, signDN);


                List certList = new ArrayList();
                certList.add(origCert);
                certList.add(signCert);

                Store certs = new JcaCertStore(certList);

                JcaSignerInfoGeneratorBuilder infoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build());

                TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(infoGeneratorBuilder.build(new JcaContentSignerBuilder("MD5withRSA").setProvider(BC).build(origKP.getPrivate()), origCert), new SHA1DigestCalculator(), new ASN1ObjectIdentifier("1.2.3"));

                tsTokenGen.addCertificates(certs);

                TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms.ALLOWED);

                try
                {
                    return tsRespGen.generateGrantedResponse(tspReq, new BigInteger("23"), new Date());
                }
                catch (TSPException e)
                {
                    return tsRespGen.generateRejectedResponse(e);
                }
            }
        );

        ats.validatePresent(h1Doc, new Date());

        try
        {
            ats.validatePresent(h2Doc, new Date());
            fail();
        }
        catch (ArchiveTimeStampValidationException e)
        {
            assertEquals("object hash not found in wrapped timestamp", e.getMessage());
        }
    }

    public void testBasicBuildEvidenceRecord()
        throws Exception
    {
        ERSData h1Doc = new ERSByteData(H1_DATA);
        ERSData h2Doc = new ERSByteData(H2_DATA);
        ERSDataGroup h3Docs = new ERSDataGroup(
            new ERSData[]{new ERSByteData(H3A_DATA),
                new ERSByteData(H3B_DATA),
                new ERSByteData(H3C_DATA)});

        DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().build();
        DigestCalculator digestCalculator = digestCalculatorProvider.get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256));

        ERSArchiveTimeStampGenerator ersGen = new ERSArchiveTimeStampGenerator(digestCalculator);

        ersGen.addData(h1Doc);
        ersGen.addData(h2Doc);
        ersGen.addData(h3Docs);

        TimeStampRequestGenerator tspReqGen = new TimeStampRequestGenerator();

        tspReqGen.setCertReq(true);

        ERSArchiveTimeStamp ats = ersGen.generateArchiveTimeStamp(tspReqGen, tspReq ->
            {
                Assert.assertTrue(Arrays.areEqual(Hex.decode("98fbf91c1aebdfec514d4a76532ec95f27ebcf4c8b6f7e2947afcbbfe7084cd4"),
                        tspReq.getMessageImprintDigest()));


                String signDN = "O=Bouncy Castle, C=AU";
                KeyPair signKP = TSPTestUtil.makeKeyPair();
                X509Certificate signCert = TSPTestUtil.makeCACertificate(signKP,
                        signDN, signKP, signDN);

                String origDN = "CN=Eric H. Echidna, E=eric@bouncycastle.org, O=Bouncy Castle, C=AU";
                KeyPair origKP = TSPTestUtil.makeKeyPair();
                X509Certificate origCert = TSPTestUtil.makeCertificate(origKP,
                        origDN, signKP, signDN);


                List certList = new ArrayList();
                certList.add(origCert);
                certList.add(signCert);

                Store certs = new JcaCertStore(certList);

                JcaSignerInfoGeneratorBuilder infoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build());

                TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(infoGeneratorBuilder.build(new JcaContentSignerBuilder("MD5withRSA").setProvider(BC).build(origKP.getPrivate()), origCert), new SHA1DigestCalculator(), new ASN1ObjectIdentifier("1.2.3"));

                tsTokenGen.addCertificates(certs);

                TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms.ALLOWED);

                try
                {
                    return tsRespGen.generateGrantedResponse(tspReq, new BigInteger("23"), new Date());
                }
                catch (TSPException e)
                {
                    return tsRespGen.generateRejectedResponse(e);
                }
            }
        );

        ERSEvidenceRecordGenerator evGen = new ERSEvidenceRecordGenerator(digestCalculatorProvider);

        ERSEvidenceRecord ev = evGen.generate(ats);

        ev.validatePresent(h1Doc, new Date());
        ev.validatePresent(h2Doc, new Date());
        ev.validatePresent(h3Docs, new Date());

        // check for individual sub-documents
        List<byte[]> h3Hashes = h3Docs.getHashes(digestCalculator);
        for (int i = 0; i != h3Hashes.size(); i++)
        {
            ev.validatePresent((byte[])h3Hashes.get(i), new Date());
        }

        X509CertificateHolder tspCert = ev.getSigningCertificate();

        ev.validate(new JcaSimpleSignerInfoVerifierBuilder().build(tspCert));

        ERSEvidenceRecord ev2 = new ERSEvidenceRecord(ev.getEncoded(), digestCalculatorProvider);

        tspCert = ev2.getSigningCertificate();

        ev2.validate(new JcaSimpleSignerInfoVerifierBuilder().build(tspCert));

        ev2.validatePresent(h3Docs, new Date());
    }

    public void test4NodeBuild()
        throws Exception
    {
        ERSData h1Doc = new ERSByteData(H1_DATA);
        ERSData h2Doc = new ERSByteData(H2_DATA);
        ERSDataGroup h3Docs = new ERSDataGroup(
            new ERSData[]{new ERSByteData(H3A_DATA),
                new ERSByteData(H3B_DATA),
                new ERSByteData(H3C_DATA)});
        ERSData h4Doc = new ERSByteData(H4_DATA);

        DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().build();
        DigestCalculator digestCalculator = digestCalculatorProvider.get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256));

        ERSArchiveTimeStampGenerator ersGen = new ERSArchiveTimeStampGenerator(digestCalculator);

        ersGen.addData(h1Doc);
        ersGen.addData(h2Doc);
        ersGen.addData(h3Docs);
        ersGen.addData(h4Doc);

        TimeStampRequestGenerator tspReqGen = new TimeStampRequestGenerator();
        tspReqGen.setCertReq(true);

        ersGen.generateArchiveTimeStamp(tspReqGen, tspReq ->
                {
                    Assert.assertTrue(Arrays.areEqual(Hex.decode("d82fea0eaff4b12925a201dff2332965953ca38c1eef6c9e31b55bbce4ce2984"),
                            tspReq.getMessageImprintDigest()));
                    return null;
                }
        );

        ersGen = new ERSArchiveTimeStampGenerator(digestCalculator);

        List<ERSData> dataList = new ArrayList<ERSData>();

        dataList.add(h1Doc);
        dataList.add(h2Doc);
        dataList.add(h3Docs);
        dataList.add(h4Doc);

        ersGen.addAllData(dataList);

        tspReqGen = new TimeStampRequestGenerator();

        tspReqGen.setCertReq(true);

        ersGen.generateArchiveTimeStamp(tspReqGen, tspReq ->
                {
                    Assert.assertTrue(Arrays.areEqual(Hex.decode("d82fea0eaff4b12925a201dff2332965953ca38c1eef6c9e31b55bbce4ce2984"),
                            tspReq.getMessageImprintDigest()));
                    return null;
                }
        );
    }

    public void testDirUtil()
        throws Exception
    {
        File rootDir = File.createTempFile("ers", ".dir");
        rootDir.delete();
        if (rootDir.mkdir())
        {
            DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().build();
            DigestCalculator digestCalculator = digestCalculatorProvider.get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256));

            File h1 = new File(rootDir, "h1");
            OutputStream fOut = new FileOutputStream(h1);
            fOut.write(H1_DATA);
            fOut.close();

            File h2 = new File(rootDir, "h2");
            fOut = new FileOutputStream(h2);
            fOut.write(H2_DATA);
            fOut.close();

            File h3 = new File(rootDir, "h3");
            h3.mkdir();
            fOut = new FileOutputStream(new File(h3, "a"));
            fOut.write(H3A_DATA);
            fOut.close();
            fOut = new FileOutputStream(new File(h3, "b"));
            fOut.write(H3B_DATA);
            fOut.close();
            fOut = new FileOutputStream(new File(h3, "c"));
            fOut.write(H3C_DATA);
            fOut.close();

            ERSArchiveTimeStampGenerator ersGen = new ERSArchiveTimeStampGenerator(digestCalculator);

            ersGen.addData(new ERSFileData(h1));
            ersGen.addData(new ERSFileData(h2));
            ersGen.addData(new ERSDirectoryDataGroup(h3));

            TimeStampRequestGenerator tspReqGen = new TimeStampRequestGenerator();

            tspReqGen.setCertReq(true);

            ersGen.generateArchiveTimeStamp(tspReqGen, tspReq ->
                    {
                        Assert.assertTrue(Arrays.areEqual(Hex.decode("98fbf91c1aebdfec514d4a76532ec95f27ebcf4c8b6f7e2947afcbbfe7084cd4"),
                                tspReq.getMessageImprintDigest()));
                        return null;
                    }
            );

            deleteDirectory(rootDir);
        }
        else
        {
            throw new Exception("can't create temp dir");
        }
    }

    public void testBSIData()
        throws Exception
    {
        ERSEvidenceRecord ers = new ERSEvidenceRecord(Streams.readAll(getClass().getResourceAsStream("BIN_ER.ers")), new JcaDigestCalculatorProviderBuilder().build());

        ers.getLastArchiveTimeStamp().validate(new JcaSimpleSignerInfoVerifierBuilder().build(ers.getSigningCertificate()));

        ers.validatePresent(new ERSInputStreamData(getClass().getResourceAsStream("BIN.bin")), new Date());
    }

    public void testBSIDataXML()
        throws Exception
    {
        ERSEvidenceRecord ers = new ERSEvidenceRecord(Base64.decode("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"), new JcaDigestCalculatorProviderBuilder().build());

        ers.getLastArchiveTimeStamp().validate(new JcaSimpleSignerInfoVerifierBuilder().build(ers.getSigningCertificate()));
  
        ers.validatePresent(Hex.decode("9CE2D7D350F9418407439F0CA11DCC12AB9F7CDB15F9ECC5ECA935482602B872"), new Date());
        ers.validatePresent(Hex.decode("EECC4D3352C0E965FD88795EDFD1A60C5AC09B3C1100C052EBB6AE0BD3432B26"), new Date());

        // look for data group
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(Arrays.concatenate(
            Hex.decode("9CE2D7D350F9418407439F0CA11DCC12AB9F7CDB15F9ECC5ECA935482602B872"),
            Hex.decode("EECC4D3352C0E965FD88795EDFD1A60C5AC09B3C1100C052EBB6AE0BD3432B26")));

        ers.validatePresent(digest, new Date());
    }

    private void deleteDirectory(File directory)
    {
        File[] files = directory.listFiles();
        if (files != null)
        {
            for (int i = 0; i != files.length; i++)
            {
                deleteDirectory(files[i]);
            }
        }
        directory.delete();
    }

    public void testSort()
        throws Exception
    {
        ERSDataGroup h3Docs = new ERSDataGroup(
            new ERSData[]{new ERSByteData(H1_DATA),
                new ERSByteData(H2_DATA)}
        );

        DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().build();

        trySort(h3Docs, NISTObjectIdentifiers.id_sha256, digestCalculatorProvider);

        h3Docs = new ERSDataGroup(
            new ERSData[]{new ERSByteData(H2_DATA),
                new ERSByteData(H1_DATA)}
        );

        trySort(h3Docs, NISTObjectIdentifiers.id_sha256, digestCalculatorProvider);

        h3Docs = new ERSDataGroup(
            new ERSData[]{new ERSByteData(H1_DATA),
                new ERSByteData(H2_DATA),
                new ERSByteData(H3A_DATA),
                new ERSByteData(H3B_DATA),
                new ERSByteData(H3C_DATA),
                new ERSByteData(H4_DATA)}
        );
        trySort(h3Docs, NISTObjectIdentifiers.id_sha256, digestCalculatorProvider);
        trySort(h3Docs, NISTObjectIdentifiers.id_sha224, digestCalculatorProvider);
        trySort(h3Docs, NISTObjectIdentifiers.id_sha384, digestCalculatorProvider);
    }

    private void trySort(ERSDataGroup h3Docs, ASN1ObjectIdentifier sha, DigestCalculatorProvider digestCalculatorProvider)
        throws OperatorCreationException
    {
        List<byte[]> hashes = h3Docs.getHashes(digestCalculatorProvider.get(
            new AlgorithmIdentifier(sha)));
        for (int i = 0; i != hashes.size() - 1; i++)
        {
            assertTrue(compare((byte[])hashes.get(i), (byte[])hashes.get(i + 1)) < 0);
        }
    }

    private int compare(byte[] a, byte[] b)
    {
        return new BigInteger(1, a).compareTo(new BigInteger(1, b));
    }
}
