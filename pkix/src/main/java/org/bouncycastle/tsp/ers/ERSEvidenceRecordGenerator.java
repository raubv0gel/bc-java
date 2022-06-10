package org.bouncycastle.tsp.ers;

import org.bouncycastle.asn1.tsp.EvidenceRecord;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.tsp.TSPException;

public class ERSEvidenceRecordGenerator
{
    private final DigestCalculatorProvider digCalcProv;

    public ERSEvidenceRecordGenerator(DigestCalculatorProvider digCalcProv)
    {
        this.digCalcProv = digCalcProv;
    }

    public ERSEvidenceRecord generate(ERSArchiveTimeStamp archiveTimeStamp)
        throws TSPException, ERSException
    {
        return new ERSEvidenceRecord(
            new EvidenceRecord(null, null, archiveTimeStamp.toASN1Structure()), digCalcProv);
    }

    public ERSEvidenceRecord generateWithRenewedTimeStamp(ERSEvidenceRecord oldErsEvidenceRecord, ERSArchiveTimeStamp newArchiveTimeStamp)
            throws TSPException, ERSException
    {
        return new ERSEvidenceRecord(
            oldErsEvidenceRecord.toASN1Structure().addArchiveTimeStamp(newArchiveTimeStamp.toASN1Structure(), false), digCalcProv);
    }

    public ERSEvidenceRecord generateWithNewHashTree(ERSEvidenceRecord oldErsEvidenceRecord, ERSArchiveTimeStamp newArchiveTimeStamp)
            throws TSPException, ERSException
    {
        return new ERSEvidenceRecord(
            oldErsEvidenceRecord.toASN1Structure().addArchiveTimeStamp(newArchiveTimeStamp.toASN1Structure(), true), digCalcProv);
    }
}
