package org.bouncycastle.tsp.ers;

import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampResponse;


/**
 * Interface for an implementation that is able to generate a {@link TimeStampResponse}
 * for a given {@link TimeStampRequest}.
 */
@FunctionalInterface
public interface TimeStamper
{
	TimeStampResponse stamp(TimeStampRequest timeStampRequest)
			throws Exception;
}
