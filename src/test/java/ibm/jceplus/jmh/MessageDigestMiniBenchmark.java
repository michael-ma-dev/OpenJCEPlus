/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.jmh;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;

@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@State(Scope.Benchmark)
@Warmup(iterations = 2, time = 3, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 3, time = 5, timeUnit = TimeUnit.SECONDS)
public class MessageDigestMiniBenchmark extends JMHBase {

    @Param({"16", "2048", "32768"})
    private int payloadSize;

    @Param({"OpenJCEPlus-OpenSSL", "OpenJCEPlus-OpenSSL-FFM"})
    private String provider;

    private MessageDigest messageDigestSHA256;
    private byte[] payload;
    protected SecureRandom random = new SecureRandom();

    @Setup
    public void setup() throws Exception {
        super.setup(provider);

        payload = new byte[payloadSize];
        random.nextBytes(payload);
        messageDigestSHA256 = MessageDigest.getInstance("SHA-256", provider);
    }

    @Benchmark
    public byte[] sha256UpdateDigest() {
        messageDigestSHA256.update(payload);
        return messageDigestSHA256.digest();
    }

    @Benchmark
    public byte[] sha256SingleShotDigest() {
        return messageDigestSHA256.digest(payload);
    }

    public static void main(String[] args) throws RunnerException {
        String testSimpleName = MessageDigestMiniBenchmark.class.getSimpleName();
        Options opt = optionsBuild(testSimpleName, testSimpleName);
        new Runner(opt).run();
    }
}
