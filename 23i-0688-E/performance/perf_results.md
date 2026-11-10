# Part D - Performance results (v1 vs v2)

**Machine.** 11th Gen Intel Core i7-11800H @ 2.30GHz (16 logical cores), WSL2
Ubuntu 24.04 (kernel 6.6.87.2-microsoft-standard-WSL2), g++ 13.3.0.
**Flags.** `-std=c++17 -O2 -Wall`, `libcrypto` (OpenSSL 3.0.13), identical for v1 and v2.
**Baseline.** v1 under `AES256-GCM`.

**Method.**
- Record benchmarks run in-process: 10,000 records x 5 runs, 1 KiB plaintext.
  Latency is total time / records; throughput is bytes / time; mean and standard
  deviation are over the 5 runs. Raw data: `taskd_records.csv`.
- Handshake is timed from TCP connect to the greeting being decrypted, 30 runs
  each, against a locally running lock. Raw data: `taskd_v1_handshake.csv`,
  `taskd_v2_handshake.csv`.

| Metric                      | v1 (AES256-GCM) | v2             | v2 / v1 |
|-----------------------------|-----------------|----------------|---------|
| Record overhead (bytes)     | 16 (tag)        | 24 (8 seq+tag) | +8 B    |
| Seal latency (us/record)    | 0.92            | 1.09           | 1.18x   |
| Open latency (us/record)    | 1.20            | 1.24           | 1.03x   |
| Seal throughput (MB/s)      | 1110 +/- 15     | 941 +/- 24     | 0.85x   |
| Open throughput (MB/s)      | 852 +/- 11      | 827 +/- 28     | 0.97x   |
| Handshake (ms)              | 1.41 +/- 0.48   | 2.61 +/- 0.56  | 1.85x   |

Chart: `23i-0688-E-performance-chart.svg`.

**Trade-off (draft for the report).** v2 adds about 1.2 ms to each session
handshake and 8 bytes to each record, and gives up roughly 15% of seal
throughput. In return it buys an authenticated, pinned device identity (no
impersonation), a fresh 2048-bit ephemeral key exchange (forward secrecy, no
feasible discrete log), HKDF-derived per-direction keys, a unique nonce per
record, and sequence binding (no replay or reordering). For a device that opens
a front door, a one-time millisecond-scale cost per session and a few bytes per
message is irrelevant next to the attacks it closes; a lock that is fast but
lets a captured UNLOCK reopen the door is the real failure. The cost is paid
once per session (the handshake) and is dominated by the 2048-bit modular
exponentiation and the RSA signature verification, both of which are the point.
