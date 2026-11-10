# SmartLock A2 - progress / handoff

**Roll 23i-0688, Section E.** Last worked: 2026-11-10. Repo:
https://github.com/FaatehHaneef/smartlock-break-build (public, by choice).

## How to resume (environment)
- Develop in **WSL Ubuntu** (`wsl -d Ubuntu`), user `fuul`, g++ 13.3, libssl-dev 3.0.13 installed.
- Project path in WSL: `/mnt/c/Users/sfate/OneDrive/Desktop/Info sec A2`.
- `instance.txt` is git-ignored (regenerate: `cd SmartLock/smartlock && make && ./instance_generator 23i-0688`).
- Build/run commands for every part are in `23i-0688-E/README.txt`.
- Each phase ends with focused commits pushed to `main`; **no Claude Code co-author line** on commits.

## DONE (all code + measurement, committed & pushed)
- Phase 0: v1 builds, instance generated (port 9377), normal session verified.
- Part A (all 5 exploits + PIN), `23i-0688-E/exploits/`:
  - TASKA1 downgrade, TASKA2 impersonation/MITM, TASKA3 keying, TASKA4 nonce, TASKA5 replay, pincrack.
  - `23i-0688-E/answers.txt` fully filled from the wire (flag, recovered_dh_b=46088512346, cracked_pin, nonce_xor_hex).
- Part C: `SmartLock/v2_skeleton/securelink2.cpp` (copied to `23i-0688-E/securelink2.cpp`).
  All 6 self-checks PASS (`evidence/v2_selfcheck_output.txt`); v2 builds & runs.
- C.2: re-run evidence in `23i-0688-E/evidence/` (downgrade+impersonation blocked, keying/nonce/replay N/A).
- Part D: `23i-0688-E/performance/` harness (TASKD), CSV data, `perf_results.md`, SVG chart.

## REMAINING (pick up here)
1. **Part B design write-up** (18): threat model; per-stage mechanism tied to each A attack; v2 handshake diagram. -> report content.
2. **Report REPORT.pdf**: assemble Parts A-D with evidence inline; the C.2 "v1 attack -> v2 result" table; scope/ethics paragraph; and the **AI-audit reflection (3 marks) in your own words**. Report tooling not yet decided (draft in Markdown, finalize in Word, or generate via pandoc).
3. **Kali evidence pass**: produce real `.pcap`s + Wireshark "Follow TCP Stream" screenshots. A drop-in folder + `KALI_RUNBOOK.md` still to be prepared; then it's just capture/screenshot.
4. **Viva prep** (be able to re-run exploits on an unseen capture; explain own code).

## Gotchas learned
- Run v1/v2 lock in background and **kill by captured PID**, not `pkill -f "lock_server instance.txt"` (that pattern matches the parent shell).
- When backgrounding a lock for benchmarks, invoke the binary directly (absolute path) so `$!` is the lock's PID, not a subshell's.
- LF->CRLF git warnings on Windows are harmless.
- Exploits must RE-DERIVE values from captures, never hard-code (grading + viva).
