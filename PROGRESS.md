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

## DONE since (2026-11-13)
- Kali evidence pass complete: real `.pcap`s + tool output + 2 Wireshark screenshots, pushed from Kali.
- Part B design write-up (`report/PartB-design.md`), aligned to the course slides (in-channel challenge-response + salted slow KDF for the PIN).
- AI-audit: user supplied their own wording (directional key separation; nonce reuse; faulty test harness) - now in the report; no PIN-mechanism point.
- Portfolio README with cover banner + handshake diagram (`report/cover.*`, `report/v2-handshake.*`).
- Final report compiled with **Tectonic** (LaTeX): `report/23i-0688-E-REPORT.tex` -> `23i-0688-E/23i-0688-E-REPORT.pdf` (9 pages). Tectonic exe: `C:\Users\sfate\AppData\Local\Programs\tectonic\tectonic.exe`. Rebuild: run it on the .tex from `report/`. SVG->PNG via `rsvg-convert` (installed); PDF view via `pdftoppm` (poppler, installed).

## REMAINING (pick up here)
1. **Final submission zip**: build `23i-0688-E.zip` from the `23i-0688-E/` folder per the Deliverables layout (no binaries/.git). Save `git log --stat` to `evidence/git_log.txt`.
2. **Viva prep** (be able to re-run exploits on an unseen capture; explain own code).
3. Optional polish: a v1 "attack map" diagram to mirror the v2 handshake figure; optional one-line build pointer on the report title page (rubric lists build commands there).

## Gotchas learned
- Run v1/v2 lock in background and **kill by captured PID**, not `pkill -f "lock_server instance.txt"` (that pattern matches the parent shell).
- When backgrounding a lock for benchmarks, invoke the binary directly (absolute path) so `$!` is the lock's PID, not a subshell's.
- LF->CRLF git warnings on Windows are harmless.
- Exploits must RE-DERIVE values from captures, never hard-code (grading + viva).
