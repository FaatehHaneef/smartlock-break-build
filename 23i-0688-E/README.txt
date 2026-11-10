SmartLock Assignment 2 - Submission
Roll: 23i-0688    Section: E

All code is C++17 and links OpenSSL's libcrypto. Built and tested on Ubuntu
24.04 (WSL2) and Kali with g++ 13.3 and OpenSSL 3.0.13. The lock/hub code is
POSIX (sockets), so build and run it on Linux (Kali or Ubuntu), not native
Windows/MSYS2.

One-time dependency:
  sudo apt install build-essential libssl-dev

--------------------------------------------------------------------------------
Contents
  23i-0688-E-REPORT.pdf   Report covering Parts A-D (added last).
  answers.txt             Part A.1 recovered secrets (key = value).
  README.txt              This file.
  securelink2.cpp         Part C module (also built in SmartLock/v2_skeleton/).
  exploits/               Part A exploits + shared header + PIN crack.
  performance/            Part D harness (TASKD), raw CSV data, and chart.
  evidence/               Captures/transcripts and tool output.

--------------------------------------------------------------------------------
1. Build v1 and generate the instance (done once)

  cd SmartLock/smartlock
  make
  ./instance_generator 23i-0688      # writes instance.txt (listens on port 9377)
  ./lock_server instance.txt         # terminal 1
  ./hub_client  instance.txt 127.0.0.1   # terminal 2 (normal session)

--------------------------------------------------------------------------------
2. Part A exploits (from exploits/)

Each exploit works from a captured session. A transcript is one line per wire
message (key:value, TAB separated) - identical to Wireshark "Follow TCP Stream".
A capture is in evidence/keying_session.transcript; on Kali, produce a .pcap with
tcpdump and export the stream to the same text form. The shared header
23i-0688-E-TASKA-common.hpp has the discrete log, AES-GCM, and transcript parser.

  g++ -std=c++17 -O2 -Wall 23i-0688-E-TASKA3-V1.cpp -o taska3 -lcrypto
  ./taska3 ../evidence/keying_session.transcript        # keying: recover b + flag

  g++ -std=c++17 -O2 -Wall 23i-0688-E-TASKA4-V1.cpp -o taska4 -lcrypto
  ./taska4 ../evidence/keying_session.transcript        # nonce reuse: read records

  g++ -std=c++17 -O2 -Wall 23i-0688-E-pincrack.cpp -o pincrack -lcrypto
  ./pincrack ../evidence/keying_session.transcript ../../SmartLock/smartlock/pin_wordlist.txt

  # Replay (needs a running lock). Start ./lock_server first, then:
  g++ -std=c++17 -O2 -Wall 23i-0688-E-TASKA5-V1.cpp -o taska5 -lcrypto
  ./taska5 127.0.0.1 9377 3 ../evidence/keying_session.transcript

  # On-path relays (downgrade, impersonation). Start the lock, start the relay,
  # then point the hub at the relay's port:
  g++ -std=c++17 -O2 -Wall 23i-0688-E-TASKA1-V1.cpp -o taska1 -lcrypto
  ./taska1 9999 127.0.0.1 9377     # then: ./hub_client instance.txt 127.0.0.1 9999
  g++ -std=c++17 -O2 -Wall 23i-0688-E-TASKA2-V1.cpp -o taska2 -lcrypto
  ./taska2 9999 127.0.0.1 9377     # then: ./hub_client instance.txt 127.0.0.1 9999

PIN cracking with a standard tool (Kali): see exploits/23i-0688-E-pincrack-hashcat.txt.

--------------------------------------------------------------------------------
3. Part C - v2 (from SmartLock/v2_skeleton/)

  make                                   # builds lock_server2 and hub_client2
  ./lock_server2 ../smartlock/instance.txt
  ./hub_client2  ../smartlock/instance.txt 127.0.0.1    # normal authenticated session

  # Six-check self-test (output saved in evidence/v2_selfcheck_output.txt):
  g++ -std=c++17 -O2 -Wall securelink2_selftest.cpp securelink2.cpp -o selftest -lcrypto
  ./selftest

The graded module is securelink2.cpp (top level here, and in v2_skeleton/).

--------------------------------------------------------------------------------
4. Part D - performance (from performance/)

  g++ -std=c++17 -O2 -Wall -I../../SmartLock/smartlock -I../../SmartLock/v2_skeleton \
      23i-0688-E-TASKD-V1.cpp ../../SmartLock/v2_skeleton/securelink2.cpp -o taskd -lcrypto
  ./taskd micro 10000 5            # record overhead, latency, throughput
  # handshake timing (start the matching lock first):
  ./taskd hs-v1 127.0.0.1 9377 30
  ./taskd hs-v2 127.0.0.1 9377 30

Results and chart: performance/perf_results.md, taskd_*.csv, and the SVG chart.

--------------------------------------------------------------------------------
Scope and ethics
  All interception, capture, and replay was performed only inside an isolated
  lab, between machines/processes under my own control, never on any other
  network.
