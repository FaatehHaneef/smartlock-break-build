SmartLock Assignment 2 - Submission
Roll: 23i-0688    Section: E

This folder is the submission package. Layout follows the assignment Deliverables.

Contents
  23i-0688-E-REPORT.pdf   Report covering Parts A-D (added last).
  answers.txt             Part A.1 recovered secrets (key = value).
  README.txt              This file.
  securelink2.cpp         Part C module (added in the Part C phase).
  exploits/               One file per Part A exploit:
                            23i-0688-E-TASKA1-V1.cpp  downgrade
                            23i-0688-E-TASKA2-V1.cpp  impersonation / MITM
                            23i-0688-E-TASKA3-V1.cpp  keying recovery
                            23i-0688-E-TASKA4-V1.cpp  nonce reuse
                            23i-0688-E-TASKA5-V1.cpp  replay
  performance/            23i-0688-E-TASKD-V1.cpp + raw data + chart (Part D).
  evidence/              Captures (.pcap), tool output, git_log.txt.

Build and run
  (Filled in as each component is added. All code is C++17 + OpenSSL libcrypto,
   built with g++ on Ubuntu/Kali: g++ -std=c++17 -O2 -Wall <file> -lcrypto.)

Scope and ethics
  All interception, capture, and replay was performed only inside an isolated
  lab, between machines under my own control, never on any other network.
