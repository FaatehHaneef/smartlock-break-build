# Kali evidence runbook (roll 23i-0688, section E)

Goal: produce the `.pcap` captures and Wireshark screenshots that are the Part A
and C.2 evidence. Everything runs on this one Kali VM over loopback (`lo`); the
on-path attacks use the local relay, which the brief accepts as the two-VM model.

Scope/ethics: all capture and interception is on this VM's own loopback, no other
network is touched.

Open TWO terminals (call them T1 = lock, T2 = hub/attacker). Run tcpdump with
`sudo` in a third if you prefer; `lo` capture needs root.

--------------------------------------------------------------------------------
## 0. One-time setup

```
# get the code (public repo)
cd ~
git clone https://github.com/FaatehHaneef/smartlock-break-build.git
cd smartlock-break-build

# tools (Kali usually has wireshark/tshark/tcpdump/hashcat already)
sudo apt update
sudo apt install -y build-essential libssl-dev wireshark tshark tcpdump hashcat

# build everything
make -C SmartLock/smartlock
make -C SmartLock/v2_skeleton

# regenerate YOUR instance (instance.txt is not in the repo)
cd SmartLock/smartlock
./instance_generator 23i-0688          # prints: listens on port 9377
cd ../..

# build the exploits + tools (each binary lands in /tmp)
cd 23i-0688-E/exploits
for f in 23i-0688-E-TASKA1-V1 23i-0688-E-TASKA2-V1 23i-0688-E-TASKA3-V1 23i-0688-E-TASKA4-V1 23i-0688-E-TASKA5-V1 23i-0688-E-pincrack; do
  g++ -std=c++17 -O2 -Wall "$f.cpp" -o "/tmp/$f" -lcrypto
done
cd ../..
g++ -std=c++17 -O2 -Wall tools/wiretap.cpp -o /tmp/wiretap
```

Smoke test (T1 then T2):
```
# T1
cd ~/smartlock-break-build/SmartLock/smartlock && ./lock_server instance.txt
# T2
cd ~/smartlock-break-build/SmartLock/smartlock && ./hub_client instance.txt 127.0.0.1
```
You should see the greeting with your flag. Ctrl-C the lock when done.

PORT is 9377 throughout. All capture files go in `23i-0688-E/evidence/`.

--------------------------------------------------------------------------------
## 1. Baseline capture (v1 normal) -> feeds A3, A4, PIN

```
# T3: start capture
cd ~/smartlock-break-build
sudo tcpdump -i lo -w 23i-0688-E/evidence/cap_v1_normal.pcap tcp port 9377 &
# T1: lock
cd SmartLock/smartlock && ./lock_server instance.txt
# T2: one normal hub session
cd ~/smartlock-break-build/SmartLock/smartlock && ./hub_client instance.txt 127.0.0.1
# T3: stop capture
sudo pkill tcpdump
```
Wireshark: `wireshark 23i-0688-E/evidence/cap_v1_normal.pcap`, right-click a
packet -> Follow -> TCP Stream. Screenshot it: you can read HELLO, SUITE, CERT,
PAIR, DH, DHCLIENT and the MSG records in clear. Save as
`evidence/shot_v1_normal_stream.png`.

Extract a transcript from the pcap (this is the viva skill: recover from a
capture, not from instance.txt):
```
tshark -r 23i-0688-E/evidence/cap_v1_normal.pcap -T fields -e tcp.payload -Y "tcp.len>0" \
  | tr -d '\n' | tr -d ':' | xxd -r -p > 23i-0688-E/evidence/cap_v1_normal.transcript
```
Run the exploits against it (tool-output evidence):
```
/tmp/23i-0688-E-TASKA3-V1 23i-0688-E/evidence/cap_v1_normal.transcript   # flag + b
/tmp/23i-0688-E-TASKA4-V1 23i-0688-E/evidence/cap_v1_normal.transcript   # nonce XOR
/tmp/23i-0688-E-pincrack  23i-0688-E/evidence/cap_v1_normal.transcript SmartLock/smartlock/pin_wordlist.txt
```
PIN with hashcat (standard tool, see exploits/23i-0688-E-pincrack-hashcat.txt):
```
echo b0724bb7ba89050217feac138f354b28 > /tmp/captured.md5    # read the real hash from the PAIR line
hashcat -m 0 -a 6 /tmp/captured.md5 SmartLock/smartlock/pin_wordlist.txt ?d?d?d --potfile-disable
```

--------------------------------------------------------------------------------
## 2. A1 downgrade capture

```
# T3
sudo tcpdump -i lo -w 23i-0688-E/evidence/cap_v1_downgrade.pcap "tcp port 9377 or tcp port 9999" &
# T1: lock
./lock_server instance.txt
# T2: relay, then hub pointed at the relay
/tmp/23i-0688-E-TASKA1-V1 9999 127.0.0.1 9377 &
./hub_client instance.txt 127.0.0.1 9999
# T3
sudo pkill tcpdump
```
Screenshot the relay terminal (shows "rewrote HELLO -> NULL" and CLEARTEXT
records) and the Wireshark stream showing `suites:NULL` and the plaintext
greeting. Save `shot_v1_downgrade.png`.

--------------------------------------------------------------------------------
## 3. A2 impersonation/MITM capture

```
# T3
sudo tcpdump -i lo -w 23i-0688-E/evidence/cap_v1_mitm.pcap "tcp port 9377 or tcp port 9999" &
# T1: lock
./lock_server instance.txt
# T2
/tmp/23i-0688-E-TASKA2-V1 9999 127.0.0.1 9377 &
./hub_client instance.txt 127.0.0.1 9999
# T3
sudo pkill tcpdump
```
Screenshot the relay terminal: it prints two different session keys and reads
every record; the hub shows `device claims to be: smartlock-IMPOSTOR.local`.
Save `shot_v1_mitm.png`.

--------------------------------------------------------------------------------
## 4. A5 replay capture

```
# T1: lock (fresh, so the counter starts at 0)
./lock_server instance.txt
# T3
sudo tcpdump -i lo -w 23i-0688-E/evidence/cap_v1_replay.pcap tcp port 9377 &
# T2: replay the captured UNLOCK 3 times (needs a transcript from step 1)
/tmp/23i-0688-E-TASKA5-V1 127.0.0.1 9377 3 23i-0688-E/evidence/cap_v1_normal.transcript
./hub_client instance.txt 127.0.0.1          # read STATUS: unlocks=3
# T3
sudo pkill tcpdump
```
Screenshot the replay output (unlock #1..#3) and the STATUS showing the counter
climbed. Save `shot_v1_replay.png`.

--------------------------------------------------------------------------------
## 5. v2 evidence (C.2)

Normal v2 session (succeeds):
```
sudo tcpdump -i lo -w 23i-0688-E/evidence/cap_v2_normal.pcap tcp port 9377 &
# T1
cd ~/smartlock-break-build/SmartLock/v2_skeleton && ./lock_server2 ../smartlock/instance.txt
# T2
cd ~/smartlock-break-build/SmartLock/v2_skeleton && ./hub_client2 ../smartlock/instance.txt 127.0.0.1
sudo pkill tcpdump
```
Downgrade blocked:
```
# T1: ./lock_server2 ../smartlock/instance.txt
# T2: /tmp/23i-0688-E-TASKA1-V1 9999 127.0.0.1 9377 &   then
#     ./hub_client2 ../smartlock/instance.txt 127.0.0.1 9999   -> "[hub] abort: no suite"
```
Impersonation blocked:
```
# T1: ./lock_server2 ../smartlock/instance.txt
# T2: /tmp/23i-0688-E-TASKA2-V1 9999 127.0.0.1 9377 &   then
#     ./hub_client2 ../smartlock/instance.txt 127.0.0.1 9999
#     -> "[hub] abort: device key is not the pinned key"
```
Also build + run the C.1 self-test and screenshot ALL CHECKS PASSED:
```
cd ~/smartlock-break-build/SmartLock/v2_skeleton
g++ -std=c++17 -O2 -Wall securelink2_selftest.cpp securelink2.cpp -o /tmp/selftest -lcrypto
/tmp/selftest
```

--------------------------------------------------------------------------------
## 6. Save the evidence

Put every `.pcap` and screenshot in `23i-0688-E/evidence/`. Then either commit
from Kali (if your git is signed in) or copy them back to Windows later:
```
git add 23i-0688-E/evidence
git commit -m "Add Kali packet captures and screenshots (Part A + C.2 evidence)"
git push
```
```
```
