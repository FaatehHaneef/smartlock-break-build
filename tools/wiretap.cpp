// Passive TCP wiretap (DEV AID, not a submission exploit).
//
// Sits between the hub and the lock, forwards every byte unchanged in both
// directions, and appends each completed newline-delimited line to a transcript
// file in arrival order. The SmartLock wire is line-based key:value text, so the
// transcript is byte-identical to Wireshark "Follow TCP Stream", which lets the
// Part A exploits be developed against it in WSL and then run unchanged on the
// real .pcap captured with tcpdump on Kali.
//
//   usage: wiretap <listen_port> <lock_host> <lock_port> <transcript_out>
//   e.g.:  ./wiretap 9999 127.0.0.1 9377 session.transcript
//
// Build: g++ -std=c++17 -O2 -Wall wiretap.cpp -o wiretap
#include <cstdio>
#include <cstring>
#include <string>
#include <fstream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <poll.h>
#include <unistd.h>

static int dial(const char* host, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_port = htons(port);
    inet_pton(AF_INET, host, &a.sin_addr);
    if (connect(fd, (sockaddr*)&a, sizeof a) < 0) { perror("connect lock"); return -1; }
    return fd;
}

// Pump bytes from src to dst, appending each completed '\n'-terminated line to
// the transcript. 'buf' accumulates a partial line across reads.
static bool pump(int src, int dst, std::string& buf, std::ofstream& log) {
    char tmp[4096];
    ssize_t n = read(src, tmp, sizeof tmp);
    if (n <= 0) return false;
    if (write(dst, tmp, n) < 0) return false;    // forward unchanged
    buf.append(tmp, n);
    size_t nl;
    while ((nl = buf.find('\n')) != std::string::npos) {
        log << buf.substr(0, nl) << "\n";        // one wire line
        log.flush();
        buf.erase(0, nl + 1);
    }
    return true;
}

int main(int argc, char** argv) {
    if (argc < 5) {
        fprintf(stderr, "usage: %s <listen_port> <lock_host> <lock_port> <transcript_out>\n", argv[0]);
        return 1;
    }
    int lport = std::stoi(argv[1]);
    const char* lhost = argv[2];
    int rport = std::stoi(argv[3]);
    std::ofstream log(argv[4], std::ios::out | std::ios::trunc);

    int s = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1; setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_addr.s_addr = INADDR_ANY; a.sin_port = htons(lport);
    if (bind(s, (sockaddr*)&a, sizeof a) < 0) { perror("bind"); return 1; }
    listen(s, 1);
    printf("[wiretap] listening on %d, forwarding to %s:%d, logging to %s\n",
           lport, lhost, rport, argv[4]);
    fflush(stdout);

    int hub = accept(s, nullptr, nullptr);
    if (hub < 0) { perror("accept"); return 1; }
    int lock = dial(lhost, rport);
    if (lock < 0) return 1;

    std::string hbuf, lbuf;
    pollfd fds[2] = {{hub, POLLIN, 0}, {lock, POLLIN, 0}};
    while (true) {
        if (poll(fds, 2, -1) < 0) break;
        if (fds[0].revents & POLLIN) if (!pump(hub, lock, hbuf, log)) break;
        if (fds[1].revents & POLLIN) if (!pump(lock, hub, lbuf, log)) break;
        if ((fds[0].revents | fds[1].revents) & (POLLHUP | POLLERR)) break;
    }
    close(hub); close(lock); close(s);
    printf("[wiretap] session closed, transcript written\n");
    return 0;
}
