#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pcap.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>

#pragma pack(push, 1)
struct Mac {
    uint8_t v[6];
};

struct Ethernet {
    Mac dmac;
    Mac smac;
    uint16_t type;
};

struct IPv4 {
    uint8_t vhl;
    uint8_t tos;
    uint16_t len;
    uint16_t id;
    uint16_t off;
    uint8_t ttl;
    uint8_t proto;
    uint16_t sum;
    uint32_t sip;
    uint32_t dip;
};

struct TCP {
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack;
    uint8_t hlen;
    uint8_t flags;
    uint16_t win;
    uint16_t sum;
    uint16_t urp;
};

struct PseudoHeader {
    uint32_t sip;
    uint32_t dip;
    uint8_t zero;
    uint8_t proto;
    uint16_t len;
};
#pragma pack(pop)

Mac myMac;

void usage() {
    printf("syntax : tls-block <interface> <server name>\n");
    printf("sample : tls-block wlan0 naver.com\n");
}

bool getMyMac(const char* dev) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return false;

    ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        close(fd);
        return false;
    }

    memcpy(myMac.v, ifr.ifr_hwaddr.sa_data, 6);
    close(fd);
    return true;
}

uint16_t checksum(const void* data, int len) {
    const uint8_t* p = (const uint8_t*)data;
    uint32_t sum = 0;

    while (len > 1) {
        uint16_t word;
        memcpy(&word, p, 2);
        sum += ntohs(word);
        p += 2;
        len -= 2;
    }

    if (len == 1) sum += (*p) << 8;

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return htons((uint16_t)(~sum));
}

uint16_t tcpChecksum(IPv4* ip, TCP* tcp, const uint8_t* data, int dataLen) {
    uint8_t buf[1500];
    PseudoHeader pseudo;
    int tcpLen = sizeof(TCP) + dataLen;

    pseudo.sip = ip->sip;
    pseudo.dip = ip->dip;
    pseudo.zero = 0;
    pseudo.proto = 6;
    pseudo.len = htons(tcpLen);

    memcpy(buf, &pseudo, sizeof(pseudo));
    memcpy(buf + sizeof(pseudo), tcp, sizeof(TCP));
    if (dataLen > 0) {
        memcpy(buf + sizeof(pseudo) + sizeof(TCP), data, dataLen);
    }

    return checksum(buf, sizeof(pseudo) + tcpLen);
}

int seqPlus(TCP* tcp, int dataLen) {
    int n = dataLen;
    if (tcp->flags & 0x02) n++;
    if (tcp->flags & 0x01) n++;
    return n;
}

uint16_t read16(const uint8_t* p) {
    return ((uint16_t)p[0] << 8) | p[1];
}

uint32_t read24(const uint8_t* p) {
    return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2];
}

bool getSniFromExt(uint8_t* data, int len, char* sni, int sniSize) {
    if (len < 2) return false;

    int pos = 0;
    int listLen = read16(data + pos);
    pos += 2;
    int end = pos + listLen;
    if (end > len) return false;

    while (pos + 3 <= end) {
        uint8_t nameType = data[pos];
        pos += 1;

        int nameLen = read16(data + pos);
        pos += 2;

        if (pos + nameLen > end) return false;

        if (nameType == 0) {
            if (nameLen >= sniSize) nameLen = sniSize - 1;
            memcpy(sni, data + pos, nameLen);
            sni[nameLen] = 0;
            return true;
        }

        pos += nameLen;
    }

    return false;
}

bool getSni(uint8_t* data, int dataLen, char* sni, int sniSize) {
    if (dataLen < 5) return false;

    if (data[0] != 0x16) return false;
    if (data[1] != 0x03) return false;

    int recordLen = read16(data + 3);
    if (recordLen <= 0) return false;
    if (dataLen < 5 + recordLen) return false;

    int pos = 5;

    if (pos + 4 > dataLen) return false;
    if (data[pos] != 0x01) return false;

    int handshakeLen = read24(data + pos + 1);
    pos += 4;
    if (pos + handshakeLen > dataLen) return false;

    if (pos + 34 > dataLen) return false;
    pos += 34;

    if (pos + 1 > dataLen) return false;
    int sessionLen = data[pos];
    pos += 1;
    if (pos + sessionLen > dataLen) return false;
    pos += sessionLen;

    if (pos + 2 > dataLen) return false;
    int cipherLen = read16(data + pos);
    pos += 2;
    if (pos + cipherLen > dataLen) return false;
    pos += cipherLen;

    if (pos + 1 > dataLen) return false;
    int compLen = data[pos];
    pos += 1;
    if (pos + compLen > dataLen) return false;
    pos += compLen;

    if (pos + 2 > dataLen) return false;
    int extensionsLen = read16(data + pos);
    pos += 2;
    if (pos + extensionsLen > dataLen) return false;

    int extEnd = pos + extensionsLen;
    while (pos + 4 <= extEnd) {
        int extType = read16(data + pos);
        pos += 2;

        int extLen = read16(data + pos);
        pos += 2;

        if (pos + extLen > extEnd) return false;

        if (extType == 0x0000) {
            return getSniFromExt(data + pos, extLen, sni, sniSize);
        }

        pos += extLen;
    }

    return false;
}

struct Buf {
    bool used;
    uint32_t sip;
    uint32_t dip;
    uint16_t sport;
    uint16_t dport;
    uint8_t data[8192];
    int len;
};

Buf bufs[16];

Buf* getBuf(IPv4* ip, TCP* tcp) {
    for (int i = 0; i < 16; i++) {
        if (!bufs[i].used) continue;
        if (bufs[i].sip == ip->sip &&
            bufs[i].dip == ip->dip &&
            bufs[i].sport == tcp->sport &&
            bufs[i].dport == tcp->dport) {
            return &bufs[i];
        }
    }

    for (int i = 0; i < 16; i++) {
        if (bufs[i].used) continue;
        bufs[i].used = true;
        bufs[i].sip = ip->sip;
        bufs[i].dip = ip->dip;
        bufs[i].sport = tcp->sport;
        bufs[i].dport = tcp->dport;
        bufs[i].len = 0;
        return &bufs[i];
    }

    return nullptr;
}

void clearBuf(Buf* buf) {
    if (buf == nullptr) return;
    memset(buf, 0, sizeof(Buf));
}

void forwardRst(pcap_t* handle, Ethernet* orgEth, IPv4* orgIp, TCP* orgTcp, int dataLen) {
    uint8_t packet[sizeof(Ethernet) + sizeof(IPv4) + sizeof(TCP)];
    memset(packet, 0, sizeof(packet));

    Ethernet* eth = (Ethernet*)packet;
    IPv4* ip = (IPv4*)(packet + sizeof(Ethernet));
    TCP* tcp = (TCP*)(packet + sizeof(Ethernet) + sizeof(IPv4));

    eth->dmac = orgEth->dmac;
    eth->smac = myMac;
    eth->type = htons(0x0800);

    ip->vhl = 0x45;
    ip->len = htons(sizeof(IPv4) + sizeof(TCP));
    ip->id = orgIp->id;
    ip->ttl = orgIp->ttl;
    ip->proto = 6;
    ip->sip = orgIp->sip;
    ip->dip = orgIp->dip;
    ip->sum = 0;
    ip->sum = checksum(ip, sizeof(IPv4));

    tcp->sport = orgTcp->sport;
    tcp->dport = orgTcp->dport;
    tcp->seq = htonl(ntohl(orgTcp->seq) + seqPlus(orgTcp, dataLen));
    tcp->ack = orgTcp->ack;
    tcp->hlen = (sizeof(TCP) / 4) << 4;
    tcp->flags = 0x14;
    tcp->win = 0;
    tcp->sum = 0;
    tcp->sum = tcpChecksum(ip, tcp, nullptr, 0);

    pcap_sendpacket(handle, packet, sizeof(packet));
}

void backwardRst(int raw, IPv4* orgIp, TCP* orgTcp, int dataLen) {
    int packetLen = sizeof(IPv4) + sizeof(TCP);
    uint8_t packet[1500];
    memset(packet, 0, sizeof(packet));

    IPv4* ip = (IPv4*)packet;
    TCP* tcp = (TCP*)(packet + sizeof(IPv4));

    ip->vhl = 0x45;
    ip->len = htons(packetLen);
    ip->id = orgIp->id;
    ip->ttl = 128;
    ip->proto = 6;
    ip->sip = orgIp->dip;
    ip->dip = orgIp->sip;
    ip->sum = 0;
    ip->sum = checksum(ip, sizeof(IPv4));

    tcp->sport = orgTcp->dport;
    tcp->dport = orgTcp->sport;
    tcp->seq = orgTcp->ack;
    tcp->ack = htonl(ntohl(orgTcp->seq) + seqPlus(orgTcp, dataLen));
    tcp->hlen = (sizeof(TCP) / 4) << 4;
    tcp->flags = 0x14;
    tcp->win = 0;
    tcp->sum = 0;
    tcp->sum = tcpChecksum(ip, tcp, nullptr, 0);

    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = ip->dip;

    sendto(raw, packet, packetLen, 0, (sockaddr*)&addr, sizeof(addr));
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        usage();
        return 1;
    }

    char* dev = argv[1];
    char* serverName = argv[2];

    if (!getMyMac(dev)) {
        printf("get my mac error\n");
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        printf("pcap_open_live error %s\n", errbuf);
        return 1;
    }

    int raw = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    int one = 1;
    setsockopt(raw, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    while (true) {
        pcap_pkthdr* header;
        const uint8_t* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res < 0) break;

        if (header->caplen < sizeof(Ethernet) + sizeof(IPv4) + sizeof(TCP)) continue;

        Ethernet* eth = (Ethernet*)packet;
        if (ntohs(eth->type) != 0x0800) continue;

        IPv4* ip = (IPv4*)(packet + sizeof(Ethernet));
        int ipLen = (ip->vhl & 0x0f) * 4;
        if ((ip->vhl >> 4) != 4) continue;
        if (ip->proto != 6) continue;
        if (header->caplen < sizeof(Ethernet) + ipLen + sizeof(TCP)) continue;

        TCP* tcp = (TCP*)((uint8_t*)ip + ipLen);
        int tcpLen = (tcp->hlen >> 4) * 4;
        if (tcpLen < (int)sizeof(TCP)) continue;
        if (ntohs(tcp->dport) != 443) continue;

        int ipTotalLen = ntohs(ip->len);
        int dataLen = ipTotalLen - ipLen - tcpLen;
        if (dataLen <= 0) continue;
        if (header->caplen < sizeof(Ethernet) + ipLen + tcpLen + dataLen) continue;

        uint8_t* data = (uint8_t*)tcp + tcpLen;

        Buf* buf = getBuf(ip, tcp);
        if (buf == nullptr) continue;

        if (buf->len == 0 && data[0] != 0x16) {
            clearBuf(buf);
            continue;
        }

        if (dataLen > (int)sizeof(buf->data) - buf->len) {
            clearBuf(buf);
            continue;
        }

        memcpy(buf->data + buf->len, data, dataLen);
        buf->len += dataLen;

        char sni[256];
        memset(sni, 0, sizeof(sni));
        if (!getSni(buf->data, buf->len, sni, sizeof(sni))) continue;

        printf("sni=%s\n", sni);
        if (strcmp(sni, serverName) != 0) {
            clearBuf(buf);
            continue;
        }

        printf("blocked\n");
        fflush(stdout);
        forwardRst(handle, eth, ip, tcp, dataLen);
        backwardRst(raw, ip, tcp, dataLen);
        clearBuf(buf);
    }

    close(raw);
    pcap_close(handle);
    return 0;
}
