
#include <arpa/inet.h>  //inet_addr , inet_ntoa , ntohs etc
#include <netinet/in.h>
#include <stdio.h>   //printf
#include <string.h>  //strlen
#include <sys/socket.h>
#include <unistd.h>  //getpid

#include "Poco//Net/DNSResolver.h"

#ifdef DEBUG_BUILD
#define DEBUG(...) fprintf(stderr, __VA_ARGS__)
#else
#define DEBUG(...)
#endif

namespace {
bool check_ipv4(const std::string& host) {
    unsigned char ip_address[sizeof(struct in6_addr)];
    return inet_pton(AF_INET, host.c_str(), ip_address) > 0;
}
/*
 * Get the DNS servers from /etc/resolv.conf file on Linux
 * */
std::string get_dns_servers() {
    std::string dns_server;
    FILE*       fp;
    char        line[200], *p;
    if ((fp = fopen("/etc/resolv.conf", "r")) == NULL) {
        DEBUG("Failed opening /etc/resolv.conf file \n");
    }

    while (fgets(line, 200, fp)) {
        if (line[0] == '#') {
            continue;
        }
        if (strncmp(line, "nameserver", 10) == 0) {
            p = strtok(line, " ");
            p = strtok(NULL, " ");
            DEBUG("Nameserver=%s", p);
            dns_server = p;
        }
    }
    if (dns_server.empty()) {
        dns_server = "208.67.222.222";
    }

    return dns_server;
}

void ChangetoDnsNameFormat(unsigned char* dns, std::string host) {
    size_t lock = 0, i;
    host.push_back('.');

    for (i = 0; i < host.size(); i++) {
        if (host[i] == '.') {
            *dns++ = i - lock;
            for (; lock < i; lock++) {
                *dns++ = host[lock];
            }
            lock++;  // or lock=i+1;
        }
    }
    *dns++ = '\0';
}

std::string ReadName(unsigned char* reader, unsigned char* buffer, int* count) {
    std::string name;
    name.reserve(256);
    unsigned int p = 0, jumped = 0, offset;
    size_t       i, j;

    *count = 1;

    // read the names in 3www6google3com format
    while (*reader != 0) {
        if (*reader >= 192) {
            offset = (*reader) * 256 + *(reader + 1) - 49152;  // 49152 = 11000000 00000000 ;)
            reader = buffer + offset - 1;
            jumped = 1;  // we have jumped to another location so counting wont go up!
        } else {
            name.push_back(*reader);
        }

        reader = reader + 1;

        if (jumped == 0) {
            *count = *count + 1;  // if we havent jumped to another location then we can count up
        }
    }

    if (jumped == 1) {
        *count = *count + 1;  // number of steps we actually moved forward in the packet
    }

    // now convert 3www6google3com0 to www.google.com
    for (i = 0; i < name.size(); i++) {
        p = name[i];
        for (j = 0; j < (size_t)p; j++) {
            name[i] = name[i + 1];
            i       = i + 1;
        }
        name[i] = '.';
    }
    name.pop_back();
    return name;
}

}  // namespace

namespace Poco::Net {
// DNS header structure
struct DNS_HEADER {
    unsigned short id;  // identification number

    unsigned char rd : 1;      // recursion desired
    unsigned char tc : 1;      // truncated message
    unsigned char aa : 1;      // authoritive answer
    unsigned char opcode : 4;  // purpose of message
    unsigned char qr : 1;      // query/response flag

    unsigned char rcode : 4;  // response code
    unsigned char cd : 1;     // checking disabled
    unsigned char ad : 1;     // authenticated data
    unsigned char z : 1;      // its z! reserved
    unsigned char ra : 1;     // recursion available

    unsigned short q_count;     // number of question entries
    unsigned short ans_count;   // number of answer entries
    unsigned short auth_count;  // number of authority entries
    unsigned short add_count;   // number of resource entries
};

// Constant sized fields of query structure
struct QUESTION {
    uint16_t qtype;
    uint16_t qclass;
};

// Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct R_DATA {
    unsigned short type;
    unsigned short _class;
    unsigned int   ttl;
    unsigned short data_len;
};
#pragma pack(pop)

// Pointers to resource record contents
struct RES_RECORD {
    struct R_DATA* resource;
    std::string    name;
    std::string    rdata;
};

// Structure of a Query
typedef struct {
    unsigned char*   name;
    struct QUESTION* ques;
} QUERY;

/*
 * Perform a DNS query by sending a packet
 * */
DNSResolveResult resolve_dns(const std::string& host, DNSRecords query_type, size_t timeout_sec, size_t timeout_micro) {
    DNSResolveResult result;
    if (check_ipv4(host)) {
        result.ipv4 = {host};
        return result;
    }
    static std::string dns_server = get_dns_servers();

    unsigned char buf[65536], *qname, *reader;
    int           i, j, stop, s;

    struct sockaddr_in a;

    struct RES_RECORD  answers[20], auth[20], addit[20];  // the replies from the DNS server
    struct sockaddr_in dest;

    struct DNS_HEADER* dns   = NULL;
    struct QUESTION*   qinfo = NULL;

    DEBUG("Resolving %s", host.c_str());

    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);  // UDP packet for DNS queries
    struct timeval timeout;
    timeout.tv_sec  = timeout_sec;
    timeout.tv_usec = timeout_micro;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    dest.sin_family      = AF_INET;
    dest.sin_port        = htons(53);
    dest.sin_addr.s_addr = inet_addr(dns_server.c_str());  // dns servers

    // Set the DNS structure to standard queries
    dns = (struct DNS_HEADER*)&buf;

    dns->id         = (unsigned short)htons(getpid());
    dns->qr         = 0;  // This is a query
    dns->opcode     = 0;  // This is a standard query
    dns->aa         = 0;  // Not Authoritative
    dns->tc         = 0;  // This message is not truncated
    dns->rd         = 1;  // Recursion Desired
    dns->ra         = 0;  // Recursion not available! hey we dont have it (lol)
    dns->z          = 0;
    dns->ad         = 0;
    dns->cd         = 0;
    dns->rcode      = 0;
    dns->q_count    = htons(1);  // we have only 1 question
    dns->ans_count  = 0;
    dns->auth_count = 0;
    dns->add_count  = 0;

    // point to the query portion
    qname = (unsigned char*)&buf[sizeof(struct DNS_HEADER)];

    ChangetoDnsNameFormat(qname, host);
    qinfo = (struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)];  // fill it

    qinfo->qtype  = (size_t)htons(static_cast<uint16_t>(query_type));  // type of the query , A , MX , CNAME , NS etc
    qinfo->qclass = (size_t)htons(1);                                  // its internet (lol)

    DEBUG("\nSending Packet...");
    if (sendto(s, (char*)buf, sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1) + sizeof(struct QUESTION), 0,
               (struct sockaddr*)&dest, sizeof(dest)) < 0) {
        perror("sendto failed");
    }
    DEBUG("Done");

    // Receive the answer
    i = sizeof dest;
    DEBUG("\nReceiving answer...");
    if (recvfrom(s, (char*)buf, 65536, 0, (struct sockaddr*)&dest, (socklen_t*)&i) < 0) {
        perror("recvfrom failed");
    }
    DEBUG("Done");

    dns = (struct DNS_HEADER*)buf;

    // move ahead of the dns header and the query field
    reader = &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1) + sizeof(struct QUESTION)];

    DEBUG("\nThe response contains : ");
    DEBUG("\n %d Questions.", ntohs(dns->q_count));
    DEBUG("\n %d Answers.", ntohs(dns->ans_count));
    DEBUG("\n %d Authoritative Servers.", ntohs(dns->auth_count));
    DEBUG("\n %d Additional records.\n\n", ntohs(dns->add_count));

    // Start reading answers
    stop = 0;

    for (i = 0; i < ntohs(dns->ans_count); i++) {
        answers[i].name = ReadName(reader, buf, &stop);
        reader          = reader + stop;

        answers[i].resource = (struct R_DATA*)(reader);
        reader              = reader + sizeof(struct R_DATA);

        if (ntohs(answers[i].resource->type) == 1)  // if its an ipv4 address
        {
            answers[i].rdata = std::string(static_cast<size_t>(ntohs(answers[i].resource->data_len)), ' ');

            for (j = 0; j < ntohs(answers[i].resource->data_len); j++) {
                answers[i].rdata[j] = reader[j];
            }

            answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';

            reader = reader + ntohs(answers[i].resource->data_len);
        } else {
            answers[i].rdata = ReadName(reader, buf, &stop);
            reader           = reader + stop;
        }
    }

    // read authorities
    for (i = 0; i < ntohs(dns->auth_count); i++) {
        auth[i].name = ReadName(reader, buf, &stop);
        reader += stop;

        auth[i].resource = (struct R_DATA*)(reader);
        reader += sizeof(struct R_DATA);

        auth[i].rdata = ReadName(reader, buf, &stop);
        reader += stop;
    }

    // read additional
    for (i = 0; i < ntohs(dns->add_count); i++) {
        addit[i].name = ReadName(reader, buf, &stop);
        reader += stop;

        addit[i].resource = (struct R_DATA*)(reader);
        reader += sizeof(struct R_DATA);

        if (ntohs(addit[i].resource->type) == 1) {
            addit[i].rdata = std::string(static_cast<size_t>(ntohs(addit[i].resource->data_len)), ' ');
            for (j = 0; j < ntohs(addit[i].resource->data_len); j++)
                addit[i].rdata[j] = reader[j];

            addit[i].rdata[ntohs(addit[i].resource->data_len)] = '\0';
            reader += ntohs(addit[i].resource->data_len);
        } else {
            addit[i].rdata = ReadName(reader, buf, &stop);
            reader += stop;
        }
    }

    // print answers
    DEBUG("\nAnswer Records : %d \n", ntohs(dns->ans_count));
    result.ipv4.reserve(ntohs(dns->ans_count));

    for (i = 0; i < ntohs(dns->ans_count); i++) {
        DEBUG("Name : %s ", answers[i].name.c_str());

        if (static_cast<DNSRecords>(ntohs(answers[i].resource->type)) == DNSRecords::T_A)  // IPv4 address
        {
            long* p;
            p                 = (long*)answers[i].rdata.c_str();
            a.sin_addr.s_addr = (*p);  // working without ntohl
            DEBUG("has IPv4 address : %s", inet_ntoa(a.sin_addr));
            result.ipv4.push_back(inet_ntoa(a.sin_addr));
        }

        if (ntohs(answers[i].resource->type) == 5) {
            // Canonical name for an alias
            DEBUG("has alias name : %s", answers[i].rdata.c_str());
            result.ipv4_aliases.push_back(answers[i].rdata);
        }

        DEBUG("\n");
    }
#ifdef ADDITIONAL_DNS_RESULTS
    // print authorities
    DEBUG("\nAuthoritive Records : %d \n", ntohs(dns->auth_count));
    for (i = 0; i < ntohs(dns->auth_count); i++) {
        DEBUG("Name : %s ", auth[i].name.c_str());
        if (ntohs(auth[i].resource->type) == 2) {
            DEBUG("has nameserver : %s", auth[i].rdata.c_str());
        }
        DEBUG("\n");
    }

    // print additional resource records
    DEBUG("\nAdditional Records : %d \n", ntohs(dns->add_count));
    for (i = 0; i < ntohs(dns->add_count); i++) {
        DEBUG("Name : %s ", addit[i].name.c_str());
        if (ntohs(addit[i].resource->type) == 1) {
            long* p;
            p                 = (long*)addit[i].rdata.c_str();
            a.sin_addr.s_addr = (*p);
            DEBUG("has IPv4 address : %s", inet_ntoa(a.sin_addr));
        }
        DEBUG("\n");
    }
#endif

    return result;
}

}  // namespace Poco::Net
