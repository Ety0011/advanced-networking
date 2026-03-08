#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <errno.h>

// --- Constants
#define DNS_PORT        53
#define MAX_PACKET_SIZE 65536
#define MAX_NAME_LEN    256
#define MAX_TXT_LEN     512

#define DNS_FLAG_RD     0x0100  // Recursion enabled

// DNS compression pointer mask
// if the two highest bits of a label length byte are set, it indicates a pointer to another location in the packet
#define DNS_POINTER_MASK 0xC0

// DNS Record Types
#define T_A     1U
#define T_NS    2U
#define T_CNAME 5U
#define T_MX    15U
#define T_TXT   16U
#define T_AAAA  28U
#define T_SOA   6U

// --- DNS Packet Structures

// Fixed 12-byte DNS header, present in both queries and responses.
typedef struct {
    uint16_t id;         // Transaction ID
    uint16_t flags;      // Flags (QR, opcode, AA, TC, RD, RA, Z, RCODE)
    uint16_t qd_count;   // Number of questions
    uint16_t an_count;   // Number of answer RRs
    uint16_t ns_count;   // Number of authority RRs
    uint16_t ar_count;   // Number of additional RRs
} __attribute__((packed)) DnsHeader;

// Trailing fixed fields of a DNS question entry (follows the encoded QNAME).
typedef struct {
    uint16_t qtype;   // Query type  (e.g. T_A, T_MX ...)
    uint16_t qclass;  // Query class (always 1 = IN for Internet)
} __attribute__((packed)) DnsQuestion;

// Fixed fields present at the start of every DNS resource record RDATA section
typedef struct {
    uint16_t type;      // Record type
    uint16_t class;     // Record class
    uint32_t ttl;       // Time to live (seconds)
    uint16_t data_len;  // Length of the RDATA field that follows
} __attribute__((packed)) DnsRRFields;

// --- Configuration

typedef struct {
    char resolver_ip[16];
    uint8_t retries;
    uint8_t timeout;
    char query_name[MAX_NAME_LEN];
    uint16_t qtype;
    char qtype_str[10];
} Config;

// --- Utility functions

static uint16_t get_type_id(const char* type) {
    if (strcmp(type, "A") == 0) return T_A;
    if (strcmp(type, "AAAA") == 0) return T_AAAA;
    if (strcmp(type, "MX") == 0) return T_MX;
    if (strcmp(type, "CNAME") == 0) return T_CNAME;
    if (strcmp(type, "NS") == 0) return T_NS;
    if (strcmp(type, "TXT") == 0) return T_TXT;
    if (strcmp(type, "SOA") == 0) return T_SOA;
    return 0;
}

static const char* get_type_str(uint16_t type) {
    switch (type) {
        case T_A: return "A";
        case T_AAAA: return "AAAA";
        case T_MX: return "MX";
        case T_CNAME: return "CNAME";
        case T_NS: return "NS";
        case T_TXT: return "TXT";
        case T_SOA: return "SOA";
        default: return "UNKNOWN";
    }
}

// Encodes a dotted domain name into the DNS wire format
static void encode_domain_name(unsigned char* out, const char* hostname) {
    int label_len_pos = 0; // Position where we will write the current label length
    int write_pos = 1; // Start one byte ahead to leave room for the first length byte
    int read_pos = 0;

    while (hostname[read_pos] != '\0') {
        if (hostname[read_pos] == '.') {
            // Write the length of the label we just finished
            out[label_len_pos] = (write_pos - label_len_pos) - 1;
            label_len_pos = write_pos;
            write_pos++;
        } else {
            out[write_pos++] = hostname[read_pos];
        }
        read_pos++;
    }

    // Write the length of the final label and terminate
    out[label_len_pos] = (write_pos - label_len_pos) - 1;
    out[write_pos] = 0;
}

// Decodes a DNS name into dotted
static int decode_domain_name(const unsigned char* buffer, int offset, char* out) {
    int pos = offset;
    int jumped = 0;
    int original_bytes_used = 0;

    out[0] = '\0';

    while (buffer[pos] != 0) {
        if ((buffer[pos] & DNS_POINTER_MASK) == DNS_POINTER_MASK) {
            // Compression pointer: upper 2 bits are set
            if (!jumped) {
                // Record where we leave the original stream (pointer occupies 2 bytes)
                original_bytes_used = (pos - offset) + 2;
            }
            jumped = 1;

            int target = ((buffer[pos] & ~DNS_POINTER_MASK) << 8) | buffer[pos + 1];
            pos = target;
        } else {
            // Normal label: first byte is the label length
            int label_len = buffer[pos++];
            strncat(out, (const char*)&buffer[pos], label_len);
            strcat(out, ".");
            pos += label_len;
        }
    }

    if (!jumped) {
        // No pointer was followed, consumed everything up to and including the final '\0'
        original_bytes_used = (pos - offset) + 1;
    }

    return original_bytes_used;
}

// Fills the buffer with a DNS query packet and returns the total packet length
static int build_query(unsigned char* buffer, const Config* cfg) {
    memset(buffer, 0, MAX_PACKET_SIZE);

    // Header
    DnsHeader* hdr = (DnsHeader*)buffer;
    hdr->id = htons((uint16_t)getpid());
    hdr->flags = htons(DNS_FLAG_RD);
    hdr->qd_count = htons(1);

    // Question
    unsigned char* qname = buffer + sizeof(DnsHeader);
    encode_domain_name(qname, cfg->query_name);

    int qname_len = (int)strlen((const char*)qname) + 1; // +1 for the '\0'

    DnsQuestion* qinfo = (DnsQuestion*)(buffer + sizeof(DnsHeader) + qname_len);
    qinfo->qtype  = htons((uint16_t)cfg->qtype);
    qinfo->qclass = htons(1); // IN

    return sizeof(DnsHeader) + qname_len + sizeof(DnsQuestion);
}

// Parses and prints a single DNS resource record starting at offset. Returns the new offset
static int print_record(const unsigned char* buffer, int offset) {
    char name[MAX_NAME_LEN];

    // Owner name
    offset += decode_domain_name(buffer, offset, name);

    // Fixed RR fields
    const DnsRRFields* rr = (const DnsRRFields*)(buffer + offset);
    uint16_t type = ntohs(rr->type);
    uint32_t ttl = ntohl(rr->ttl);
    uint16_t data_len = ntohs(rr->data_len);
    offset += sizeof(DnsRRFields);

    printf("%s\t%u\tIN\t%s\t", name, ttl, get_type_str(type));

    switch (type) {
        case T_A: {
            struct in_addr addr;
            memcpy(&addr, buffer + offset, sizeof(addr));
            printf("%s\n", inet_ntoa(addr));
            break;
        }
        case T_AAAA: {
            char ipv6[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, buffer + offset, ipv6, sizeof(ipv6));
            printf("%s\n", ipv6);
            break;
        }
        case T_CNAME:
        case T_NS: {
            char rname[MAX_NAME_LEN];
            decode_domain_name(buffer, offset, rname);
            printf("%s\n", rname);
            break;
        }
        case T_MX: {
            uint16_t preference = ntohs(*(const uint16_t*)(buffer + offset));
            char mname[MAX_NAME_LEN];
            decode_domain_name(buffer, offset + 2, mname);
            printf("%u\t%s\n", preference, mname);
            break;
        }
        case T_TXT: {
            // First byte is the string length
            int txt_len = buffer[offset];
            char txt[MAX_TXT_LEN];
            memset(txt, 0, sizeof(txt));
            strncpy(txt, (const char*)(buffer + offset + 1), txt_len);
            printf("%s\n", txt);
            break;
        }
        case T_SOA: {
            char mname[MAX_NAME_LEN], rname[MAX_NAME_LEN];
            int bytes = decode_domain_name(buffer, offset, mname);
            bytes += decode_domain_name(buffer, offset + bytes, rname);

            // After the two names: serial, refresh, retry, expire, minimum (5 x uint32)
            const uint32_t *nums = (const uint32_t *)(buffer + offset + bytes);
            printf("%s %s %u %u %u %u %u\n",
                mname, rname,
                ntohl(nums[0]),  // serial
                ntohl(nums[1]),  // refresh
                ntohl(nums[2]),  // retry
                ntohl(nums[3]),  // expire
                ntohl(nums[4])); // minimum TTL
            break;
        }
        default:
            printf("Unknown record type\n");
            break;
    }

    return offset + data_len;
}

// Parse and print one DNS section (answer, authority or additional)
// Returns the updated offset
static int print_section(const unsigned char* buffer, int offset, int count, const char* section_name) {
    if (count <= 0)
        return offset;

    printf("%s SECTION:\n", section_name);
    for (int i = 0; i < count; i++) {
        offset = print_record(buffer, offset);
    }
    printf("\n");

    return offset;
}

// --- Argument parsing
static void print_help(const char* prog) {
    fprintf(stderr, "Usage: %s [options] <query> [TYPE]\n\n", prog);
    fprintf(stderr, "Arguments:\n");
    fprintf(stderr, "  <query>   The DNS query to solve\n");
    fprintf(stderr, "  [TYPE]    The DNS record type for the query. Supported values are: A, AAAA, MX, CNAME, NS, TXT (default: A)\n\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "-s <server>, --server <server>\n\t\tThe IPv4 address of the DNS resolver (default: 127.0.0.53)\n");
    fprintf(stderr, "-r <retries>, --retries <retries>\n\t\tThe maximum number of retries before declaring failure (default: 3)\n");
    fprintf(stderr, "-t <timeout>, --timeout <timeout>\n\t\tThe timeout for receiving the DNS reply in seconds (default: 1)\n");
    fprintf(stderr, "-h, --help\n\t\tDisplay this help and exit\n");
}

// Returns 0 on success, 1 on help, 2 on error.
static int parse_args(int argc, char* argv[], Config* cfg) {
    // Defaults
    strcpy(cfg->resolver_ip, "127.0.0.53");
    cfg->retries = 3;
    cfg->timeout = 1;

    int i = 1;
    while (i < argc && argv[i][0] == '-') {
        if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--server") == 0) {
            strncpy(cfg->resolver_ip, argv[++i], 15);
        } else if (strcmp(argv[i], "-r") == 0 || strcmp(argv[i], "--retries") == 0) {
            cfg->retries = (uint8_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--timeout") == 0) {
            cfg->timeout = (uint8_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_help(argv[0]);
            return 1;
        } else {
            fprintf(stderr, "Error: Unknown option '%s'\n", argv[i]);
            print_help(argv[0]);
            return 2;
        }
        i++;
    }

    if (i >= argc) {
        fprintf(stderr, "Error: Missing query.\n");
        print_help(argv[0]);
        return 2;
    }

    strncpy(cfg->query_name, argv[i++], MAX_NAME_LEN - 1);

    if (i < argc)
        strncpy(cfg->qtype_str, argv[i], sizeof(cfg->qtype_str) - 1);
    else
        strcpy(cfg->qtype_str, "A");

    cfg->qtype = get_type_id(cfg->qtype_str);
    if (cfg->qtype == 0) {
        fprintf(stderr, "Error: Unsupported record type '%s'\n", cfg->qtype_str);
        return 2;
    }

    return 0;
}

// --- Network helpers

// Creates and configures a UDP socket pointing at the resolver in cfg.
// Returns the socket fd on success, or -1 on failure.
static int open_udp_socket(const Config* cfg, struct sockaddr_in* server_addr) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }

    // Set receive timeout
    struct timeval tv = { .tv_sec = cfg->timeout, .tv_usec = 0 };
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    memset(server_addr, 0, sizeof(*server_addr));
    server_addr->sin_family = AF_INET;
    server_addr->sin_port = htons(DNS_PORT);
    server_addr->sin_addr.s_addr = inet_addr(cfg->resolver_ip);

    return sockfd;
}

// Sends the query and waits for a response. retry on timeout.
// Returns the number of bytes received or -1 on failure.
static int send_and_receive(int sockfd, struct sockaddr_in* server_addr, unsigned char* buffer, int query_len, uint8_t retries) {
    socklen_t addr_len = sizeof(*server_addr);

    for (uint8_t attempt = 0; attempt <= retries; attempt++) {
        if (sendto(sockfd, buffer, query_len, 0, (struct sockaddr*)server_addr, sizeof(*server_addr)) < 0) {
            perror("sendto");
            return -1;
        }

        int received = recvfrom(sockfd, buffer, MAX_PACKET_SIZE, 0, (struct sockaddr*)server_addr, &addr_len);
        if (received > 0)
            return received;
    }

    return -1;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_help(argv[0]);
        return 1;
    }

    Config cfg;
    int parse_result = parse_args(argc, argv, &cfg);
    if (parse_result != 0) 
        return (parse_result == 1) ? 0 : 1;

    // Open socket and send query
    struct sockaddr_in server_addr;
    int sockfd = open_udp_socket(&cfg, &server_addr);
    if (sockfd < 0) return 1;

    unsigned char buffer[MAX_PACKET_SIZE];
    int query_len = build_query(buffer, &cfg);
    int received  = send_and_receive(sockfd, &server_addr, buffer, query_len, cfg.retries);
    close(sockfd);

    if (received < 0) {
        fprintf(stderr, "Error: No response after %u retries (timeout: %u s).\n", cfg.retries, cfg.timeout);
        return 1;
    }

    // Parse and print the response
    const DnsHeader* hdr = (const DnsHeader*)buffer;
    int qd = ntohs(hdr->qd_count);
    int an = ntohs(hdr->an_count);
    int ns = ntohs(hdr->ns_count);
    int ar = ntohs(hdr->ar_count);

    printf("QUERY: %d, ANSWER: %d, AUTHORITY: %d, ADDITIONAL: %d\n\n", qd, an, ns, ar);

    int offset = sizeof(DnsHeader);

    // Question section
    if (qd > 0) {
        printf("QUESTION SECTION:\n");
        for (int i = 0; i < qd; i++) {
            char name[MAX_NAME_LEN];
            offset += decode_domain_name(buffer, offset, name);

            uint16_t qtype = ntohs(*(const uint16_t*)(buffer + offset));
            offset += 4; // qtype (2) + qclass (2)

            printf("%-20s\tIN\t%s\n", name, get_type_str(qtype));
        }
        printf("\n");
    }

    // Answer / Authority / Additional sections
    offset = print_section(buffer, offset, an, "ANSWER");
    offset = print_section(buffer, offset, ns, "AUTHORITY");
    offset = print_section(buffer, offset, ar, "ADDITIONAL");

    return 0;
}