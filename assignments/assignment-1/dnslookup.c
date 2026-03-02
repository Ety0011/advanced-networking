#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define SUCCESS 0
#define FAILURE -1
#define DNS_PORT 53
#define UDP_MAX_PAYLOAD_SIZE 65507 // 65535 - 8 (UDP header) - 20 (IP header)
#define DNS_MAX_UDP_SIZE 512       // RFC 1035 limit
#define DNS_PTR_MASK                                                           \
  0xC0 // top 2 bits set, signals this is a compression pointer not a label
       // length
#define DNS_TYPE_A 1
#define DNS_TYPE_NS 2
#define DNS_TYPE_CNAME 5
#define DNS_TYPE_MX 15
#define DNS_TYPE_TXT 16
#define DNS_TYPE_AAAA 28
#define MAX_NUM_RECORDS                                                        \
  50 // record is at minimum 12 bytes -> 512 / 12 = 42, we round to 50

typedef struct {
  char *server_addr;
  int retries;
  int timeout;
  char *qname;
  char *qtype;
} dns_args;

typedef struct {
  uint16_t id;
  uint16_t flags;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
} __attribute__((packed)) dns_header;

typedef struct {
  char qname[256];
  uint16_t qtype;
  uint16_t qclass;
} __attribute__((packed)) dns_question;

typedef struct {
  char name[256];
  uint16_t type;
  uint16_t class;
  uint32_t ttl;
  uint16_t rdlength;
  char rdata[512];
} dns_record;

typedef struct {
  dns_header header;
  dns_question question;
  dns_record answers[MAX_NUM_RECORDS];
  dns_record authority[MAX_NUM_RECORDS];
  dns_record additional[MAX_NUM_RECORDS];
} dns_message;

void print_usage();
bool parse_int(const char *value, int *out);
int parse_command_line(int argc, char *argv[], dns_args *args);
int encode_qname(const char *qname, uint8_t *buf);
uint16_t qtype_to_str(const char *type);
int build_request(const char *qname, const char *qtype, uint8_t *packet);
int send_request(uint8_t *request, int request_len, dns_args *args,
                 uint8_t response[]);
dns_message parse_response(uint8_t *response, int response_len);

int main(int argc, char *argv[]) {
  dns_args args = {0};
  if (parse_command_line(argc, argv, &args) == FAILURE) {
    return EXIT_FAILURE;
  }

  uint8_t request[DNS_MAX_UDP_SIZE];
  int request_len = build_request(args.qname, args.qtype, request);

  uint8_t response[UDP_MAX_PAYLOAD_SIZE];
  int response_len = send_request(request, request_len, &args, response);
  if (response_len == FAILURE) {
    fprintf(stderr, "Error: could not send request");
    return EXIT_FAILURE;
  }

  dns_message message = parse_response(response, response_len);
  printf("id: %u", message.header.id);

  return EXIT_SUCCESS;
}

void print_usage() {
  printf(
      "Usage: ./dnslookup [options] <query> [TYPE]\n\n"
      "Arguments:\n"
      "\tquery\tThe DNS query to solve\n"
      "\tTYPE\tThe DNS record type for the query. Supported values are:\n"
      "\t\tA, AAAA, MX, CNAME, NS, TXT (default: A)\n\n"
      "Options:\n"
      "\t-s <server>, --server <server>\n"
      "\t\t\tThe IPv4 address of the DNS resolver (default: 127.0.0.53)\n"
      "\t-r <retries>, --retries <retries>\n"
      "\t\t\tThe maximum number of retries before declaring failure (default: "
      "3)\n"
      "\t-t <timeout>, --timeout <timeout>\n"
      "\t\t\tThe timeout for receiving the DNS reply in seconds (default: 1s)\n"
      "\t-h, --help\n"
      "\t\t\tDisplay this help and exit\n");
}

bool parse_int(const char *value, int *out) {
  char *end;
  int result = (int)strtol(value, &end, 10);
  if (end == value || *end != '\0' || result < 0) {
    return false;
  }
  *out = result;
  return true;
}

int parse_command_line(int argc, char *argv[], dns_args *args) {
  int curr = 1;

  // [options]
  args->server_addr = "127.0.0.53";
  args->retries = 3;
  args->timeout = 1;
  while (curr < argc && argv[curr][0] == '-') {
    char *option = argv[curr];
    int next = curr + 1;
    if (next == argc) {
      fprintf(stderr, "Error: option %s requires a value\n", option);
      return FAILURE;
    }

    bool is_valid = true;
    char *value = argv[next];
    if (strcmp(option, "-s") == 0 || strcmp(option, "--server") == 0) {
      args->server_addr = value;
    } else if (strcmp(option, "-r") == 0 || strcmp(option, "--retries") == 0) {
      is_valid = parse_int(value, &args->retries);
    } else if (strcmp(option, "-t") == 0 || strcmp(option, "--timeout") == 0) {
      is_valid = parse_int(value, &args->timeout);
    } else {
      is_valid = false;
    }

    if (!is_valid) {
      fprintf(stderr, "Error: invalid option %s with value %s\n", option,
              value);
      return FAILURE;
    }
    curr += 2;
  }

  // <query>
  if (curr == argc) {
    fprintf(stderr, "Error: no <query> is provided\n");
    return FAILURE;
  }
  args->qname = argv[curr++];

  // [TYPE]
  args->qtype = "A";
  if (curr < argc) {
    char *type = argv[curr];
    if (strcmp(type, "AAAA") == 0) {
      args->qtype = "AAAA";
    } else if (strcmp(type, "MX") == 0) {
      args->qtype = "MX";
    } else if (strcmp(type, "CNAME") == 0) {
      args->qtype = "CNAME";
    } else if (strcmp(type, "NS") == 0) {
      args->qtype = "NS";
    } else if (strcmp(type, "TXT") == 0) {
      args->qtype = "TXT";
    } else if (strcmp(type, "A") != 0) {
      fprintf(stderr, "Error: invalid TYPE\n");
      return FAILURE;
    }
    curr++;
  }

  if (curr < argc) {
    fprintf(stderr, "Error: too many arguments are provided\n");
    return FAILURE;
  }

  return SUCCESS;
}

int encode_qname(const char *qname, uint8_t *request) {
  uint8_t *start = request;
  char *dot;
  int len;
  while (*qname != '\0') {
    dot = strchr(qname, '.');
    if (dot) {
      len = dot - qname;
    } else {
      len = strlen(qname);
    }

    *request++ = len;
    for (int i = 0; i < len; i++) {
      *request++ = *qname++;
    }

    if (dot) {
      qname++;
    }
  }

  *request++ = '\0';

  return request - start;
}

int decode_qname(uint8_t *response, int offset, char *out) {
  char *start_out = out;

  while (response[offset] != '\0') {
    if ((response[offset] & DNS_PTR_MASK) == DNS_PTR_MASK) {
      int jump = ((response[offset] & 0x3F) << 8) | response[offset + 1];
      int decoded = decode_qname(response, jump, out);
      out += decoded;
      break;
    }

    int len = response[offset++];
    for (int i = 0; i < len; i++) {
      *out++ = response[offset++];
    }
    *out++ = '.';
  }

  *out = '\0';
  return out - start_out + 1;
}

uint16_t qtype_to_str(const char *type) {
  uint16_t result = 1; // defaults to "A"
  if (strcmp(type, "NS") == 0) {
    result = 2;
  } else if (strcmp(type, "CNAME") == 0) {
    result = 5;
  } else if (strcmp(type, "MX") == 0) {
    result = 15;
  } else if (strcmp(type, "TXT") == 0) {
    result = 16;
  } else if (strcmp(type, "AAAA") == 0) {
    result = 28;
  }
  return result;
}

int build_request(const char *qname, const char *qtype, uint8_t *request) {
  uint8_t *start = request;

  dns_header header = {.id = htons(getpid()),
                       .flags = htons(0x0100), // literally just set recursion
                       .qdcount = htons(1),
                       .ancount = htons(0),
                       .nscount = htons(0),
                       .arcount = htons(0)};
  memcpy(request, &header, sizeof(dns_header));
  request += sizeof(dns_header);

  dns_question question;
  int encoded_len = encode_qname(qname, (uint8_t *)question.qname);
  question.qtype = htons(qtype_to_str(qtype));
  question.qclass = htons(1);
  memcpy(request, question.qname, encoded_len);
  request += encoded_len;
  memcpy(request, &question.qtype, 2);
  request += 2;
  memcpy(request, &question.qclass, 2);
  request += 2;

  return request - start;
}

int send_request(uint8_t *request, int request_len, dns_args *args,
                 uint8_t response[]) {
  int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock_fd < 0) {
    perror("socket");
    return FAILURE;
  }

  struct sockaddr_in server_addr;
  int server_addr_len = sizeof(server_addr);
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(DNS_PORT);
  inet_aton(args->server_addr, &server_addr.sin_addr);

  struct sockaddr_in from_addr;
  socklen_t from_addr_len = sizeof(from_addr);

  // set timeout here
  struct timeval time = {.tv_sec = args->timeout, .tv_usec = 0};
  if (setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &time, sizeof(time)) ==
      FAILURE) {
    perror("setsockopt");
    close(sock_fd);
    return FAILURE;
  }

  int response_len = -1;
  int attempts = 0;
  do {
    if (attempts >= args->retries) {
      fprintf(stderr, "Error: timed out after %d retries\n", args->retries);
      close(sock_fd);
      return FAILURE;
    }

    int bytes_sent = sendto(sock_fd, request, request_len, 0,
                            (struct sockaddr *)&server_addr, server_addr_len);
    if (bytes_sent < 0) {
      perror("sendto");
      close(sock_fd);
      return FAILURE;
    }

    response_len = recvfrom(sock_fd, response, UDP_MAX_PAYLOAD_SIZE, 0,
                            (struct sockaddr *)&from_addr, &from_addr_len);
    if (response_len == FAILURE) {
      perror("recvfrom");
    }

    attempts++;
  } while (response_len < 0);

  close(sock_fd);
  return response_len;
}

int parse_header(uint8_t *response, int offset, dns_header *header) {
  memcpy(header, response + offset, sizeof(dns_header));
  header->id = ntohs(header->id);
  header->flags = ntohs(header->flags);
  header->qdcount = ntohs(header->qdcount);
  header->ancount = ntohs(header->ancount);
  header->nscount = ntohs(header->nscount);
  header->arcount = ntohs(header->arcount);
  return sizeof(dns_header);
}

int parse_question(uint8_t *response, int offset, dns_question *question) {
  int original_offset = offset;
  int decoded = decode_qname(response, offset, question->qname);
  offset += decoded;

  memcpy(&question->qtype, response + offset, 2);
  question->qtype = ntohs(question->qtype);
  offset += 2;

  memcpy(&question->qclass, response + offset, 2);
  question->qclass = ntohs(question->qclass);
  offset += 2;

  return offset - original_offset;
}

int parse_record(uint8_t *response, int offset, dns_record *record) {
  int original_offset = offset;
  int decoded = decode_qname(response, offset, record->name);
  offset += decoded;

  memcpy(&record->type, response + offset, 2);
  record->type = ntohs(record->type);
  offset += 2;

  memcpy(&record->class, response + offset, 2);
  record->class = ntohs(record->class);
  offset += 2;

  memcpy(&record->ttl, response + offset, 4);
  record->ttl = ntohl(record->ttl);
  offset += 4;

  memcpy(&record->rdlength, response + offset, 2);
  record->rdlength = ntohs(record->rdlength);
  offset += 2;

  switch (record->type) {
  case DNS_TYPE_A:
    inet_ntop(AF_INET, response + offset, record->rdata, sizeof(record->rdata));
    break;
  case DNS_TYPE_NS:
    decode_qname(response, offset, record->rdata);
    break;
  case DNS_TYPE_CNAME:
    decode_qname(response, offset, record->rdata);
    break;
  case DNS_TYPE_MX: { // <- brackets for any case that defines variables
    uint16_t preference;
    memcpy(&preference, response + offset, 2);
    preference = ntohs(preference);
    int written = sprintf(record->rdata, "%d\t", preference);
    decode_qname(response, offset + 2, record->rdata + written);
    break;
  }
  case DNS_TYPE_TXT: {
    int len = response[offset];
    memcpy(record->rdata, response + offset + 1, len);
    record->rdata[len] = '\0';
    break;
  }
  case DNS_TYPE_AAAA:
    inet_ntop(AF_INET6, response + offset, record->rdata,
              sizeof(record->rdata));
    break;
  default:
    break;
  }
  offset += record->rdlength;

  return offset - original_offset;
}

dns_message parse_response(uint8_t *response, int response_len) {
  dns_message message;
  int offset = 0;

  offset += parse_header(response, offset, &message.header);

  offset += parse_question(response, offset, &message.question);

  for (int i = 0; i < message.header.ancount; i++) {
    offset += parse_record(response, offset, &message.answers[i]);
  }

  for (int i = 0; i < message.header.nscount; i++) {
    offset += parse_record(response, offset, &message.authority[i]);
  }

  for (int i = 0; i < message.header.arcount; i++) {
    offset += parse_record(response, offset, &message.additional[i]);
  }

  return message;
}