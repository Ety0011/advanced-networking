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
#define DNS_MAX_MESSAGE_SIZE 512 // RFC 1035: max DNS message size over UDP
#define DNS_MAX_RECORD_COUNT 50  // DNS_MAX_MESSAGE_SIZE / 12 approx = 43 -> 50
#define DNS_MAX_NAME_SIZE                                                      \
  256 // RFC 1035: max domain name length is 255 + null terminator
#define DNS_PTR_MASK                                                           \
  0xC0 // top 2 bits set, signals this is a compression pointer not a label
       // length
#define DNS_TYPE_A 1
#define DNS_TYPE_NS 2
#define DNS_TYPE_CNAME 5
#define DNS_TYPE_MX 15
#define DNS_TYPE_TXT 16
#define DNS_TYPE_AAAA 28
#define DNS_CLASS_IN 1

typedef struct {
  char *server_addr;
  int retries;
  int timeout;
  char *qname;
  char *qtype;
} dns_args;

typedef struct {
  uint16_t id;      // unique identifier to match responses to requests
  uint16_t flags;   // QR, opcode, AA, TC, RD, RA, Z, RCODE packed into 16 bits
  uint16_t qdcount; // number of questions
  uint16_t ancount; // number of answer records
  uint16_t nscount; // number of authority (name server) records
  uint16_t arcount; // number of additional records
} __attribute__((packed)) dns_header; // remove compiler padding

typedef struct {
  char qname[DNS_MAX_NAME_SIZE];
  uint16_t qtype;
  uint16_t qclass;
} __attribute__((packed)) dns_question;

typedef struct {
  char name[DNS_MAX_NAME_SIZE];
  uint16_t type;
  uint16_t class;
  uint32_t ttl;
  uint16_t rdlength;
  char rdata[DNS_MAX_MESSAGE_SIZE];
} dns_record;

typedef struct {
  dns_header header;
  dns_question question;
  dns_record answers[DNS_MAX_RECORD_COUNT];
  dns_record authority[DNS_MAX_RECORD_COUNT];
  dns_record additional[DNS_MAX_RECORD_COUNT];
} dns_message;

void print_usage();
bool parse_int(const char *value, int *out);
int parse_command_line(int argc, char *argv[], dns_args *args);
int encode_name(const char *qname, uint8_t *buf);
uint16_t str_to_type(const char *type);
int build_request(const char *qname, const char *qtype, uint8_t *packet);
int send_request(uint8_t *request, int request_len, dns_args *args,
                 uint8_t response[]);
dns_message parse_response(uint8_t *response, int response_len);
void print_message(dns_message *message);

int main(int argc, char *argv[]) {
  dns_args args = {0};
  if (parse_command_line(argc, argv, &args) == FAILURE) {
    return EXIT_FAILURE;
  }

  uint8_t request[DNS_MAX_MESSAGE_SIZE];
  int request_len = build_request(args.qname, args.qtype, request);

  uint8_t response[DNS_MAX_MESSAGE_SIZE];
  int response_len = send_request(request, request_len, &args, response);
  if (response_len == FAILURE) {
    fprintf(stderr, "Error: could not send request\n");
    return EXIT_FAILURE;
  }

  dns_message message = parse_response(response, response_len);

  print_message(&message);

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

int encode_name(const char *qname, uint8_t *request) {
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

int decode_name(uint8_t *response, int offset, char *out) {
  int start_offset = offset;

  while (response[offset] != '\0') {
    if ((response[offset] & DNS_PTR_MASK) == DNS_PTR_MASK) {
      int jump = ((response[offset] & 0x3F) << 8) | response[offset + 1];
      decode_name(response, jump, out);
      offset += 2;
      return offset - start_offset;
    }

    int len = response[offset++];
    for (int i = 0; i < len; i++) {
      *out++ = response[offset++];
    }
    *out++ = '.';
  }

  *out = '\0';
  offset++; // skip the \0 terminator
  return offset - start_offset;
}

uint16_t str_to_type(const char *type) {
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

char *type_to_str(uint16_t type) {
  char *result;
  switch (type) {
  case DNS_TYPE_A:
    result = "A";
    break;
  case DNS_TYPE_NS:
    result = "NS";
    break;
  case DNS_TYPE_CNAME:
    result = "CNAME";
    break;
  case DNS_TYPE_MX:
    result = "MX";
    break;
  case DNS_TYPE_TXT:
    result = "TXT";
    break;
  case DNS_TYPE_AAAA:
    result = "AAAA";
    break;
  default:
    result = "A";
    break;
  }
  return result;
}

char *class_to_str(uint16_t class) {
  char *result;
  switch (class) {
  case 1:
    result = "IN";
    break;
  default:
    result = "UNKNOWN";
    break;
  }
  return result;
}

int build_request(const char *qname, const char *qtype, uint8_t *request) {
  uint8_t *start = request;

  dns_header header = {.id = htons(rand() % UINT16_MAX + 1),
                       .flags = htons(0x0100), // literally just set recursion
                       .qdcount = htons(1),
                       .ancount = htons(0),
                       .nscount = htons(0),
                       .arcount = htons(0)};
  memcpy(request, &header, sizeof(dns_header));
  request += sizeof(dns_header);

  int encoded_len = encode_name(qname, request);
  request += encoded_len;
  // direct cast avoids the temp variable that memcpy would require
  *((uint16_t *)request) = htons(str_to_type(qtype));
  request += 2;
  *((uint16_t *)request) = htons(DNS_CLASS_IN);
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

    response_len = recvfrom(sock_fd, response, DNS_MAX_MESSAGE_SIZE, 0,
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
  int decoded = decode_name(response, offset, question->qname);
  offset += decoded;

  question->qtype = ntohs(*((uint16_t *)(response + offset)));
  offset += 2;

  question->qclass = ntohs(*((uint16_t *)(response + offset)));
  offset += 2;

  return offset - original_offset;
}

int parse_record(uint8_t *response, int offset, dns_record *record) {
  int original_offset = offset;
  int decoded = decode_name(response, offset, record->name);
  offset += decoded;

  record->type = ntohs(*((uint16_t *)(response + offset)));
  offset += 2;

  record->class = ntohs(*((uint16_t *)(response + offset)));
  offset += 2;

  record->ttl = ntohl(*((uint32_t *)(response + offset)));
  offset += 4;

  record->rdlength = ntohs(*((uint16_t *)(response + offset)));
  offset += 2;

  switch (record->type) {
  case DNS_TYPE_A:
    inet_ntop(AF_INET, response + offset, record->rdata, sizeof(record->rdata));
    break;
  case DNS_TYPE_NS:
    decode_name(response, offset, record->rdata);
    break;
  case DNS_TYPE_CNAME:
    decode_name(response, offset, record->rdata);
    break;
  case DNS_TYPE_MX: { // <- brackets for any case that defines variables
    uint16_t preference = ntohs(*((uint16_t *)(response + offset)));
    int written = sprintf(record->rdata, "%d\t", preference);
    decode_name(response, offset + 2, record->rdata + written);
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

void print_record(dns_record *record) {
  printf("%s\t%d\t%s\t%s\t%s\n", record->name, record->ttl,
         class_to_str(record->class), type_to_str(record->type), record->rdata);
}

void print_message(dns_message *message) {
  printf("QUERY: %d, ANSWER: %d, AUTHORITY: %d, ADDITIONAL: %d\n\n",
         message->header.qdcount, message->header.ancount,
         message->header.nscount, message->header.arcount);

  if (message->header.qdcount > 0) {
    printf("QUESTION SECTION:\n");
    printf("%s\t\t%s\t%s\n\n", message->question.qname,
           class_to_str(message->question.qclass),
           type_to_str(message->question.qtype));
  }

  if (message->header.ancount > 0) {
    printf("ANSWER SECTION:\n");
    for (int i = 0; i < message->header.ancount; i++) {
      print_record(&message->answers[i]);
    }
  }

  if (message->header.nscount > 0) {
    printf("AUTHORITY SECTION:\n");
    for (int i = 0; i < message->header.nscount; i++) {
      print_record(&message->authority[i]);
    }
  }

  if (message->header.arcount > 0) {
    printf("ADDITIONAL SECTION:\n");
    for (int i = 0; i < message->header.arcount; i++) {
      print_record(&message->additional[i]);
    }
  }
}
