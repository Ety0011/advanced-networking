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

typedef struct {
  char *server;
  int retries;
  int timeout;
  char *query;
  char *type;
} dns_args_t;

typedef struct {
  uint16_t id;
  uint16_t flags;
  uint16_t question_count;
  uint16_t answer_count;
  uint16_t name_server_count;
  uint16_t additional_records_count;
} __attribute__((packed)) dns_header_t;

typedef struct {
  uint16_t qtype;
  uint16_t qclass;
} __attribute__((packed)) dns_question_t;

void print_usage();
bool parse_int(const char *value, int *out);
int parse_command_line(int argc, char *argv[], dns_args_t *args);
int encode_name(const char *domain, uint8_t *buf);
uint16_t type_to_qtype(const char *type);
int build_packet(const char *domain, const char *qtype, uint8_t *packet);
int send_dns_query(uint8_t *packet, int packet_len, const char *server_ip);

int main(int argc, char *argv[]) {
  dns_args_t args = {0};
  if (parse_command_line(argc, argv, &args) == FAILURE) {
    return EXIT_FAILURE;
  }

  uint8_t packet[512]; // standard DNS UDP message size limit
  int packet_len = build_packet(args.query, args.type, packet);

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

int parse_command_line(int argc, char *argv[], dns_args_t *args) {
  int curr = 1;

  // [options]
  args->server = "127.0.0.53";
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
      args->server = value;
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
  args->query = argv[curr++];

  // [TYPE]
  args->type = "A";
  if (curr < argc) {
    char *type = argv[curr];
    if (strcmp(type, "AAAA") == 0) {
      args->type = "AAAA";
    } else if (strcmp(type, "MX") == 0) {
      args->type = "MX";
    } else if (strcmp(type, "CNAME") == 0) {
      args->type = "CNAME";
    } else if (strcmp(type, "NS") == 0) {
      args->type = "NS";
    } else if (strcmp(type, "TXT") == 0) {
      args->type = "TXT";
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

int encode_name(const char *domain, uint8_t *buf) {
  uint8_t *start = buf;
  char *dot;
  int length;
  while (*domain != '\0') {
    dot = strchr(domain, '.');
    if (dot) {
      length = dot - domain;
    } else {
      length = strlen(domain);
    }

    *buf++ = length;
    for (int i = 0; i < length; i++) {
      *buf++ = *domain++;
    }

    if (dot) {
      domain++;
    }
  }

  *buf++ = '\0';

  return buf - start;
}

uint16_t type_to_qtype(const char *type) {
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

int build_packet(const char *domain, const char *qtype, uint8_t *packet) {
  uint8_t *start = packet;

  dns_header_t header = {.id = htons(getpid()),
                         .flags = htons(0x0100), // literally just set recursion
                         .question_count = htons(1),
                         .answer_count = htons(0),
                         .name_server_count = htons(0),
                         .additional_records_count = htons(0)};
  memcpy(packet, &header, sizeof(dns_header_t));
  packet += sizeof(dns_header_t);

  int encoded = encode_name(domain, packet);
  packet += encoded;

  dns_question_t question = {.qtype = htons(type_to_qtype(qtype)),
                             .qclass = htons(1)};
  memcpy(packet, &question, sizeof(dns_question_t));
  packet += sizeof(dns_question_t);

  return packet - start;
}

int send_dns_query(uint8_t *packet, int packet_len, const char *server_ip) {
  int sock = socket(AF_INET, SOCK_DGRAM, 0);

  struct sockaddr_in server;
  server.sin_family = AF_INET;
  server.sin_port = htons(DNS_PORT);
  inet_aton(server_ip, &server.sin_addr);

  sendto(sock, packet, packet_len, 0, (struct sockaddr *)&server,
         sizeof(server));
}
