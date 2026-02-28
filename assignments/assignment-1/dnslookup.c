#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SUCCESS 0
#define FAILURE -1
#define MIN_NUM_ARGS 1

typedef struct {
  char *server;
  int retries;
  int timeout;
  char *query;
  char *type;
} dns_args_t;

void print_usage();

int main(int argc, char *argv[]) { print_usage(); }

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

int parse_command_line(int argc, char *argv[], dns_args_t *dns) {
  if (argc < MIN_NUM_ARGS + 1) {
    fprintf(stderr, "Error: not enough arguments are provided\n");
    print_usage();
    return FAILURE;
  }

  int curr = 1;

  // [options]
  dns->server = "127.0.0.53";
  dns->retries = 3;
  dns->timeout = 1;
  while (argv[curr][0] == '-' && curr + 1 < argc) {
    char *option = argv[curr];
    char *value = argv[curr + 1];
    bool is_valid = true;
    char *end;
    if (strcmp(option, "-s") == 0 || strcmp(option, "--server") == 0) {
      dns->server = value;
    } else if (strcmp(option, "-r") == 0 || strcmp(option, "--retries") == 0) {
      int retries = (int)strtol(value, &end, 10);
      if (end == value || *end != '\0' || retries < 0) {
        is_valid = false;
      } else {
        dns->retries = retries;
      }
    } else if (strcmp(option, "-t") == 0 || strcmp(option, "--timeout") == 0) {
      int timeout = (int)strtol(value, &end, 10);
      if (end == value || *end != '\0' || timeout < 0) {
        is_valid = false;
      } else {
        dns->timeout = timeout;
      }
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
  dns->query = argv[curr++];

  // [TYPE]
  dns->type = "A";
  if (curr < argc) {
    char *type = argv[curr];
    if (strcmp(type, "AAAA") == 0) {
      dns->type = "AAAA";
    } else if (strcmp(type, "MX") == 0) {
      dns->type = "MX";
    } else if (strcmp(type, "CNAME") == 0) {
      dns->type = "CNAME";
    } else if (strcmp(type, "NS") == 0) {
      dns->type = "NS";
    } else if (strcmp(type, "TXT") == 0) {
      dns->type = "TXT";
    } else if (strcmp(type, "A") != 0) {
      fprintf(stderr, "Error: invalid TYPE\n");
      return FAILURE;
    }
    curr++;
  }

  if (curr < argc) {
    fprintf(stderr, "Error: too many arguments are provided\n");
    print_usage();
  }

  return SUCCESS;
}
