#include <stdlib.h>
#include <argp.h>

/**
  * Public Data
  */

const char *argp_program_version = "Simple Dns Server 1.0";
const char *argp_program_bug_address = "<nunez.emiliano@gmail.com>";

struct arguments{
  int verbose, quiet, nocache;
  char *dns;
  char *host_file;
};

struct arguments arguments;

/**
  * Private Data
  */

static char doc[] = "Simple DNS Server with caching and local/remote resolution";
static char args_doc[] = "";
static struct argp_option options[] = {
  {"verbose",  'v', 0,      0,  "Produce verbose output" },
  {"quiet",    'q', 0,      0,  "Don't produce any output" },
  {"nocache",  'n', 0,      0,  "Disable cache" },
  {"dns",      'd', "IP",   0,  "Primary DNS IP"},
  {"host_file",'h', "FILE", 0, "Hosts file location" },
  { 0 }
};

static error_t parse_opt (int key, char *arg, struct argp_state *state) {
  
  struct arguments *arguments = (struct arguments*) state->input;

  switch (key) {

    case 'v':
      arguments->verbose = 1;
      break;
    case 'q':
      arguments->quiet = 1;
      break;
    case 'n':
      arguments->nocache = 1;
      break;
    case 'd':
      arguments->dns = arg;
      break;
    case 'h':
      arguments->host_file = arg;
      break;
    default:
      return ARGP_ERR_UNKNOWN;
    }
  return 0;
}

static struct argp argp = { options, parse_opt, args_doc, doc };

void parse_args (int argc, char **argv) {

  arguments.quiet = 0;
  arguments.verbose = 0;
  arguments.nocache = 0;
  arguments.host_file = (char*) "/etc/hosts";
  arguments.dns = (char*) "8.8.8.8";

  argp_parse (&argp, argc, argv, 0, 0, &arguments);

}