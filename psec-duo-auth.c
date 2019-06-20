#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include <duo.h>
#include <argp.h>

#define PROGRAM_NAME "psec-duo-auth"
#define PROGRAM_VERSION "1.0"

/* HTTPS connection timeout limits in ms */
#define MIN_HTTPS_TIMEOUT 100
#define MAX_HTTPS_TIMEOUT 30000

/* Argument parser configuration */
/* argp_program_version is used internally by the argp library */
const char *argp_program_version = PROGRAM_NAME " " PROGRAM_VERSION;

static char doc[] = "Authenticate a user via Duo";

static struct argp_option options[] = {
    {"config",  'c', "CFG_FILE", 0, "Configuration file path"},
    {"user",    'u', "USER",     0, "Duo username to authenticate"},
    {"message", 'm', "MESSAGE", 0, "Message to be displayed in Duo push notification"},
    {"timeout", 't', "TIMEOUT",  0, "HTTPS timeout (milliseconds, default 3000, must be between 100 and 30000"},
    {NULL}
};

struct arguments {
  char *cfgPath;
  long httpsTimeout;
  char *message;
  char *user;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
  struct arguments *args = state->input;

  switch (key) {
    case 'c':
      args->cfgPath = arg;
      break;

    case 'u':
      args->user = arg;
      break;

    case 'm':
      args->message = arg;
      break;

    case 't':
      printf("%s", arg);
      fflush(stdout);
      args->httpsTimeout = strtol(arg, NULL, 10);
      break;


    default:
      return ARGP_ERR_UNKNOWN;
  }

  return 0;
}

static struct argp argpCfg = {options, parse_opt, NULL, doc};


/* Structure to hold Duo configuration while loading */
typedef struct {
  char *apiHost;
  char *integrationKey;
  char *secretKey;
} psec_duo_config_t;


/* Parse configuration. Expects something like:
 * {"duo": {
 *    "integration_key": "DIxxx",
 *    "secret_key": "xxxxx",
 *    "api_host": api-xxx.duosecurity.com"}}
 */
static int parse_duo_config(const char *filename, psec_duo_config_t *psecDuoConfig) {
  json_t *jCfg;
  json_t *jDuoObj;
  json_t *jVal;

  jCfg = json_load_file(filename, JSON_REJECT_DUPLICATES, NULL);
  if (!jCfg || !json_is_object(jCfg)) {
    fprintf(stderr, "Error parsing %s. Must be a valid JSON object.\n", filename);
    return -1;
  }

  jDuoObj = json_object_get(jCfg, "duo");
  if (!jDuoObj || !json_is_object(jDuoObj)) {
    fprintf(stderr,
            "Error parsing %s. Did not contain an object named 'duo'.\n",
            filename);
    return -1;
  }

  jVal = json_object_get(jDuoObj, "integration_key");
  if (!jVal || !json_is_string(jVal)) {
    fprintf(stderr,
        "Error parsing %s: No string named 'integration_key' in the 'duo' object.\n",
        filename);
    return -1;
  }
  psecDuoConfig->integrationKey = strdup(json_string_value(jVal));
  if (!psecDuoConfig->integrationKey) {
    fprintf(stderr, "Error: failed to allocate integrationKey.\n");
    return -1;
  }

  jVal = json_object_get(jDuoObj, "secret_key");
  if (!jVal || !json_is_string(jVal)) {
    fprintf(stderr,
            "Error parsing %s: No string named 'secret_key' in the 'duo' object.\n",
            filename);
    return -1;
  }
  psecDuoConfig->secretKey = strdup(json_string_value(jVal));
  if (!psecDuoConfig->secretKey) {
    fprintf(stderr, "Error: failed to allocate secretKey.\n");
    return -1;
  }

  jVal = json_object_get(jDuoObj, "api_host");
  if (!jVal || !json_is_string(jVal)) {
    fprintf(stderr,
            "Error parsing %s: No string named 'api_host' in the 'duo' object.\n",
            filename);
    return -1;
  }
  psecDuoConfig->apiHost = strdup(json_string_value(jVal));
  if (!psecDuoConfig->apiHost) {
    fprintf(stderr, "Error: failed to allocate apiHost.\n");
    return -1;
  }

  json_decref(jCfg);

  return 0;
}

/* FreeRADIUS exec exit codes */
/* auth ok */
#define EXIT_OK 0

/* user rejected */
#define EXIT_REJECT 1

/* module failed */
#define EXIT_FAIL 2


int main(int argc, char *argv[])
{
  duo_t *duo;
  duo_code_t duoResult;
  const char *duoErrMsg;

  psec_duo_config_t psecDuoConfig;

  struct arguments args;
  int argsOk;
  int returnCode;

  /* set default arguments */
  args.cfgPath = NULL;
  args.httpsTimeout = 3000;
  args.message = NULL;
  args.user = NULL;

  /* parse arguments */
  argp_parse(&argpCfg, argc, argv, 0, 0, &args);

  /* validate arguments */
  argsOk = 1;
  if (args.cfgPath == NULL) {
    argsOk = 0;
    printf("Configuration path not specified\n");
  }

  if (args.user == NULL) {
    argsOk = 0;
    printf("User to authenticate not specified\n");
  }

  if ((args.httpsTimeout < MIN_HTTPS_TIMEOUT) || (args.httpsTimeout > MAX_HTTPS_TIMEOUT)) {
    argsOk = 0;
    printf("Timeout must be between %d and %d milliseconds\n", MIN_HTTPS_TIMEOUT, MAX_HTTPS_TIMEOUT);
  }

  if (!argsOk) {
    return EXIT_FAIL;
  }

  /* Load Duo config file */
  if (parse_duo_config(args.cfgPath, &psecDuoConfig) != 0) {
    return EXIT_FAIL;
  }

  duo = duo_open(psecDuoConfig.apiHost,
                 psecDuoConfig.integrationKey,
                 psecDuoConfig.secretKey,
                 PROGRAM_NAME "/" PROGRAM_VERSION,
                 NULL, /* cafile */
                 (int) args.httpsTimeout);

  if (!duo) {
    fprintf(stderr, "Failed to initialize Duo auth library: %s\n", duo_geterr(duo));
    exit(EXIT_FAIL);
  }

  duo_set_conv_funcs(duo, NULL, NULL, NULL);

  duoResult = duo_login(duo,
                        args.user,
                        NULL, /* client_ip */
                        DUO_FLAG_SYNC | DUO_FLAG_AUTO,
                        args.message /* command */
  );

  switch (duoResult) {
    case DUO_OK:
      /* Authentication succeeded */
      printf("Duo authentication succeeded for %s\n", args.user);
      returnCode = EXIT_OK;
      break;

    case DUO_FAIL:
      /* Authentication failed */
      printf("Duo authentication failed for %s\n", args.user);
      returnCode = EXIT_REJECT;
      break;

    default:
      /* Something went wrong */
      returnCode = EXIT_FAIL;
      duoErrMsg = duo_geterr(duo);
      if (duoErrMsg) {
        printf("Duo error: %s\n", duo_geterr(duo));
      }
      break;
  }

  duo_close(duo);

  return returnCode;
}
