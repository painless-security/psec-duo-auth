#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include <argp.h>

#include "libduo/duo.h"

#define PROGRAM_NAME "psec-duo-auth"
#define PROGRAM_VERSION "1.0"

/* Argument parser configuration */
/* argp_program_version is used internally by the argp library */
const char *argp_program_version = PROGRAM_NAME " " PROGRAM_VERSION;

static char doc[] = "Authenticate a user via Duo";

static struct argp_option options[] = {
    {"config",  'c', "CFG_FILE", 0, "Configuration file path"},
    {"user",    'u', "USER",     0, "Duo username to authenticate"},
    {"message", 'm', "MESSAGE", 0, "Message to be displayed in Duo push notification"},
    {NULL}
};

struct arguments {
  char *cfgPath;
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
  struct duo_auth *duoAuth;
  struct duo_push_params duoPushParams;

  psec_duo_config_t psecDuoConfig;

  struct arguments args;
  int argsOk;
  int returnCode;

  /* set default arguments */
  args.cfgPath = NULL;
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

  if (!argsOk) {
    return EXIT_FAIL;
  }

  /* Load Duo config file */
  if (parse_duo_config(args.cfgPath, &psecDuoConfig) != 0) {
    return EXIT_FAIL;
  }

  duo = duo_init(psecDuoConfig.apiHost,
                 psecDuoConfig.integrationKey,
                 psecDuoConfig.secretKey,
                 PROGRAM_NAME "/" PROGRAM_VERSION,
                 NULL, /* cafile */
                 NULL /* proxy */
		 ); 

  if (!duo) {
    fprintf(stderr, "Failed to initialize Duo auth library: %s\n", duo_get_error(duo));
    exit(EXIT_FAIL);
  }

  /* Start wth a preauth */
  duoAuth = duo_auth_preauth(duo, args.user);
  if (!duoAuth) {
    printf("Duo preauth failed: %s\n", duo_get_error(duo));
    return EXIT_FAIL;
  }

  if (0 == strcmp(duoAuth->ok.preauth.result, "allow")) {
    /* allow means no Duo auth is required for this user */
    printf("%s\n", duoAuth->ok.preauth.status_msg);
    return EXIT_OK;
  } else if (0 != strcmp(duoAuth->ok.preauth.result, "auth")) {
    /* anything other than allow or auth - reject the user */
    printf("%s\n", duoAuth->ok.preauth.status_msg);
    return EXIT_REJECT;
  }
  duo_auth_free(duoAuth);

  /* Duo auth needed, continue */
  duoPushParams.device = "auto";
  duoPushParams.type = NULL;
  duoPushParams.display_username = NULL;
  duoPushParams.pushinfo = NULL;

  duoAuth = duo_auth_auth(duo, args.user, "push", NULL, &duoPushParams);
  
  if (!duoAuth) {
    printf("Duo auth failed: %s\n", duo_get_error(duo));
    return EXIT_FAIL;
  }

  if (0 == strcmp(duoAuth->ok.auth.result, "allow")) {
    /* Authentication succeeded */
    printf("Duo authentication succeeded for %s\n", args.user);
    return EXIT_OK;
  }
  
  /* Authentication failed */
  printf("Duo authentication failed for %s\n", args.user);
  return EXIT_REJECT;

  duo_auth_free(duoAuth);
  duo_close(duo);

  return returnCode;
}
