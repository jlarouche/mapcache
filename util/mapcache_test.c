/******************************************************************************
 * $Id: mapcache_seed.c 13201 2014-05-05 15:28:45Z jlarouche $
 *
 * Project:  MapServer
 * Purpose:  MapCache utility program for testing purposes
 * Author:   Jerome Villeneuve-Larouche and the MapServer team.
 *
 ******************************************************************************
 * Copyright (c) 1996-2011 Regents of the University of Minnesota.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies of this Software or works derived from this Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *****************************************************************************/

#include <unistd.h>
#include "mapcache-util-config.h"
#include <signal.h>
#include "mapcache.h"
#include <apr_getopt.h>
#include <apr_file_io.h>
#include <apr_file_info.h>

int sig_int_received = 0;
mapcache_context ctx;
mapcache_cfg *cfg;

static const apr_getopt_option_t test_options[] = {
  /* long-option, short-option, has-arg flag, description */
  { "help", 'h', FALSE, "show help" },
  { "config", 'c', TRUE, "configuration file (/path/to/mapcache.xml)"},
  { "query", 'q', TRUE, "Query string" },
  { "ouput", 'o', TRUE, "Output file with extension (/path/to/image.gif)" },
  { NULL, 0, 0, NULL }
};

void handle_sig_int(int signal)
{
  if(!sig_int_received) {
    fprintf(stderr,"SIGINT received, waiting for threads to finish\n");
    fprintf(stderr,"press ctrl-C again to force terminate\n");
    sig_int_received = 1;
  } else {
    exit(signal);
  }
}

int usage(const char *progname, char *msg, ...)
{
  int i=0;
  if(msg) {
    va_list args;
    va_start(args,msg);
    printf("%s\n",progname);
    vprintf(msg,args);
    printf("\noptions:\n");
    va_end(args);
  }
  else
    printf("usage: %s options\n",progname);

  while(test_options[i].name) {
    if(test_options[i].has_arg==TRUE) {
      printf("-%c|--%s [value]: %s\n",test_options[i].optch,test_options[i].name, test_options[i].description);
    } else {
      printf("-%c|--%s: %s\n",test_options[i].optch,test_options[i].name, test_options[i].description);
    }
    i++;
  }
  apr_terminate();
  return 1;
}

void mapcache_context_testing_log(mapcache_context *ctx, mapcache_log_level level, char *msg, ...)
{
  va_list args;
  va_start(args,msg);
  vfprintf(stderr,msg,args);
  va_end(args);
  printf("\n");
}

int main(int argc, const char **argv)
{

  mapcache_request *request = NULL;
  mapcache_http_response *http_response = NULL;
  apr_getopt_t *opt;
  apr_table_t *params;
  apr_size_t bytes;
  apr_status_t ret;
  int rv, optch;
  const char *optarg;
  const char *configfile=NULL;
  const char *outputfile=NULL;
  const char *query_string=NULL;
  apr_file_t *fp;

  apr_initialize();
  (void) signal(SIGINT, handle_sig_int);
  apr_pool_create(&ctx.pool, NULL);
  mapcache_context_init(&ctx);
  ctx.process_pool = ctx.pool;
  cfg = mapcache_configuration_create(ctx.pool);
  ctx.config = cfg;
  ctx.log = mapcache_context_testing_log;
  apr_getopt_init(&opt, ctx.pool, argc, argv);

  while ((rv = apr_getopt_long(opt, test_options, &optch, &optarg)) == APR_SUCCESS) {
    switch (optch) {
      case 'h':
        return usage(argv[0],NULL);
        break;
      case 'c':
        configfile = optarg;
        break;
      case 'q':
        query_string = optarg;
        break;
      case 'o':
        outputfile = optarg;
        break;
    }
  }

  if (rv != APR_EOF) {
    return usage(argv[0],"bad options");
  }

  if( ! configfile ) {
    return usage(argv[0],"config not specified");
  } else {
    mapcache_configuration_parse(&ctx,configfile,cfg,0);
    if(ctx.get_error(&ctx))
      return usage(argv[0],ctx.get_error_message(&ctx));
    mapcache_configuration_post_config(&ctx,cfg);
    if(ctx.get_error(&ctx))
      return usage(argv[0],ctx.get_error_message(&ctx));
  }

  if ( ! query_string ) {
    return usage(argv[0], "Query String not specified");
  } else {
    params = mapcache_http_parse_param_string(&ctx, query_string);
    if(ctx.get_error(&ctx))
      return usage(argv[0],ctx.get_error_message(&ctx));
  }

  mapcache_service_dispatch_request(&ctx, &request, "/", params, ctx.config);
  if(ctx.get_error(&ctx) || !request)
    return usage(argv[0], ctx.get_error_message(&ctx));

  if( request->type == MAPCACHE_REQUEST_GET_MAP) {
    mapcache_request_get_map *req_map = (mapcache_request_get_map*)request;
    http_response = mapcache_core_get_map(&ctx,req_map);
  }

  if (ctx.get_error(&ctx) || !http_response)
    return usage(argv[0], ctx.get_error_message(&ctx));

  if (!outputfile)
  {
    if(write(1, (void*)http_response->data->buf, http_response->data->size) != http_response->data->size)
      usage(argv[0], "Error while writing to stdout");
  }
  else
  {
    ret = apr_file_remove(outputfile,ctx.pool);
    if(ret != APR_SUCCESS && !APR_STATUS_IS_ENOENT(ret))
      usage(argv[0], "Could not remove output file");

    if ((ret =  apr_file_open(&fp, outputfile, APR_FOPEN_CREATE|APR_FOPEN_WRITE|APR_FOPEN_BUFFERED|APR_FOPEN_BINARY,
            APR_OS_DEFAULT, ctx.pool ) != APR_SUCCESS))
      usage(argv[0], "Could not open output file");

    bytes = (apr_size_t)http_response->data->size;
    ret = apr_file_write(fp, (void*)http_response->data->buf, &bytes);
    if ( ret != APR_SUCCESS)
      usage(argv[0], "Error while writing to output file");

    apr_file_close(fp);
    printf("File written\n");
  }

  apr_terminate();
  return 0;
}
