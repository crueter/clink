#include "mongoose.h"
#include <sys/stat.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static struct mg_serve_http_opts s_http_server_opts;

static void rec_mkdir(const char *dir) {
    char tmp[256];
    char *p = NULL;
    size_t len;

    snprintf(tmp, sizeof(tmp),"%s",dir);
    len = strlen(tmp);
    if (tmp[len - 1] == '/')
        tmp[len - 1] = 0;
    for (p = tmp + 1; *p; p++)
        if (*p == '/') {
            *p = 0;
            mkdir(tmp, S_IRWXU);
            *p = '/';
        }
    mkdir(tmp, S_IRWXU);
}

static void ev_handler(struct mg_connection *nc, int ev, void *p) {
    if (ev == MG_EV_HTTP_REQUEST) {
        mg_serve_http(nc, (struct http_message *) p, s_http_server_opts);
        struct http_message *hm = (struct http_message *) p;
        char *uri = hm->uri.p;
        char *base_uri = strtok(uri, "?");
        char *base_uri2 = malloc(hm->uri.len + 1);

        snprintf(base_uri2, hm->uri.len + 1, "%s", base_uri);
        printf("%s\n", base_uri2);

        char *query = hm->query_string.p;
        char *base_query = malloc(hm->query_string.len + 1);
        char *base_query2 = malloc(256);
        snprintf(base_query, hm->query_string.len + 1, "%s", query);
        mg_url_decode(base_query, hm->query_string.len + 1, base_query2, 256, 0);
        printf("%s\n", base_query2);
    }
}

int main(int argc, char *argv[]) {
    char *port, *data_dir, *url, *seed;
    int index;
    int c;

    opterr = 0;

    while ((c = getopt (argc, argv, "p:d:s:")) != -1) {
        switch (c) {
        case 'p':
            port = optarg;
            break;
        case 'd':
            data_dir = optarg;
            break;
        case 's':
            seed = optarg;
            break;
        case '?':
            if (optopt == 'p' || optopt == 'd' || optopt == 's')
                fprintf (stderr, "Option -%c requires an argument.\n", optopt);
            else if (isprint (optopt))
                fprintf (stderr, "Unknown option `-%c'.\n", optopt);
            else
                fprintf (stderr,
                                 "Unknown option character `\\x%x'.\n",
                                 optopt);
            return 1;
        default:
            abort ();
        }
    }

    printf ("port = %s, data dir = %s, seed = %s\n",
                    port, data_dir, seed);

    for (index = optind; index < argc; index++)
        printf ("Non-option argument %s\n", argv[index]);
    rec_mkdir(strcat(strdup(data_dir), "/links"));
    rec_mkdir(strcat(strdup(data_dir), "/del"));
    struct mg_mgr mgr;
    struct mg_connection *nc;

    mg_mgr_init(&mgr, NULL);
    printf("Starting web server on port %s\n", port);
    nc = mg_bind(&mgr, port, ev_handler);
    if (nc == NULL) {
        printf("Failed to create listener\n");
        return 1;
    }

    // Set up HTTP server parameters
    mg_set_protocol_http_websocket(nc);
    s_http_server_opts.document_root = ".";  // Serve current directory
    s_http_server_opts.enable_directory_listing = "yes";

    for (;;) {
        mg_mgr_poll(&mgr, 1000);
    }
    mg_mgr_free(&mgr);
    return 0;
}

