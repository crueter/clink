#include "mongoose.h"
#include <string.h>
#include <sys/stat.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

char *port, *data_dir, *url, *seed;
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

void make_short_url(struct mg_connection *nc, char *to, char *host, char *link) {
    if (strncmp(to, "", 1) != 0) {
        if (strncmp(link, "/", 2) == 0) {
            mg_printf(nc, "HTTP/1.0 200 OK\r\n\r\nmaking short url to %s", to);
        } else {
            mg_printf(nc, "HTTP/1.0 200 OK\r\n\r\nmaking short url to %s, with url https://%s%s", to, host, link);
            char *filename = malloc(strlen(data_dir) + strlen(link) + 1);
            sprintf(filename, "%s/links%s", data_dir, link);
            FILE *url = fopen(filename, "w+");
            fputs(to, url);
            fclose(url);
        }
    } else {
        if (strncmp(link, "/", 2) == 0) {
            mg_printf(nc, "HTTP/1.0 200 OK\r\n\r\nwelcome to link shortener\r\nexample: curl https://%s/?duckduckgo.com", host);
        } else {
            mg_printf(nc, "HTTP/1.0 500 Internal Server Error\r\n\r\nplease include a URL to point to");
        }
    }
}

static void ev_handler(struct mg_connection *nc, int ev, void *p) {
    if (ev == MG_EV_HTTP_REQUEST) {
        struct http_message *hm = (struct http_message *) p;
        char *uri = strdup(hm->uri.p);
        char *base_uri = strtok(uri, "?");
        char *base_uri2 = malloc(hm->uri.len + 1);

        snprintf(base_uri2, hm->uri.len + 1, "%s", base_uri);
        printf("%s\n", base_uri2);

        char *base_query2 = malloc(256);
        if (hm->query_string.len > 0) {
            char *query = strdup(hm->query_string.p);
            char *base_query = malloc(hm->query_string.len + 1);
            snprintf(base_query, hm->query_string.len + 1, "%s", query);
            mg_url_decode(base_query, hm->query_string.len + 1, base_query2, 256, 0);
            printf("%s\n", base_query2);
        } else {
            base_query2 = "";
        }

        struct mg_str *host = mg_get_http_header(hm, "Host");
        char *uhost = strdup(host->p);

        char *fhost = malloc(host->len + 1);
        snprintf(fhost, host->len + 1, "%s", uhost);

        printf("%s\n", fhost);

        if (strncmp(hm->method.p, "POST", hm->method.len) == 0) {
            struct mg_str body = hm->body;
            char *post_body = malloc(body.len + 1);
            snprintf(post_body, body.len + 1, "%s", body.p);

            printf("%s\n", post_body);
            make_short_url(nc, post_body, fhost, base_uri2);
        } else {
            make_short_url(nc, base_query2, fhost, base_uri2);
        }
        nc->flags |= MG_F_SEND_AND_CLOSE;
    }
}

int main(int argc, char *argv[]) {
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

