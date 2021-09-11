#include "mongoose.h"
#include "index.h"

#include <string.h>
#include <sys/stat.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <crypt.h>
#include <time.h>

char *port = "8080";
char *data_dir = "/srv/clink";
char *seed = "secret";

static struct mg_http_serve_opts s_http_server_opts;

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

bool file_exists(char *filename) {
    struct stat buffer;
    return (stat (filename, &buffer) == 0);
}

char *get_link_filename(char *link) {
    char *filename = malloc(strlen(data_dir) + strlen(link) + 8);
    sprintf(filename, "%s/links/%s", data_dir, link);
    return filename;
}

char *get_del_filename(char *link) {
    char *filename = malloc(strlen(data_dir) + strlen(link) + 6);
    sprintf(filename, "%s/del/%s", data_dir, link);
    return filename;
}

bool link_exists(char *link) {
    return file_exists(get_link_filename(link));
}

FILE *get_link_file(char *link, const char *mode) {
    return fopen(get_link_filename(link), mode);
}

FILE *get_del_file(char *link, const char *mode) {
    return fopen(get_del_filename(link), mode);
}

char *random_short_link() {
    srand(time(NULL));
    char *short_link = malloc(17);
    for(size_t i = 0; i < 16; i++) {
        sprintf(short_link + i, "%x", rand() % 16);
    }
    return short_link;
}

char *gen_del_key(char *link) {
    char salt[50];
    sprintf(salt, "$6$%s%d", seed, (int)time(NULL));

    char *del_key = crypt(link, salt);

    return del_key;
}

void trim(char *str) {
    char *_str = str;
    int len = strlen(_str);

    while(isspace(_str[len - 1])) _str[--len] = 0;
    while(*_str && *_str == '/') ++_str, --len;

    memmove(str, _str, len + 1);
}

void make_short_url(struct mg_connection *nc, char *to, char *host, char *link) {
    char *short_link;
    if (strlen(link) == 0) {
        short_link = random_short_link();
    } else {
        short_link = link;
    }

    if (link_exists(short_link)) {
        mg_http_reply(nc, 500, "", "short link %s already exists", link);
        return;
    }

    FILE *url = get_link_file(short_link, "w+");
    fputs(to, url);
    fclose(url);

    FILE *del = get_del_file(short_link, "w+");
    char *del_key = gen_del_key(short_link);
    fputs(del_key, del);
    fclose(del);

    char *del_header = malloc(256);
    sprintf(del_header, "X-Delete-With: %s\r\n", del_key);

    mg_http_reply(nc, 201, del_header, "http://%s/%s", host, short_link);
}

void handle_url_req(struct mg_connection *nc, char *to, char *host, char *link) {
    if (strlen(to) != 0) {
        make_short_url(nc, to, host, link);
    } else {
        if (strlen(link) == 0) {
            mg_http_reply(nc, 200, "Content-Type: text/html\r\n", INDEX_HTML,
                          host, host, host, host, host, host, host, host, host, host, host); // FIXME: need better solution
        } else {
            if (link_exists(link)) {
                FILE *url = get_link_file(link, "r");
                char *urlto = malloc(256);
                fgets(urlto, 256, url);
                fclose(url);
                char *loc = malloc(strlen(urlto) + 14);
                sprintf(loc, "Location: %s\r\n", urlto);
                mg_http_reply(nc, 302, loc, urlto);
            } else {
                mg_http_reply(nc, 404, "", "this short link does not exist");
            }
        }
    }
}

void handle_delete(struct mg_connection *nc, char *link, char *del_key) {
    if (link_exists(link)) {
        FILE *del = get_del_file(link, "r");
        char *key = malloc(256);
        fgets(key, 256, del);
        if (strcmp(key, del_key) == 0) {
            remove(get_link_filename(link));
            remove(get_del_filename(link));
            mg_http_reply(nc, 204, "", "");
        } else {
            mg_http_reply(nc, 403, "", "incorrect deletion key");
        }
    } else {
        mg_http_reply(nc, 404, "", "this short link does not exist");
    }
}

static void ev_handler(struct mg_connection *nc, int ev, void *p, void *f) {
    if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message *hm = (struct mg_http_message *) p;
        char *uri = malloc(hm->uri.len + 1);

        snprintf(uri, hm->uri.len + 1, "%s", hm->uri.ptr);
        trim(uri);

        char *query = malloc(256);
        struct mg_str hquery = hm->query;
        if (hquery.len > 0) {
            char *base_query = malloc(hquery.len + 1);
            snprintf(base_query, hquery.len + 1, "%s", hquery.ptr);
            mg_url_decode(base_query, hquery.len + 1, query, 256, 0);
        } else {
            query = "";
        }

        struct mg_str *mhost = mg_http_get_header(hm, "Host");
        char *host = malloc(mhost->len + 1);
        snprintf(host, mhost->len + 1, "%s", mhost->ptr);

        char *body = strdup(hm->body.ptr);

        if (strncmp(hm->method.ptr, "POST", hm->method.len) == 0) {
            handle_url_req(nc, body, host, uri);
        } else if (strncmp(hm->method.ptr, "DELETE", hm->method.len) == 0) {
            handle_delete(nc, uri, body);
        } else {
            handle_url_req(nc, query, host, uri);
        }
    }
}

int main(int argc, char *argv[]) {
    int index;
    int c;

    opterr = 0;
    setvbuf(stdout, NULL, _IONBF, 0);

    while ((c = getopt (argc, argv, "p:d:s:h")) != -1) {
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
        case 'h':
            printf("clink: a minimal URL shortener\n");
            printf("usage: %s [-p port] [-d data_dir] [-s seed]\n\n", argv[0]);
            printf("options:\n");
            printf("-p <port>\t\tport to use (default 8080)\n");
            printf("-d <data directory>\tdirectory to store data (default /srv/clink)\n");
            printf("-s <seed>\t\tsecret seed to use (DO NOT SHARE THIS; default 'secret')\n\n");
            printf("source: https://git.swurl.xyz/swirl/clink (submit bug reports, suggestions, etc. here)\n");
            return 0;
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

    for (index = optind; index < argc; index++)
        printf ("Non-option argument %s\n", argv[index]);
    rec_mkdir(strcat(strdup(data_dir), "/links"));
    rec_mkdir(strcat(strdup(data_dir), "/del"));
    struct mg_mgr mgr;
    struct mg_connection *nc;

    mg_mgr_init(&mgr);
    printf("Starting web server on port %s\n", port);
    char *str_port = malloc(20);
    sprintf(str_port, "http://0.0.0.0:%s", port);
    nc = mg_http_listen(&mgr, str_port, ev_handler, &mgr);
    if (nc == NULL) {
        printf("Failed to create listener\n");
        return 1;
    }

    for (;;) {
        mg_mgr_poll(&mgr, 1000);
    }
    mg_mgr_free(&mgr);
    return 0;
}

