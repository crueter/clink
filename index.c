#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ccgi.h"

extern char **environ;

#ifdef _WIN32
#define EOL "\n"
#else
#define EOL "\r\n"
#endif
int alpha_cmp(const void *a, const void *b) {
    return strcmp(*(const char **) a, *(const char **) b);
}

int main(int argc, char **argv) {
/* printf("Content-type: text/html\n\n");
 printf("<html><title>Hello</title><body>\n");
 printf("Goodbye Cruel World\n");
 printf("cope %s\n", argv[1]);
 printf("</body></html>");
 return 1;*/
    puts("Content-Type: text/html" EOL "Status: 201 Created" EOL EOL);

    puts("<pre>" EOL "<h1>Environment</h1>" EOL);
    {
        const char *sorted_env[500];
        size_t i, num_env;

        for (num_env = 0; environ[num_env] != 0; num_env++) {
            sorted_env[num_env] = environ[num_env];
        }
        qsort(sorted_env, num_env, sizeof(const char *), alpha_cmp);

        for (i = 0; i < num_env; i++) {
            printf("E: %s" EOL, sorted_env[i]);
        }
    }
    puts(EOL "<h1>Query string</h1>" EOL);
    {
        const char *k;
        CGI_varlist *vl = CGI_get_query(NULL);

        for (k = CGI_first_name(vl); k != NULL; k = CGI_next_name(vl)) {
            printf("Q: %s=%s" EOL, k, CGI_lookup(vl, k));
        }

        CGI_free_varlist(vl);
    }
    puts(EOL "<h1>Form variables</h1>" EOL);
    {
        const char *k;
        CGI_varlist *vl = CGI_get_post(NULL, NULL);

        for (k = CGI_first_name(vl); k != NULL; k = CGI_next_name(vl)) {
            printf("P: %s=%s" EOL, k, CGI_lookup(vl, k));
        }

        CGI_free_varlist(vl);
    }
    const char *host = getenv("HTTP_HOST");
    printf("%s\n", host);

    const char *query = getenv("QUERY_STRING");
    printf("%s\n", query);

    puts(EOL "</pre>" EOL);
    return 0;
}

