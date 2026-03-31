// YOUR CODE HERE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <dirent.h>
#include <openssl/md5.h>

// consts
#define BUFSIZE (1 << 16)
#define MAX_URL 4096
#define MAX_HOST 512
#define MAX_PATH 2048
#define CACHE_DIR "./cache"
#define BLOCKLIST_FILE "./blocklist"
#define DEFAULT_TIMEOUT 60
#define HTTP_PORT 80

// globals
static int listen_fd = -1;
static int cache_timeout = DEFAULT_TIMEOUT;



// MD5 hex wrapper for openssl
static void md5_hex(const char *str, char out[33]) {
    unsigned char digest[16];
    MD5((const unsigned char *)str, strlen(str), digest);
    for (int i = 0; i < 16; i++)
        snprintf(out + i*2, 3, "%02x", digest[i]);
    out[32] = '\0';
}

// send error HTTP response
static void send_error(int fd, int code, const char *msg) {
    char buf[512];
    int n = snprintf(buf, sizeof(buf),
        "HTTP/1.0 %d %s\r\n"
        "Content-Type: text/html\r\n"
        "Connection: close\r\n\r\n"
        "<html><body><h1>%d %s</h1></body></html>\r\n",
        code, msg, code, msg);
    { ssize_t _wr = write(fd, buf, n); (void)_wr; }
}

// parses url for host, port, path and HTTP URL
static int parse_url(const char *url, char *host, int *port, char *path) {
    const char *p = url;
    if (strncasecmp(p, "http://", 7) != 0) return -1;
    p += 7;

    // Extract host port
    const char *slash = strchr(p, '/');
    const char *colon = strchr(p, ':');
    size_t host_len;

    if (colon && (!slash || colon < slash)) {
        host_len = colon - p;
        *port = atoi(colon + 1);
    } else {
        host_len = slash ? (size_t)(slash - p) : strlen(p);
        *port = HTTP_PORT;
    }
    if (host_len >= MAX_HOST) return -1;
    strncpy(host, p, host_len);
    host[host_len] = '\0';

    // Extract path
    if (slash)
        strncpy(path, slash, MAX_PATH - 1);
    else
        strcpy(path, "/");
    path[MAX_PATH - 1] = '\0';

    return 0;
}


// signal handling
static void sigchld_handler(int s) {
    (void)s;
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

static void sigint_handler(int s) {
    (void)s;
    if (listen_fd >= 0) close(listen_fd);
    printf("\nProxy shutting down.\n");
    exit(0);
}

// safe reallot
static int safe_append(char **buf, size_t *len, const char *data, size_t n) {
    char *tmp = realloc(*buf, *len + n);
    if (!tmp) return 0;
    memcpy(tmp + *len, data, n);
    *buf = tmp;
    *len += n;
    return 1;
}

// remove trailing whitespace
static void rtrim(char *s) {
    int n = (int)strlen(s) - 1;
    while (n >= 0 && (s[n] == '\r' || s[n] == '\n' || s[n] == ' '))
        s[n--] = '\0';
}

// check if host is in block list
static int is_blocked(const char *host) {
    FILE *f = fopen(BLOCKLIST_FILE, "r");
    if (!f) return 0;
    char line[MAX_HOST];
    while (fgets(line, sizeof(line), f)) {
        rtrim(line);
        if (line[0] == '\0' || line[0] == '#') continue;
        if (strcasecmp(line, host) == 0) {
            fclose(f);
            return 1;
        }
    }
    fclose(f);
    return 0;
}

// un-hashes url using md5
static void cache_path(const char *url, char *out, size_t outlen) {
    char hash[33];
    md5_hex(url, hash);
    snprintf(out, outlen, "%s/%s", CACHE_DIR, hash);
}

// write data to the cache. Returns 1 if write is a success
static int cache_write(const char *url, const char *data, size_t len) {
    // Ensure cache dir exists
    mkdir(CACHE_DIR, 0755);

    char path[512];
    cache_path(url, path, sizeof(path));
    FILE *f = fopen(path, "wb");
    if (!f) return 0;
    fwrite(data, 1, len, f);
    fclose(f);
    return 1;
}

// checks if cache exists and is not too old
static int cache_valid(const char *url) {
    char path[512];
    cache_path(url, path, sizeof(path));
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    time_t now = time(NULL);
    return (now - st.st_mtime) < cache_timeout;
}

// reads from the cache to send to user without prompting webserver
static ssize_t cache_read(const char *url, char **out_data) {
    char path[512];
    cache_path(url, path, sizeof(path));
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return -1; }
    *out_data = malloc(sz);
    { size_t _fr = fread(*out_data, 1, sz, f); (void)_fr; }
    fclose(f);
    return (ssize_t)sz;
}



// prefetch_links(response, resp_len, url);
// todo


static void handle_client(int client_fd) {
    char req_buf[BUFSIZE];
    ssize_t req_len = 0;
    ssize_t n;

    // read until reaching \r\n\r\n
    while(req_len < (ssize_t) (sizeof(req_buf) -1)) {
        n = read(client_fd, req_buf + req_len, sizeof(req_buf) - 1 - req_len);
        if(n<= 0) break;

        req_len += n;
        req_buf[req_len] = '\0';
        if (strstr(req_buf, "\r\n\r\n")) break;
    }
    if (req_len == 0) return;
    req_buf[req_len] = '\0';

    // request parsing

    char method[16], url[MAX_URL], version[16];
    if (sscanf(req_buf, "%15s %4095s %15s", method, url, version) != 3) {
        send_error(client_fd, 400, "Bad Request");
        return;
    }

    // only accept get request
    if (strcasecmp(method, "GET") != 0) {
        send_error(client_fd, 400, "Bad Request");
        return;
    }

    char host [MAX_HOST], path[MAX_PATH];
    int port;
    if (parse_url(url, host, &port, path) != 0) {
        send_error(client_fd, 400, "Bad request");
        return;
    }

    // check block list
    if (is_blocked(host)) {
        send_error(client_fd, 403, "Forbidden");
        return;
    }

    // also check ip against blocklist
    struct hostent *he = gethostbyname(host);
    if (!he) {
        send_error(client_fd, 404, "Host not found");
        return;
    }

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, he->h_addr_list[0], ip_str, sizeof(ip_str));
    if (is_blocked(ip_str)) {
        send_error(client_fd, 403, "Forbidden");
        return;
    }

    // check cache
    if(cache_valid(url)) {
        char *cached = NULL;
        ssize_t cached_len = cache_read(url, &cached);
        if (cached_len > 0) {
            { ssize_t _wr = write(client_fd, cached, cached_len); (void)_wr; }
            free(cached);
            return;
        }
        if (cached) free(cached);
    }

    // not in cache so connect to origin server

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0){
        send_error(client_fd, 500, "Internal Server Error");
        return;
    }

    struct sockaddr_in srv_addr;
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(port);
    memcpy(&srv_addr.sin_addr, he->h_addr_list[0], he->h_length);

    // connect and wait
    struct timeval tv = {30, 0};
    setsockopt(server_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(server_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(server_fd, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) != 0) {
        close(server_fd);
        send_error(client_fd, 502, "Bad Gateway");
        return;
    }

    // build and send a HTTP/1.0 request to origin
    char fwd_req[MAX_PATH + MAX_HOST + 256];
    int fwd_len = snprintf(fwd_req, sizeof(fwd_req),
        "GET %s HTTP/1.0\r\n"
        "Host: %s\r\n"
        "Connection: close\r\n"
        "\r\n",
        path, host);
    { ssize_t _wr = write(server_fd, fwd_req, fwd_len); (void)_wr; }

    // send server response to client and cache it
    char *response = NULL;
    size_t resp_len = 0;
    int do_cache = (strchr(url, '?') == NULL);
    char tmp[BUFSIZE];
    while ((n = read(server_fd, tmp, sizeof(tmp))) > 0) {
        {ssize_t _wr = write(client_fd, tmp, n); (void)_wr; }
        if (do_cache) {
            if (!safe_append(&response, &resp_len, tmp, n)) {
                do_cache = 0;
                free(response);
                response = NULL;
                resp_len = 0;
            }
        }
    }
    close(server_fd);
    
    // cache server response
    if (response && resp_len > 0 ) {
        cache_write(url, response, resp_len); 
    }

    // // uses child process to pre-fetch links
    // if (response && resp_len > 0) {
    //     pid_t pid = fork();
    //     if (pid == 0) {
    //         prefetch_links(response, resp_len, url);
    //         free(response);
    //         exit(0);
    //     }
    // }

    if (response) free(response);
}


int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <port> [cache_timeout_seconds]\n", argv[0]);
        exit(1);
    }

    int port = atoi(argv[1]);
    if (argc >= 3)
        cache_timeout = atoi(argv[2]);

    // Ensure cache directory exists
    mkdir(CACHE_DIR, 0755);

    // Signal handlers
    struct sigaction sa_chld = {0};
    sa_chld.sa_handler = sigchld_handler;
    sigemptyset(&sa_chld.sa_mask);
    sa_chld.sa_flags = SA_RESTART;
    sigaction(SIGCHLD, &sa_chld, NULL);

    struct sigaction sa_int = {0};
    sa_int.sa_handler = sigint_handler;
    sigemptyset(&sa_int.sa_mask);
    sigaction(SIGINT,  &sa_int, NULL);
    sigaction(SIGTERM, &sa_int, NULL);

    // Create listening socket
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) { perror("socket"); exit(1); }

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(port);

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); exit(1);
    }
    if (listen(listen_fd, 128) < 0) {
        perror("listen"); exit(1);
    }

    printf("Proxy listening on port %d (cache timeout: %ds)\n",
           port, cache_timeout);

    // main accept loop
    while (1) {
        struct sockaddr_in cli_addr;
        socklen_t cli_len = sizeof(cli_addr);
        int client_fd = accept(listen_fd, (struct sockaddr *)&cli_addr, &cli_len);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            continue;
        }

        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            close(client_fd);
            continue;
        }
        if (pid == 0) {
            // Child process
            close(listen_fd);
            handle_client(client_fd);
            close(client_fd);
            exit(0);
        }
        // Parent process, close client socket and loop */
        close(client_fd);
    }

    return 0;
}