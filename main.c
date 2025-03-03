#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <libnet.h>

#define TIMEOUT 1000
#define PROMISC 0
#define SNAPL 96
#define MAX_PORTS 123

#define IP_HL(ip) (((ip)->ip_hl) & 0x0F)
#define TCP_HL(tcp) ((((tcp)->th_off) & 0xF0) >> 4)

int find_addr(struct pcap_addr *, const char *);
int set_packet_filter(pcap_t *, const char *, uint16_t *);
void process_packet(uint8_t *, const struct pcap_pkthdr *, const uint8_t *);
void signal_handler(int);
char *strdup(const char *);
void stoa(char *, uint16_t *);
void display_help(const char *);
void port_setup(char *, char *, uint16_t *, size_t);

pcap_t *pcap_hdlr;
libnet_t *lnet_context;
int verbose = 0;

int main(int argc, char const *argv[])
{
    uint16_t ports[MAX_PORTS];
    pcap_if_t *if_list;
    int opt;
    char error_buff[PCAP_ERRBUF_SIZE], dev_name[256], *address_str = NULL, *ports_str = NULL;

    while ((opt = getopt(argc, argv, ":a:p:hv")) > 0)
    {
        switch (opt)
        {
        case 'a':
            address_str = optarg; // ip address
            break;
        case 'p':
            port_setup(ports_str, optarg, ports, sizeof(ports)); // port(s)
            break;
        case 'h':
            display_help(argv[0]); // display help and exit
            break;
        case 'v':
            verbose = 1; // verbose mode
            break;
        case ':':
            // option needs a value
            printf("Error: You specified the -%c option with no arguments\n\n", optopt);
            display_help(argv[0]);
            break;
        case '?':
            // unknown option
            printf("Error: You specified an unknown option -> -%c\n\n", optopt);
            display_help(argv[0]);
            break;
        }
    }

    if (address_str == NULL || argc == 1)
        display_help(argv[0]);

    if (pcap_findalldevs(&if_list, error_buff) == PCAP_ERROR)
    {
        fprintf(stderr, "FindAllDevs error: %s\n", error_buff);
        exit(EXIT_FAILURE);
    }

    if (if_list)
    {
        for (pcap_if_t *dev = if_list; dev->next != NULL;)
        {
            if ((dev->flags & PCAP_IF_UP) && find_addr(dev->addresses, address_str))
            {
                strncpy(dev_name, dev->name, sizeof(dev_name));
                puts(dev_name);
                break;
            }
            dev = dev->next;
        }
        pcap_freealldevs(if_list);

        pcap_hdlr = pcap_open_live(dev_name, SNAPL, PROMISC, TIMEOUT, error_buff);
        if (pcap_hdlr == NULL)
        {
            fprintf(stderr, "PCAPOpenLive error: %s\n", error_buff);
            exit(EXIT_FAILURE);
        }
        if (set_packet_filter(pcap_hdlr, address_str, ports) != 0)
        {
            fprintf(stderr, "Filter error: %s\n", pcap_geterr(pcap_hdlr));
            exit(EXIT_FAILURE);
        }

        lnet_context = libnet_init(LIBNET_RAW4, dev_name, error_buff);
        if (!lnet_context)
        {
            fprintf(stderr, "Libnet init error: %s\n", error_buff);
            exit(EXIT_FAILURE);
        }
        libnet_seed_prand(lnet_context);
        signal(SIGINT, signal_handler);
        pcap_loop(pcap_hdlr, -1, process_packet, (uint8_t *)lnet_context);
    }
    else
    {
        printf("No available devices found...\n");
        exit(EXIT_SUCCESS);
    }
}

int find_addr(struct pcap_addr *addr_list, const char *addr)
{
    struct pcap_addr *temp = addr_list;
    struct in_addr ipv4;

    if (!inet_aton(addr, &ipv4))
    {
        printf("Error: The address you specified is not in a valid dotted decimal format\n");
        exit(EXIT_SUCCESS);
    }

    while (temp != NULL)
    {
        if (temp->addr->sa_family == AF_INET)
        {
            if (((struct sockaddr_in *)temp->addr)->sin_addr.s_addr == ipv4.s_addr)
                return 1;
        }
        temp = temp->next;
    }

    return 0;
}

int set_packet_filter(pcap_t *if_handler, const char *address, uint16_t *ports)
{
    struct bpf_program filter;
    char expression[1024], *ptr;
    int i = 0, bytes = 0;

    sprintf(expression, "tcp and dst host %s and (tcp[tcpflags] & tcp-syn != 0) and (tcp[tcpflags] & tcp-ack == 0)", address);

    if (ports[0] != 0)
    {
        strcat(expression, " and not (");
        ptr = expression + strlen(expression);
        while (ports[i] != 0)
        {
            if (i)
                bytes += sprintf((char *)(ptr + bytes), " or (dst port %hu)", ports[i++]);
            else
                bytes += sprintf((char *)(ptr + bytes), "(dst port %hu)", ports[i++]);
        }
        strcat(expression, ")");
    }

    // printf("%s\n", expression);

    if (pcap_compile(if_handler, &filter, expression, 1, PCAP_NETMASK_UNKNOWN) != 0)
        return -1;
    if (pcap_setfilter(if_handler, &filter) != 0)
        return -1;
    pcap_freecode(&filter);

    return 0;
}

void process_packet(uint8_t *args, const struct pcap_pkthdr *pkt_info, const uint8_t *bytes)
{
    struct libnet_ipv4_hdr *IPhdr;
    struct libnet_tcp_hdr *TCPhdr;
    uint32_t data_len;
    libnet_t *context;
    struct libnet_stats statistics;

    IPhdr = (struct libnet_ipv4_hdr *)(bytes + LIBNET_ETH_H);
    TCPhdr = (struct libnet_tcp_hdr *)(bytes + LIBNET_ETH_H + IP_HL(IPhdr) * 4);
    data_len = ntohs(IPhdr->ip_len) - IP_HL(IPhdr) * 4 - TCP_HL(TCPhdr) * 4;
    context = (libnet_t *)args;

    libnet_build_tcp(ntohs(TCPhdr->th_dport),              // source port
                     ntohs(TCPhdr->th_sport),              // destination port
                     libnet_get_prand(LIBNET_PR32),        // sequence number
                     ntohl(TCPhdr->th_seq) + data_len + 1, // ack number
                     TH_ACK | TH_SYN,                      // FLAGS
                     64240,                                // window size
                     0,                                    // checksum
                     0,                                    // urgent pointer
                     LIBNET_TCP_H,                         // TCP packet length
                     NULL,                                 // payload
                     0,                                    // payload length
                     context,                              // libnet context
                     0                                     // ptag

    );

    libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H, // IP packet length
                      IPTOS_LOWDELAY,               // type of service
                      0,                            // id
                      0,                            // fragmantation bits
                      64,                           // ttl
                      IPPROTO_TCP,                  // subsequent protocol
                      0,                            // checksum
                      IPhdr->ip_dst.s_addr,         // source ip
                      IPhdr->ip_src.s_addr,         // destination ip
                      NULL,                         // payload
                      0,                            // payload length
                      context,                      // libnet context
                      0                             // ptag
    );

    if (libnet_write(context) < 0)
    {
        fprintf(stderr, "Libnet write error: %s\n", libnet_geterror(context));
        exit(EXIT_FAILURE);
    }
    if (verbose)
    {
        libnet_stats(context, &statistics);
        printf("Packets sent -> %lu\nErrors -> %lu\nTotal bytes -> %lu\n\n\n", statistics.packets_sent, statistics.packet_errors, statistics.bytes_written);
    }

    libnet_clear_packet(context);
}

void signal_handler(int sig)
{
    printf("\nExiting...\n");
    libnet_destroy(lnet_context);
    pcap_close(pcap_hdlr);
    exit(EXIT_SUCCESS);
}

char *strdup(const char *s)
{
    char *str = (char *)malloc(strlen(s) + 1);
    if (str == NULL)
    {
        fprintf(stderr, "\nStrdup problem!\n");
        exit(EXIT_FAILURE);
    }
    strcpy(str, s);

    return str;
}

void stoa(char *str, uint16_t *array)
{
    char *token = strtok(str, ",");
    int i = 0;

    while (token != NULL && i < MAX_PORTS)
    {
        *(array + i) = (uint16_t)atoi(token);
        token = strtok(NULL, ",");
        i++;
    }
}

void display_help(const char *program)
{
    printf("Usage:\t%s [options] <arguments>\n\n"
           "Options:\n"
           "-a (mandatory)\tSpecify the IPv4 address you want to protect\n"
           "-p\t\tSpecify up to 123 excluded ports as arguments. You can separate them by ',' with no spaces\n"
           "-v\t\tVerbose mode. See statistics about the packets sent by the process\n"
           "-h\t\tDisplay this menu and exit\n\n",
           program);

    exit(EXIT_SUCCESS);
}

void port_setup(char *ports_s, char *arg, uint16_t *ports_arr, size_t size)
{
    ports_s = strdup(arg);
    memset(ports_arr, 0, size);
    stoa(ports_s, ports_arr);
    free(ports_s);
}