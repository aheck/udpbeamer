#include <stdio.h>
#include <strings.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <pcap.h>

int sock = 0;
pcap_t *handle = NULL;

void usage()
{
    fprintf(stderr, "udpbeamer DEVICE TARGET_IP UDP_PORT\n\n");
    fprintf(stderr, "UDP \"connection\" quality measuring tool\n\n");

    fprintf(stderr, "Sniffs outgoing UDP packets on a user-defined port and sends them over TCP\n");
    fprintf(stderr, "(port 3450) to a udpbeamer server on the destination host of the UDP packets.\n");
    fprintf(stderr, "The server sniffs for incoming packets and compares the ones received over the\n");
    fprintf(stderr, "TCP side-channel to the ones received over UDP and prints statistics about\n");
    fprintf(stderr, "packet loss.\n\n");

    fprintf(stderr, "Example: udpbeamer eth0 192.168.1.5 53\n");
    fprintf(stderr, "This checks if all DNS packets sent on eth0 reach 192.168.1.5\n");

    exit(1);
}

void cleanup()
{
    if (handle) {
        pcap_close(handle);
    }

    if (sock) {
        close(sock);
    }
}

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    struct sockaddr_in serveraddr;
    struct bpf_program fp;
    char filter_exp[1024];
    int bytes;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    struct pcap_pkthdr header;
    const u_char *packet;
    uint32_t len;

    atexit(&cleanup);

    int server_port = 3450;

    const char *dev;
    const char *target_host;
    int udp_port;

    if (argc != 4) {
        usage();
    }

    dev = argv[1];
    target_host = argv[2];
    udp_port = atoi(argv[3]);

    snprintf(filter_exp, sizeof(filter_exp), "ip proto \\udp and dst host %s and dst port %d", target_host, udp_port);

    sock = socket(AF_INET, SOCK_STREAM, 0);

    printf("Connecting to target host %s on TCP port %d...\n", target_host, server_port);
 
    bzero(&serveraddr, sizeof(serveraddr));
    inet_pton(AF_INET, target_host, &serveraddr.sin_addr);
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(3450);
 
    int res = connect(sock, (struct sockaddr*) &serveraddr, sizeof(serveraddr));
    if (res != 0) {
        fprintf(stderr, "ERROR: Failed to connect to %s:3450\n", target_host);
        return 0;
    }

    printf("Connected...\n");

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    while (1) {
        packet = pcap_next(handle, &header);

        if (packet == NULL) {
            sleep(1);
            continue;
        }

        len = htonl(header.len);
        bytes = send(sock, &len, sizeof(len), 0);
        printf("%d\n", bytes);
        printf("len: %d\n", header.len);
        bytes = send(sock, packet, header.len, 0);
        printf("%d\n", bytes);
    }

    return 0;
}
