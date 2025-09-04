#include "ft_ping.h"
#include <stdint.h>

uint16_t    checksum(void *b, int len);
void        build_icmp_packet(t_icmp *icmp, uint8_t *packet, t_options *options);

int main(int ac, char **av) {

    t_options options;
    t_data    data;

    set_default_options(&options);
    if (parse_args(ac, av, &options, &data) != 0) {
        return (1);
    }

    printf("Target: %s | %s\n", data.target_address, data.target_domain_name);
    printf("Options:\nverbose : %d\nflood : %d\npreload : %d\nnumeric only : %d\nglobal timeout : %d\npacket timeout : %d\npadding : %d\npadding len : %lu\nbypass rooting : %d\npacket size : %d\ntime to live : %d\n",
    options.verbose, options.flood, options.preload, options.numeric_address_only, options.global_timeout, options.packet_timeout, options.padding, options.padding_len, options.bypass_rooting, options.packet_size, options.time_to_live);


    // Initialise a socket to send packets then set its options
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("ft_ping: socket");
        return -1;
    }
    setsockopt(sockfd, IPPROTO_IP, IP_TTL, &options.time_to_live, sizeof(int));
    struct timeval timeout = {
        .tv_sec = options.packet_timeout,
        .tv_usec = 0,
    };
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    // Initialise the packet we will send :
    uint8_t *packet = calloc(1, 8 + options.packet_size);
    if (!packet) {
        perror("calloc");
        return -1;
    }
    t_icmp *icmp = (t_icmp *) packet;

    build_icmp_packet(icmp, packet, &options);

    //TODO : Main ping loop to send / receive based on options


    free(packet);
    return (0);
}

uint16_t checksum(void *b, int len) {
    uint16_t *buf = b;
    unsigned int sum = 0;

    for (; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(uint8_t*)buf;

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

void    build_icmp_packet(t_icmp *icmp, uint8_t *packet, t_options *options) {

    icmp->type = 8; // 8 = echo request, so basically a ping :)
    icmp->code = 0;
    icmp->id = htons(getpid() & 0xFFFF);
    uint16_t sequence_num = 0;
    icmp->sequence = htons(sequence_num);  // Increments with each packet sent

    // Fill the payload of the packet according to user input
    uint8_t *payload = packet + 8;  // 8 = header_len of the packet, payload comes after

    if (options->padding && options->padding_len > 0) {
        for (size_t i = 0; i < options->packet_size; i++) {
            payload[i] = options->padding_bytes[i % options->padding_len];
        }
    }
    else {
        for (size_t i = 0; i < options->packet_size; i++) {
            payload[i] = i & 0xFF; // Sequential bytes (00 01 02 ...)
        }
    }

    icmp->checksum = checksum(packet, options->packet_size + 8);
}