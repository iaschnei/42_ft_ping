#include "ft_ping.h"
#include <stdint.h>

uint16_t    checksum(void *b, int len);
void        build_icmp_packet(t_icmp *icmp, uint8_t *packet, t_options *options);
void        ping_loop(int sockfd, struct sockaddr_in *target, t_options *options, const char *hostname);

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

    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));

    target_addr.sin_family = AF_INET;

    // Convert the string IP address to binary
    if (inet_pton(AF_INET, data.target_address, &target_addr.sin_addr) != 1) {
        fprintf(stderr, "ft_ping: invalid IPv4 address: %s\n", data.target_address);
        return 1;
    }

    printf("PING %s (%s): %d data bytes\n",
    data.target_domain_name ? data.target_domain_name : data.target_address,
    data.target_address,
    options.packet_size);

    ping_loop(sockfd, &target_addr, &options, data.target_domain_name ? data.target_domain_name : data.target_address);

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


static int running = 1;

void handle_sigint(int sig) {
    (void)sig;
    running = 0;
}

// Returns time in ms
long time_diff_ms(struct timeval *start, struct timeval *end) {
    return (end->tv_sec - start->tv_sec) * 1000L + (end->tv_usec - start->tv_usec) / 1000L;
}

void ping_loop(int sockfd, struct sockaddr_in *target, t_options *options, const char *hostname) {
    t_stats stats = {0};
    struct timeval start_time, now;

    signal(SIGINT, handle_sigint);
    gettimeofday(&start_time, NULL);

    int sequence = 0;
    uint8_t *packet = calloc(1, 8 + options->packet_size);
    if (!packet) {
        perror("calloc");
        return;
    }

    t_icmp *icmp = (t_icmp *) packet;

    while (running) {
        gettimeofday(&now, NULL);
        if (options->global_timeout > 0 &&
            time_diff_ms(&start_time, &now) >= options->global_timeout * 1000)
            break;

        build_icmp_packet(icmp, packet, options);
        icmp->sequence = htons(sequence++);
        icmp->checksum = 0;
        icmp->checksum = checksum(packet, 8 + options->packet_size);

        struct timeval send_time;
        gettimeofday(&send_time, NULL);
        sendto(sockfd, packet, 8 + options->packet_size, 0,
               (struct sockaddr *)target, sizeof(*target));
        stats.packets_sent++;

        uint8_t recv_buf[1024];
        struct sockaddr_in recv_addr;
        socklen_t addr_len = sizeof(recv_addr);
        ssize_t bytes_received;

        struct timeval timeout = {.tv_sec = options->packet_timeout, .tv_usec = 0};
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

        bytes_received = recvfrom(sockfd, recv_buf, sizeof(recv_buf), 0,
                                  (struct sockaddr *)&recv_addr, &addr_len);
        struct timeval recv_time;
        gettimeofday(&recv_time, NULL);

        if (bytes_received < 0) {
            if (!options->flood) {
                printf("Request timeout for icmp_seq %d\n", sequence - 1);
            }
        } else {
            struct ip *ip_hdr = (struct ip *) recv_buf;
            int ip_header_len = ip_hdr->ip_hl << 2;
            struct icmp *icmp_reply = (struct icmp *)(recv_buf + ip_header_len);

            if (icmp_reply->icmp_type == ICMP_ECHOREPLY) {
                stats.packets_received++;

                long rtt = time_diff_ms(&send_time, &recv_time);
                if (stats.rtt_min == 0 || rtt < stats.rtt_min) stats.rtt_min = rtt;
                if (rtt > stats.rtt_max) stats.rtt_max = rtt;
                stats.rtt_sum += rtt;
                stats.rtt_sum_squared += rtt * rtt;

                if (!options->flood) {
                    printf("%ld bytes from %s: icmp_seq=%d ttl=%d time=%ld ms\n",
                           bytes_received - ip_header_len,
                           inet_ntoa(recv_addr.sin_addr),
                           ntohs(icmp_reply->icmp_seq),
                           ip_hdr->ip_ttl,
                           rtt);
                } else {
                    write(1, "\b", 1);
                }
            } else if (options->verbose) {
                printf("Received non-echo reply: type=%d code=%d\n",
                       icmp_reply->icmp_type, icmp_reply->icmp_code);
            }
        }

        if (!options->flood)
            sleep(1);
        else
            usleep(10000);  // Still add a small delay to prevent ddos detection and / or program crash :)
    }

    free(packet);

    // Print final statistics  (only rough format because we don't have access to math library)
    printf("\n--- %s ping statistics ---\n", hostname);
    printf("%d packets transmitted, %d packets received, %.0f%% packet loss\n",
           stats.packets_sent,
           stats.packets_received,
           stats.packets_sent > 0 ?
           (100.0 * (stats.packets_sent - stats.packets_received) / stats.packets_sent) : 0);

    if (stats.packets_received > 0) {
        double avg = stats.rtt_sum / (double)stats.packets_received;

        printf("round-trip min/avg/max = %ld/%.3f/%ld ms\n",
            stats.rtt_min,
            avg,
            stats.rtt_max);
    }
}