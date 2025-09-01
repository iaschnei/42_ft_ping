/*
Options : 

        -?      ->  Usage
        -v      -> Verbose output. ICMP packets other than ECHO_RESPONSE that are received are listed.
        -f      -> Flood ping. Outputs packets as fast as they come back or one hundred times per second, whichever is more. For every ECHO_REQUEST sent a period "." is printed, while for every ECHO_REPLY received a backspace is printed. This provides a rapid display of how many packets are being dropped. Only the super-user may use this option. This can be very hard on a network and should be used with caution.
        -l      -> preload If preload is specified, ping sends that many packets as fast as possible before falling into its normal mode of behavior.
        -n      -> Numeric output only. No attempt will be made to lookup symbolic names for host addresses.
        -w      -> Stop after N seconds of sending packets.
        -W      -> Number of seconds to wait for response
        -p      -> You may specify up to 16 "pad" bytes to fill out the packet you send. This is useful for diagnosing data-dependent problems in a network. For example, “-p ff” will cause the sent packet to be filled with all ones.
        -r      -> Bypass the normal routing tables and send directly to a host on an attached network. If the host is not on a directly-attached network, an error is returned. This option can be used to ping a local host through an interface that has no route through it (e.g., after the interface was dropped by routed(8)).
        -s      -> Specifies the number of data bytes to be sent. The default is 56, which translates into 64 ICMP data bytes when combined with the 8 bytes of ICMP header data.
        -T      -> Set num as the packet type of service (TOS).
        --ttl   -> Set N as the packet time-to-live.



        bool        verbose;
    bool        flood;
    int32_t     preload;
    bool        numeric_address_only;
    int32_t     global_timeout;
    int32_t     packet_timeout;
    bool        padding;
    u_int32_t   padding_value;
    bool        bypass_rooting;
    int32_t     packet_size;
    int32_t     type_of_service;
    int32_t     time_to_live;

*/

#include "ft_ping.h"

const char *help_message = "Try 'ping -?' for more information.";

char *resolve_ip_address(char *domain);

void    set_default_options(t_options *options) {
    options->verbose = false;
    options->preload = -1;
    options->numeric_address_only = false;
    options->global_timeout = -1;
    options->packet_timeout = 10;
    options->padding = false;
    options->padding_value = 0;
    options->bypass_rooting = false;
    options->packet_size = 56;
    options->type_of_service = 0;
    options->time_to_live = 64;
}

int parse_args(int ac, char **av, t_options *options, t_data *data) {

    if (ac == 1) {
        fprintf(stderr, "ft_ping: missing host operand\n%s\n", help_message);
        return (-1);
    }

    if (ac == 2) {
        if (av[1] == NULL) {
            fprintf(stderr, "ft_ping: invalid target domain or IPv4 address\n%s\n", help_message);
            return (-1);
        }

        struct in_addr ipv4;
        int is_ipv4 = inet_pton(AF_INET, av[1], &ipv4);

        if (is_ipv4 == 1) {
            data->target_address = av[1];
            data->target_domain_name = NULL;
        } else if (is_ipv4 == 0) {
            data->target_domain_name = av[1];
            data->target_address = resolve_ip_address(av[1]);
            if (data->target_address == NULL) {
                fprintf(stderr, "ft_ping: couldn't resolve IP address from given domain\n");
                return (-1);
            }
        } else {
            fprintf(stderr, "ft_ping: invalid target domain or IPv4 address\n%s\n", help_message);
            return (-1);
        }
        
        return (0);
    }

    for (int i = 2; i < ac - 1; i++) {
        
        if (strcmp(av[i], "-v") == 0) {
            options->verbose = true;
        }
        else if (strcmp(av[i], "-f") == 0) {
            options->flood = true;
        }
        else if (strcmp(av[i], "-n") == 0) {
            options->numeric_address_only = true;
        }
        else if (strcmp(av[i], "-r") == 0) {
            options->bypass_rooting = true;
        }
        /*
        else if (strcmp(av[i], "-r") == 0) {
            options->bypass_rooting = true;
        }
        */
        //TODO: Parse other options with option arguments
    }

    return (0);
}

// Find the ip address behind a domain name 
char *resolve_ip_address(char *domain) {
    struct addrinfo hints, *res;
    char ipstr[INET_ADDRSTRLEN];
    
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; // IPv4 only

    int err = getaddrinfo(domain, NULL, &hints, &res);
    if (err != 0) {
        fprintf(stderr, "ft_ping: %s: %s\n", domain, gai_strerror(err));
        return (NULL);
    }

    struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
    inet_ntop(AF_INET, &(ipv4->sin_addr), ipstr, sizeof ipstr);

    freeaddrinfo(res);

    return (strdup(ipstr));
}