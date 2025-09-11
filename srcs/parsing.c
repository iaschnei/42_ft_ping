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
        -s      -> Specifies the number of data bytes to be sent. The default is 56, which translates into 64 ICMP data bytes when combined with the 8 bytes of ICMP header data.
        --ttl   -> Set N as the packet time-to-live.  (each time the packet is transmitted to an element in the network, this number goes down. When it reaches 0, drop the packet)



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
    int32_t     time_to_live;

*/

#include "ft_ping.h"
#include <ctype.h>
#include <string.h>
#include <sys/types.h>

const char *help_message = "Try 'ping -?' for more information.";

const char *usage_message = "Usage: ping [OPTION...] HOST ... \n\
Send ICMP ECHO_REQUEST packets to network hosts.\n\
\n\
  -n                         do not resolve host addresses\n\
  -r                         send directly to a host on an attached network\n\
  --ttl=N                    specify N as time-to-live\n\
  -v                         verbose output\n\
  -w                         stop after N seconds\n\
  -W                         number of seconds to wait for response\n\
  -f                         flood ping (root only)\n\
  -l                         send NUMBER packets as fast as possible before\n\
                             falling into normal mode of behavior (root only)\n\
  -p                         fill ICMP packet with given pattern (hex)\n\
  -s                         send NUMBER data octets\n\
\n\
  -?                         give this help list";

char *resolve_ip_address(char *domain);
bool is_str_number(const char *str);

void    set_default_options(t_options *options) {
    options->verbose = false;
    options->flood = false;
    options->preload = 0;
    options->numeric_address_only = false;
    options->global_timeout = -1;
    options->packet_timeout = 1;
    options->padding = false;
    options->padding_len = 0;
    options->bypass_rooting = false;
    options->packet_size = 56;
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

        if (strcmp(av[1], "-?") == 0) {
            fprintf(stdout, "%s\n", usage_message);
            return (2);
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

    for (int i = 1; i < ac; i++) {

        if (strcmp(av[i], "-?") == 0) {
            fprintf(stdout, "%s\n", usage_message);
            return (2);
        }
        
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
        else if (strcmp(av[i], "-l") == 0) {
            if (i == ac - 1) {
                fprintf(stderr, "ft_ping: expected number after '-l' option, use -? for more information\n");
                return (-1);
            }
            i++;
            if (!is_str_number(av[i])) {
                fprintf(stderr, "ft_ping: expected number after '-l' option, use -? for more information\n");
                return (-1);
            }
            options->preload = atoi(av[i]);
        }
        else if (strcmp(av[i], "-w") == 0) {
            if (i == ac - 1) {
                fprintf(stderr, "ft_ping: expected number after '-w' option, use -? for more information\n");
                return (-1);
            }
            i++;
            if (!is_str_number(av[i])) {
                fprintf(stderr, "ft_ping: expected number after '-w' option, use -? for more information\n");
                return (-1);
            }
            options->global_timeout = atoi(av[i]);
        }
        else if (strcmp(av[i], "-W") == 0) {
            if (i == ac - 1) {
                fprintf(stderr, "ft_ping: expected number after '-W' option, use -? for more information\n");
                return (-1);
            }
            i++;
            if (!is_str_number(av[i])) {
                fprintf(stderr, "ft_ping: expected number after '-W' option, use -? for more information\n");
                return (-1);
            }
            options->packet_timeout = atoi(av[i]);
        }
        else if (strcmp(av[i], "-p") == 0) {
            if (i == ac - 1) {
                fprintf(stderr, "ft_ping: expected hexa value (max 16 bytes) after '-p' option, use -? for more information\n");
                return (-1);
            }
            i++;
            size_t len = strlen(av[i]);
            if (len > 32 || len % 2 != 0) {
                fprintf(stderr, "ft_ping: expected even-length hexa string (max 16 bytes), use -? for more information\n");
                return (-1);
            }
            for (size_t j = 0; j < len; ++j) {
                if (!isxdigit(av[i][j])) {
                    fprintf(stderr, "ft_ping: invalid hex digit in padding string\n");
                    return (-1);
                }
            }

            options->padding = true;
            options->padding_len = len / 2;
            
            for (size_t j = 0; j < len; j += 2) {
                char byte_str[3] = { av[i][j], av[i][j+1], '\0' };
                options->padding_bytes[j/2] = (uint8_t)strtoul(byte_str, NULL, 16);
            }
        }
        else if (strcmp(av[i], "-s") == 0) {
            if (i == ac - 1) {
                fprintf(stderr, "ft_ping: expected number after '-s' option, use -? for more information\n");
                return (-1);
            }
            i++;
            if (!is_str_number(av[i])) {
                fprintf(stderr, "ft_ping: expected number after '-s' option, use -? for more information\n");
                return (-1);
            }
            if (atoi(av[i]) > 56) {
                fprintf(stderr, "ft_ping: max packet size is 56, use -? for more information\n");
                return (-1);
            }

            options->packet_size = atoi(av[i]);
        }
        else if (strcmp(av[i], "--ttl") == 0) {
            if (i == ac - 1) {
                fprintf(stderr, "ft_ping: expected number after '--ttl' option, use -? for more information\n");
                return (-1);
            }
            i++;
            if (!is_str_number(av[i])) {
                fprintf(stderr, "ft_ping: expected number after '--ttl' option, use -? for more information\n");
                return (-1);
            }

            options->time_to_live = atoi(av[i]);
        }
        else {
            if (av[i] == NULL) {
                fprintf(stderr, "ft_ping: invalid target domain or IPv4 address\n%s\n", help_message);
                return (-1);
            }

            struct in_addr ipv4;
            int is_ipv4 = inet_pton(AF_INET, av[i], &ipv4);

            if (is_ipv4 == 1) {
                data->target_address = av[i];
                data->target_domain_name = NULL;
            } else if (is_ipv4 == 0) {
                data->target_domain_name = av[i];
                data->target_address = resolve_ip_address(av[i]);
                if (data->target_address == NULL) {
                    fprintf(stderr, "ft_ping: couldn't resolve IP address from given domain\n");
                    return (-1);
                }
            } else {
                fprintf(stderr, "ft_ping: invalid target domain or IPv4 address\n%s\n", help_message);
                return (-1);
            }
        }
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

bool is_str_number(const char *str) {
    if (*str == '\0') return false;
    while (*str) {
        if (!isdigit(*str))
            return false;
        str++;
    }
    return true;
}