#include "ft_ping.h"

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


    return (0);
}