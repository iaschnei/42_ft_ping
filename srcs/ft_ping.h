#ifndef FT_PING_H
#define FT_PING_H

#include <sys/types.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>


typedef struct s_options {

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
} t_options;

typedef struct s_data {

    char    *target_address;
    char    *target_domain_name;
} t_data;


#endif