//include/common_usr.h - common user-space definitions shared between user-space scripts (mostly printing functions)

#ifndef __COMMON_USR_H
#define __COMMON_USR_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sys/resource.h>
#include <net/if.h>

#include "common.h"



#define PRINT_ALL true //print all packet information, or only the packet numbers (used only in user-space)




//handle recieving network event function (prints packet info on terminal)
static int handle_event(void *ctx, void *data, size_t data_sz)
{

    const struct netevent *e = data;

    //add 1 to n_events which is contained in the context
    int *n_events = (int *)ctx;
    (*n_events)++;

    if (data_sz < sizeof(*e)) {
        fprintf(stderr, "Error: event size mismatch\n");
        return 0;
    }

    // Determine protocol string
    char protocol_str[16];
    if (e->protocol == 6) {
        strcpy(protocol_str, "TCP");
    } else if (e->protocol == 17) {
        strcpy(protocol_str, "UDP");
    } else {
        snprintf(protocol_str, sizeof(protocol_str), "%u", e->protocol);
    }

    if (PRINT_ALL) {
        //print informations (the IPs with dots for readability)
        printf("%-4i %-3u.%-3u.%-3u.%-3u:%-8u %-3u.%-3u.%-3u.%-3u:%-8u %-8s %-8u %-8u\n",
            *n_events,
            (e->src_ip) & 0xFF,
            (e->src_ip >> 8) & 0xFF,
            (e->src_ip >> 16) & 0xFF,
            (e->src_ip >> 24) & 0xFF,
            e->src_port,
            (e->dst_ip) & 0xFF,
            (e->dst_ip >> 8) & 0xFF,
            (e->dst_ip >> 16) & 0xFF,
            (e->dst_ip >> 24) & 0xFF,
            e->dst_port,
            protocol_str,
            e->packet_size,
            e->pid);
    } else {
        printf("%-4i\n", *n_events);
    }

    return 0;
}

#endif /* __COMMON_USR_H */