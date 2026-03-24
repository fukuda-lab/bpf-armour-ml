/* SPDX-License-Identifier: GPL-2.0 */
#include <stdio.h>
#include <stdlib.h>
#include <linux/bpf.h>
#include "../lib/libbpf/src/bpf_endian.h"
#include "../lib/libbpf/src/bpf_helpers.h"
#include "../lib/libbpf/src/bpf_endian.h"
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdbool.h>
// #include "../lib/fixed-point/static-fixed-point.h"
#include "../lib/fixed-point/fixed-point.h"

#define invl_ns 1000000

#define LOGGER_MAP_SIZE 10000

struct log
{
    u_int64_t timestamp;
    int32_t src_address;
    int32_t dest_address;
    int8_t protocol;
    uint16_t src_port;
    uint16_t dest_port;
    bool is_fwd_packet;
    int16_t tcp_flags;
    int32_t packet_bytes;
};

struct blocklist_key
{
    __u32 prefixlen;
    __u32 address;
    int8_t protocol;
    uint16_t src_port;
    uint16_t dest_port;
};

struct network_segment_key
{
    __u32 prefixlen;
    __u32 address;
};

struct logger_key
{
    int32_t src_address;
    int32_t dest_address;
    int8_t protocol;
    uint16_t src_port;
    uint16_t dest_port;
};

struct logger_value
{
    u_int64_t fwd_packet_count;
    u_int64_t bwd_packet_count;

    u_int64_t min_packet_bytes;
    u_int64_t max_packet_bytes;
    u_int64_t ttl_packet_bytes;

    u_int64_t fwd_min_packet_bytes;
    u_int64_t fwd_max_packet_bytes;
    u_int64_t fwd_ttl_packet_bytes;

    u_int64_t bwd_min_packet_bytes;
    u_int64_t bwd_max_packet_bytes;
    u_int64_t bwd_ttl_packet_bytes;

    u_int64_t timestamp;

    u_int64_t min_iat;
    u_int64_t max_iat;
    u_int64_t ttl_iat;

    u_int64_t fwd_min_iat;
    u_int64_t fwd_max_iat;
    u_int64_t fwd_ttl_iat;

    u_int64_t bwd_min_iat;
    u_int64_t bwd_max_iat;
    u_int64_t bwd_ttl_iat;

    u_int64_t fwd_psh_flag_count;
    u_int64_t fwd_urg_flag_count;

    u_int64_t bwd_psh_flag_count;
    u_int64_t bwd_urg_flag_count;

    u_int64_t fin_flag_count;
    u_int64_t syn_flag_count;
    u_int64_t rst_flag_count;
    u_int64_t psh_flag_count;
    u_int64_t ack_flag_count;
    u_int64_t urg_flag_count;
    u_int64_t cwr_flag_count;
    u_int64_t ece_flag_count;

    u_int64_t fwd_ttl_header_length;
    u_int64_t bwd_ttl_header_length;

    u_int64_t fwd_ttl_segment_size;
    u_int64_t bwd_ttl_segment_size;

    u_int64_t fwd_act_data_pkt;
    u_int64_t bwd_act_data_pkt;

    u_int64_t fwd_seg_min;
    u_int64_t bwd_seg_min;

    int ttl_packet_count;

    struct fixed_point ttl_mean_packet_size;
    struct fixed_point fwd_mean_packet_size;
    struct fixed_point bwd_mean_packet_size;

    struct fixed_point ttl_packet_size_variance;
    struct fixed_point fwd_packet_size_variance;
    struct fixed_point bwd_packet_size_variance;

    struct fixed_point ttl_mean_iat;
    struct fixed_point fwd_mean_iat;
    struct fixed_point bwd_mean_iat;

    struct fixed_point ttl_iat_variance;
    struct fixed_point fwd_iat_variance;
    struct fixed_point bwd_iat_variance;
};

struct characteristics
{
    struct logger_value *logger_value;

    int ttl_iat;

    struct fixed_point fwd_mean_header_length;
    struct fixed_point bwd_mean_header_length;

    struct fixed_point fwd_mean_segemnt_size;
    struct fixed_point bwd_mean_segemnt_size;

    struct fixed_point ttl_std_dev_packet_size;
    struct fixed_point fwd_std_dev_packet_size;
    struct fixed_point bwd_std_dev_packet_size;

    struct fixed_point ttl_std_dev_iat;
    struct fixed_point fwd_std_dev_iat;
    struct fixed_point bwd_std_dev_iat;

    struct fixed_point up_down_ratio;

    struct fixed_point flow_bytes;
    struct fixed_point flow_packets;

    struct fixed_point fwd_flow_packets;
    struct fixed_point bwd_flow_packets;

    struct fixed_point mean_packet_size;
};

struct loc_ts
{
    struct bpf_spin_lock lock;
    int64_t timestamp;
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct logger_key);
    __type(value, struct logger_value);
    __uint(max_entries, LOGGER_MAP_SIZE);
} logger SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct blocklist_key);
    __type(value, __u32);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 10000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} blocklist SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct loc_ts);
    __uint(max_entries, 1);
} loc_ts SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} tx_port SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct network_segment_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 10);
} network_segment SEC(".maps");

int __always_inline add_blocklist(struct logger_key *logger_key, struct logger_value *logger_value)
{
    if (!logger_value)
    {
        return -1;
    }

    struct blocklist_key filter_key = {0};
    filter_key.prefixlen = 72;
    filter_key.address = logger_key->src_address;
    filter_key.protocol = logger_key->protocol;
    filter_key.src_port = logger_key->src_port;
    filter_key.dest_port = logger_key->dest_port;

    __u32 rule = 1;
    bpf_map_update_elem(&blocklist, &filter_key, &rule, BPF_ANY);

    return 1;
}

// Process log data and calculate characteristics
void __always_inline process_log(struct logger_value *logger_value, struct characteristics *characteristics)
{
    characteristics->logger_value = logger_value;
    characteristics->logger_value->ttl_packet_count = characteristics->logger_value->fwd_packet_count + characteristics->logger_value->bwd_packet_count;
    characteristics->ttl_iat = characteristics->logger_value->fwd_ttl_iat + characteristics->logger_value->bwd_ttl_iat;

    struct fixed_point tmp1;
    struct fixed_point tmp2;
    struct fixed_point duration;
    tmp1 = to_fixed_point(characteristics->logger_value->ttl_packet_count - 1, 8);
    tmp2 = characteristics->logger_value->ttl_mean_iat;
    duration = multiply(&tmp1, &tmp2);

    tmp1 = to_fixed_point(characteristics->logger_value->ttl_packet_bytes, 8);
    characteristics->flow_bytes = divide(&tmp1, &duration);

    tmp1 = to_fixed_point(characteristics->logger_value->ttl_packet_count, 8);
    characteristics->flow_packets = divide(&tmp1, &duration);

    tmp1 = to_fixed_point(characteristics->logger_value->fwd_packet_count, 8);
    characteristics->fwd_flow_packets = divide(&tmp1, &duration);

    tmp1 = to_fixed_point(characteristics->logger_value->bwd_packet_count, 8);
    characteristics->bwd_flow_packets = divide(&tmp1, &duration);
    tmp1 = to_fixed_point(characteristics->logger_value->fwd_ttl_header_length, 8);
    tmp2 = to_fixed_point(characteristics->logger_value->fwd_packet_count, 8);
    characteristics->fwd_mean_header_length = divide(&tmp1, &tmp2);

    tmp1 = to_fixed_point(characteristics->logger_value->bwd_ttl_header_length, 8);
    tmp2 = to_fixed_point(characteristics->logger_value->bwd_packet_count, 8);
    characteristics->bwd_mean_header_length = divide(&tmp1, &tmp2);

    tmp1 = to_fixed_point(characteristics->logger_value->fwd_ttl_segment_size, 8);
    tmp2 = to_fixed_point(characteristics->logger_value->fwd_packet_count, 8);
    characteristics->fwd_mean_segemnt_size = divide(&tmp1, &tmp2);

    tmp1 = to_fixed_point(characteristics->logger_value->bwd_ttl_segment_size, 8);
    tmp2 = to_fixed_point(characteristics->logger_value->bwd_packet_count, 8);
    characteristics->bwd_mean_segemnt_size = divide(&tmp1, &tmp2);

    // calculate std dev
    get_variance(&characteristics->logger_value->ttl_packet_size_variance, characteristics->logger_value->ttl_packet_count, &characteristics->logger_value->ttl_packet_size_variance);
    fixed_sqrt(&characteristics->logger_value->ttl_packet_size_variance, &characteristics->ttl_std_dev_packet_size);

    get_variance(&characteristics->logger_value->fwd_packet_size_variance, characteristics->logger_value->fwd_packet_count, &characteristics->logger_value->fwd_packet_size_variance);
    fixed_sqrt(&characteristics->logger_value->fwd_packet_size_variance, &characteristics->fwd_std_dev_packet_size);

    get_variance(&characteristics->logger_value->bwd_packet_size_variance, characteristics->logger_value->bwd_packet_count, &characteristics->logger_value->bwd_packet_size_variance);
    fixed_sqrt(&characteristics->logger_value->bwd_packet_size_variance, &characteristics->bwd_std_dev_packet_size);

    get_variance(&characteristics->logger_value->ttl_iat_variance, characteristics->logger_value->ttl_packet_count, &characteristics->logger_value->ttl_iat_variance);
    fixed_sqrt(&characteristics->logger_value->ttl_iat_variance, &characteristics->ttl_std_dev_iat);

    get_variance(&characteristics->logger_value->fwd_iat_variance, characteristics->logger_value->fwd_packet_count, &characteristics->logger_value->fwd_iat_variance);
    fixed_sqrt(&characteristics->logger_value->fwd_iat_variance, &characteristics->fwd_std_dev_iat);

    get_variance(&characteristics->logger_value->bwd_iat_variance, characteristics->logger_value->bwd_packet_count, &characteristics->logger_value->bwd_iat_variance);
    fixed_sqrt(&characteristics->logger_value->bwd_iat_variance, &characteristics->bwd_std_dev_iat);

    tmp1 = to_fixed_point(characteristics->logger_value->fwd_packet_count, 8);
    tmp2 = to_fixed_point(characteristics->logger_value->bwd_packet_count, 8);
    characteristics->up_down_ratio = divide(&tmp1, &tmp2);
}

static int detection(struct bpf_map *map, const struct logger_key *logger_key, struct logger_value *logger_value, const void *ctx)
{
    struct characteristics characteristics;
    process_log(logger_value, &characteristics);

    // Some detection algorithm goes here :D
    struct fixed_point root = {.number = 588840, .q = 16};
    struct fixed_point l1_1 = {.number = 1310, .q = 16};
    struct fixed_point l1_2 = {.number = 96823214, .q = 16};
    struct fixed_point l2_1 = {.number = 210042, .q = 16};
    struct fixed_point l2_2 = {.number = 1441, .q = 16};
    struct fixed_point l2_3 = {.number = 99680, .q = 16};
    struct fixed_point l3_1 = {.number = 917504, .q = 16};
    struct fixed_point l3_4 = {.number = 972881, .q = 16};
    struct fixed_point l3_5 = {.number = 867565, .q = 16};
    struct fixed_point l4_2 = {.number = 1203856539, .q = 16};
    struct fixed_point l4_5 = {.number = 55508, .q = 16};
    struct fixed_point l4_6 = {.number = 516096000, .q = 16};

    if (compare(&root, &logger_value->bwd_mean_packet_size))
    {
        if (compare(&l1_1, &characteristics.fwd_flow_packets))
        {
            if (compare(&l2_1, &characteristics.bwd_std_dev_packet_size))
            {
                if (compare(&l3_1, &characteristics.fwd_mean_segemnt_size))
                {
                    if (logger_value->fwd_act_data_pkt < 1)
                    {
                        // benign?
                    }
                    else
                    {
                        add_blocklist(logger_key, logger_value);
                    }
                }
                else if (compare(&l4_2, &logger_value->bwd_mean_iat))
                {
                    // benign?
                }
                else
                {
                    add_blocklist(logger_key, logger_value);
                }
            }
            else if (logger_value->fwd_seg_min < 4)
            {
                // skip l4
                add_blocklist(logger_key, logger_value);
            }
            else if (logger_value->bwd_max_iat < 9309402)
            {
                add_blocklist(logger_key, logger_value);
            }
        }
        else if (compare(&l2_2, &characteristics.bwd_flow_packets))
        {
            // benign
        }
        else if (compare(&l3_4, &characteristics.flow_bytes))
        {
            // benign
        }
        else
        {
            add_blocklist(logger_key, logger_value);
        }
    }
    else if (compare(&l1_2, &logger_value->fwd_mean_packet_size))
    {
        if (compare(&l2_3, &characteristics.up_down_ratio))
        {
            if (compare(&l3_5, &logger_value->bwd_mean_packet_size))
            {
                if (compare(&l4_5, &characteristics.up_down_ratio))
                {
                    add_blocklist(logger_key, logger_value);
                }
                else
                {
                    // benign?
                }
            }
            else if (compare(&l4_6, &characteristics.fwd_mean_segemnt_size))
            {
                // benign?
            }
            else
            {
                add_blocklist(logger_key, logger_value);
            }
        }
        else if (logger_value->bwd_ttl_header_length < 523)
        {
            if (logger_value->bwd_min_iat < 9301)
            {
                // benign?
            }
            else
            {
                add_blocklist(logger_key, logger_value);
            }
        }
        else if (logger_value->max_iat < 4004)
        {
            add_blocklist(logger_key, logger_value);
        }
        else
        {
            // benign?
        }
    }
    else if (logger_value->bwd_max_packet_bytes < 1132)
    {
        if (logger_value->fwd_seg_min < 4)
        {
            if (logger_value->fwd_ttl_packet_bytes < 132041)
            {
                // benign
            }
            else
            {
                add_blocklist(logger_key, logger_value);
            }
        }
        else
        {
            add_blocklist(logger_key, logger_value);
        }
    }
    return 0;
}

// checks whether the 1-sec interal has passed
int __always_inline check_timestamp(struct xdp_md *ctx, struct log *log)
{
    int key = 0;
    struct loc_ts *ts = bpf_map_lookup_elem(&loc_ts, &key);
    if (!ts)
    {
        return XDP_PASS;
    }
    else
    {
        // update timestamp
        bpf_spin_lock(&ts->lock);
        if (ts->timestamp == 0)
        {
            ts->timestamp = log->timestamp;
            bpf_spin_unlock(&ts->lock);
        }
        else if (log->timestamp > ts->timestamp + invl_ns)
        {
            ts->timestamp = log->timestamp;
            bpf_spin_unlock(&ts->lock);
            bpf_for_each_map_elem(&logger, detection, &key, 0);
        }
        else
        {
            bpf_spin_unlock(&ts->lock);
        }
    }
    return XDP_PASS;
}

int calculate_avg_variance(struct log *log, struct logger_value *logger_value)
{
    if (!log || !logger_value)
    {
        return -1;
    }
    static struct fixed_point tmp1;
    static struct fixed_point tmp2;

    tmp1 = to_fixed_point(logger_value->ttl_packet_bytes, 8);
    tmp2 = to_fixed_point(logger_value->ttl_packet_count, 8);
    logger_value->ttl_mean_packet_size = divide(&tmp1, &tmp2);

    tmp1 = to_fixed_point(log->packet_bytes, 8);
    variance(&tmp1, &tmp2, &logger_value->ttl_mean_packet_size, &logger_value->ttl_packet_size_variance);

    tmp1 = to_fixed_point(logger_value->ttl_iat, 8);
    tmp2 = to_fixed_point(logger_value->ttl_packet_count, 8);
    logger_value->ttl_mean_iat = divide(&tmp1, &tmp2);

    int32_t iat = log->timestamp - logger_value->timestamp;
    tmp1 = to_fixed_point(iat, 8);
    variance(&tmp1, &tmp2, &logger_value->ttl_mean_iat, &logger_value->ttl_iat_variance);

    if (!log->is_fwd_packet)
    {
        tmp1 = to_fixed_point(logger_value->fwd_ttl_packet_bytes, 8);
        tmp2 = to_fixed_point(logger_value->fwd_packet_count, 8);
        logger_value->fwd_mean_packet_size = divide(&tmp1, &tmp2);

        tmp1 = to_fixed_point(log->packet_bytes, 8);
        variance(&tmp1, &tmp2, &logger_value->fwd_mean_packet_size, &logger_value->fwd_packet_size_variance);

        tmp1 = to_fixed_point(logger_value->fwd_ttl_iat, 8);
        tmp2 = to_fixed_point(logger_value->fwd_packet_count, 8);
        logger_value->fwd_mean_iat = divide(&tmp1, &tmp2);

        tmp1 = to_fixed_point(iat, 8);
        variance(&tmp1, &tmp2, &logger_value->fwd_mean_iat, &logger_value->fwd_iat_variance);
    }
    else
    {
        tmp1 = to_fixed_point(logger_value->bwd_ttl_packet_bytes, 8);
        tmp2 = to_fixed_point(logger_value->bwd_packet_count, 8);
        logger_value->bwd_mean_packet_size = divide(&tmp1, &tmp2);

        tmp1 = to_fixed_point(log->packet_bytes, 8);
        variance(&tmp1, &tmp2, &logger_value->bwd_mean_packet_size, &logger_value->bwd_packet_size_variance);

        tmp1 = to_fixed_point(logger_value->bwd_ttl_iat, 8);
        tmp2 = to_fixed_point(logger_value->bwd_packet_count, 8);
        logger_value->bwd_mean_iat = divide(&tmp1, &tmp2);

        tmp1 = to_fixed_point(iat, 8);
        variance(&tmp1, &tmp2, &logger_value->bwd_mean_iat, &logger_value->bwd_iat_variance);
    }
    return 0;
}

// identifies the direction of the flow
int find_fwd_bwd_network(struct log *log)
{
    if (log == NULL)
    {
        return XDP_PASS;
    }

    struct network_segment_key ntwk_key;
    ntwk_key.prefixlen = 32;
    ntwk_key.address = log->src_address;

    int32_t fwd_addr;
    int32_t bwd_addr;

    __u8 *ntwk_rule = bpf_map_lookup_elem(&network_segment, &ntwk_key);
    // if src == fwd, dest == bwd
    if (ntwk_rule)
    {
        fwd_addr = log->src_address;
        bwd_addr = log->dest_address;
        log->is_fwd_packet = false;
    }
    else // if src == bwd, dest == fwd (store flow direction)
    {
        ntwk_key.address = log->dest_address;
        ntwk_rule = bpf_map_lookup_elem(&network_segment, &ntwk_key);
        if (ntwk_rule)
        {
            bwd_addr = log->src_address;
            fwd_addr = log->dest_address;
            log->is_fwd_packet = true;
        }
        else // Packet destination/source does not belog to this network, so let the kernel handle it
        {
            return XDP_PASS;
        }
    }

    return XDP_PASS;
}

// collect features
static void collect_log(struct xdp_md *ctx, struct log *log, struct logger_value *value)
{
    if (ctx == NULL || log == NULL || value == NULL)
    {
        return;
    }

    value->ttl_packet_bytes += log->packet_bytes;
    if (log->packet_bytes < value->min_packet_bytes)
    {
        value->min_packet_bytes = log->packet_bytes;
    }
    else if (log->packet_bytes > value->max_packet_bytes)
    {
        value->max_packet_bytes = log->packet_bytes;
    }

    if (log->tcp_flags & TH_FIN)
    {
        value->fin_flag_count += 1;
    }
    if (log->tcp_flags & TH_SYN)
    {
        value->syn_flag_count += 1;
    }
    if (log->tcp_flags & TH_RST)
    {
        value->rst_flag_count += 1;
    }
    if (log->tcp_flags & TH_PUSH)
    {
        value->psh_flag_count += 1;
    }
    if (log->tcp_flags & TH_ACK)
    {
        value->ack_flag_count += 1;
    }
    if (log->tcp_flags & TH_URG)
    {
        value->urg_flag_count += 1;
    }
    if (log->tcp_flags & 0b010000000)
    {
        value->cwr_flag_count += 1;
    }
    if (log->tcp_flags & 0b001000000)
    {
        value->ece_flag_count += 1;
    }

    u_int64_t iat = 0;
    
    iat = log->timestamp - value->timestamp;
    value->timestamp = log->timestamp;
    value->ttl_iat += iat;

    if (iat < value->min_iat)
    {
        value->min_iat = iat;
    }
    else if (iat > value->max_iat)
    {
        value->max_iat = iat;
    }

    // if fwd packet, then record it fwd_packet_count, fwd_packet_bytes, fwd_min_iat, fwd_max_iat, fwd_ttl_iat, fwd_psh_flag_count, fwd_urg_flag_count, fwd_ttl_segment_size, fwd_act_data_pkt, fwd_seg_min
    if (!log->is_fwd_packet)
    {
        value->fwd_packet_count += 1;

        value->fwd_ttl_packet_bytes += log->packet_bytes;
        if (log->packet_bytes < value->fwd_min_packet_bytes)
        {
            value->fwd_min_packet_bytes = log->packet_bytes;
            value->fwd_seg_min = log->packet_bytes;
        }
        else if (log->packet_bytes > value->fwd_max_packet_bytes)
        {
            value->fwd_max_packet_bytes = log->packet_bytes;
        }

        value->fwd_ttl_iat += iat;
        if (iat < value->fwd_min_iat)
        {
            value->fwd_min_iat = iat;
        }
        else if (iat > value->fwd_max_iat)
        {
            value->fwd_max_iat = iat;
        }

        if (log->tcp_flags & TH_PUSH)
        {
            value->fwd_psh_flag_count += 1;
        }
        if (log->tcp_flags & TH_URG)
        {
            value->fwd_urg_flag_count += 1;
        }

        value->fwd_ttl_segment_size += log->packet_bytes;
        if (log->packet_bytes > 0)
        {
            value->fwd_act_data_pkt += 1;
        }

        // int temp = ctx->data_end - ctx->data; // annoying but necessary workaround, to avoid error from verifier
        // temp = temp + 1;
        // if (log->packet_bytes > 0 && log->packet_bytes < 1500)
        // {
        //     temp = temp - log->packet_bytes - 1;
        //     value->fwd_ttl_header_length += temp;
        // }
    }
    else
    {
        // else, then do the same for bwd
        value->bwd_packet_count += 1;

        value->bwd_ttl_packet_bytes += log->packet_bytes;
        if (log->packet_bytes < value->bwd_min_packet_bytes)
        {
            value->bwd_min_packet_bytes = log->packet_bytes;
            value->bwd_seg_min = log->packet_bytes;
        }
        else if (log->packet_bytes > value->bwd_max_packet_bytes)
        {
            value->bwd_max_packet_bytes = log->packet_bytes;
        }

        value->bwd_ttl_iat += iat;
        if (iat < value->bwd_min_iat)
        {
            value->bwd_min_iat = iat;
        }
        else if (iat > value->bwd_max_iat)
        {
            value->bwd_max_iat = iat;
        }

        if (log->tcp_flags & TH_PUSH)
        {
            value->bwd_psh_flag_count += 1;
        }
        if (log->tcp_flags & TH_URG)
        {
            value->bwd_urg_flag_count += 1;
        }

        value->bwd_ttl_segment_size += log->packet_bytes;
        if (log->packet_bytes > 0)
        {
            value->bwd_act_data_pkt += 1;
        }

        // int temp = ctx->data_end - ctx->data; // To avoid error from verifier
        // temp = temp + 1;
        // if (log->packet_bytes > 0 && log->packet_bytes < 1500)
        // {
        //     temp = temp - log->packet_bytes - 1;
        //     value->bwd_ttl_header_length += temp;
        // }
    }

    calculate_avg_variance(log, value);

    value->timestamp = log->timestamp;
}

// store log into the BPF Map
int __always_inline store_log(struct xdp_md *ctx, struct log *log)
{
    int ret = find_fwd_bwd_network(log);
    if (ret == XDP_PASS)
    {
        struct logger_key logger_key = {0};
        if (log->is_fwd_packet)
        {
            logger_key.src_address = log->dest_address;
            logger_key.dest_address = log->src_address;
            logger_key.src_port = log->dest_port;
            logger_key.dest_port = log->src_port;
            logger_key.protocol = log->protocol;
        }
        else
        {
            logger_key.src_address = log->src_address;
            logger_key.dest_address = log->dest_address;
            logger_key.src_port = log->src_port;
            logger_key.dest_port = log->dest_port;
            logger_key.protocol = log->protocol;
        }

        struct logger_value *value = bpf_map_lookup_elem(&logger, &logger_key);
        if (value)
        {
            collect_log(ctx, log, value);
        }
        else
        {
            int key = 0;
            static struct logger_value init_value = {0};
            init_value.min_packet_bytes = INT32_MAX;
            init_value.fwd_min_packet_bytes = INT32_MAX;
            init_value.bwd_min_packet_bytes = INT32_MAX;
            init_value.min_iat = INT32_MAX;
            init_value.fwd_min_iat = INT32_MAX;
            init_value.bwd_min_iat = INT32_MAX;
            init_value.fwd_seg_min = INT32_MAX;
            init_value.bwd_seg_min = INT32_MAX;
            collect_log(ctx, log, &init_value);
            bpf_map_update_elem(&logger, &logger_key, &init_value, BPF_ANY);

        }
        check_timestamp(ctx, log);
    }
    return ret;
}

int search_blocklist(struct log *log)
{
    if (log)
    {
        struct blocklist_key filter_key;
        filter_key.prefixlen = 32;
        filter_key.address = log->src_address;
        filter_key.protocol = log->protocol;
        filter_key.src_port = log->src_port;
        filter_key.dest_port = log->dest_port;

        __u32 *rule = bpf_map_lookup_elem(&blocklist, &filter_key);
        if (rule)
        {
            // flow is on the blocklist, drop it
            return XDP_DROP;
        }
        else
        {
            return XDP_PASS;
        }
    }
    return XDP_PASS;
}

int __always_inline process_udphdr(struct xdp_md *ctx, struct log *log)
{
    // check whether packet data format follows the definition of udp packet header
    struct udphdr *udp = (void *)(long)ctx->data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    // drop the packet if it doesn`t
    if (ctx->data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(*udp) > ctx->data_end)
    {
        return XDP_PASS;
    }
    else
    {
        if (log)
        {
            log->protocol = 17;
            log->src_port = udp->source;
            log->dest_port = udp->dest;
            log->packet_bytes = (uint64_t)udp->uh_ulen - sizeof(struct udphdr);

            int ret = search_blocklist(log);
            if (ret == XDP_PASS)
            {
                ret = store_log(ctx, log);
                return ret;
            }
            else
            {
                return ret;
            }
        }
        return XDP_PASS;
    }
}

int __always_inline process_tcphdr(struct xdp_md *ctx, struct log *log)
{
    // check whether packet data format follows the definition of tcp packet header
    struct tcphdr *tcp = (void *)(long)ctx->data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    // drop the packet if it doesn`t
    int ret = XDP_PASS;
    if (ctx->data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > ctx->data_end)
    {
        return XDP_PASS;
    }
    else
    {
        if (log)
        {
            log->src_port = ntohs(tcp->source);
            log->dest_port = ntohs(tcp->dest);
            log->protocol = 6;
            log->tcp_flags = ntohs(tcp->th_flags);
            log->packet_bytes = log->packet_bytes - (tcp->doff * 4);

            int ret = search_blocklist(log);
            if (ret == XDP_PASS)
            {
                return store_log(ctx, log);
            }
        }
    }
    return ret;
}

int __always_inline process_iphdr(struct xdp_md *ctx, struct log *log)
{
    // checks whether packet data format follows the definition of ip packet header
    struct iphdr *ip = (void *)(long)ctx->data + sizeof(struct ethhdr);
    // drop the packet if it doesn't
    if (ctx->data + sizeof(struct ethhdr) + sizeof(*ip) > ctx->data_end)
    {
        return XDP_PASS;
    }
    else
    {
        if (log)
        {
            log->dest_address = ip->daddr;
            log->src_address = ip->saddr;
            log->protocol = ip->protocol;
            log->packet_bytes = bpf_ntohs(ip->tot_len);
            if (ip->protocol == 6) // Send to TCP processor
            {
                return process_tcphdr(ctx, log);
            }
            else if (ip->protocol == 17) // Send to UDP processor
            {
                return process_udphdr(ctx, log);
            }
            else // If packet is nor TCP or UDP, check blocklist with ports as 0
            {
                log->src_port = 0;
                log->dest_port = 0;
                int ret = search_blocklist(log);
                if (ret == XDP_DROP)
                {
                    return XDP_DROP;
                }
                else if (ret == XDP_PASS)
                {
                    return store_log(ctx, log);
                }
                else
                {
                    return ret;
                }
            }
        }
        return XDP_PASS;
    }
}

int __always_inline process_ethhdr(struct xdp_md *ctx, struct log *log)
{
    // checks whether packet data format follows the definition of ethernet frame header
    struct ethhdr *eth = (void *)(long)ctx->data;
    // drop the packet if it doesn't
    if (ctx->data + sizeof(*eth) > ctx->data_end)
    {
        return XDP_PASS;
    }
    else
    {
        if (eth->h_proto == bpf_htons(ETH_P_IP))
        {
            return process_iphdr(ctx, log);
        }
    }
    return XDP_PASS;
}

SEC("xdp") // This is the typical "main" function replacement.
int xdp_filter_func(struct xdp_md *ctx)
{
    struct log log = {0};
    // struct log *log = &log_data;
    log.timestamp = bpf_ktime_get_ns() / 1000;

    process_ethhdr(ctx, &log);
    // process_ethhdr(ctx, *log);

    // return bpf_redirect_map(&tx_port, 0, 0);
    return XDP_TX;
}
char _license[] SEC("license") = "GPL";
