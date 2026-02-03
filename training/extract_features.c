#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <stdbool.h>

#include <pcap.h>

// #include "static-fixed.h"

#include "fixed-point.h"

// #include "floating-point.h"

#include "hashmap.h"

#define PCAP_BUF_SIZE 1024

struct key
{
    int32_t src_address;
    int32_t dest_address;
    uint16_t src_port;
    uint16_t dest_port;
    int8_t protocol;
};

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

struct logger_value
{
    struct key key;
    struct log log;
    uint64_t fwd_packet_count;
    uint64_t bwd_packet_count;

    uint64_t min_packet_bytes;
    uint64_t max_packet_bytes;
    uint64_t ttl_packet_bytes;

    uint64_t fwd_min_packet_bytes;
    uint64_t fwd_max_packet_bytes;
    uint64_t fwd_ttl_packet_bytes;

    uint64_t bwd_min_packet_bytes;
    uint64_t bwd_max_packet_bytes;
    uint64_t bwd_ttl_packet_bytes;

    int64_t timestamp;

    uint64_t min_iat;
    uint64_t max_iat;
    uint64_t ttl_iat;

    uint64_t fwd_min_iat;
    uint64_t fwd_max_iat;
    uint64_t fwd_ttl_iat;

    uint64_t bwd_min_iat;
    uint64_t bwd_max_iat;
    uint64_t bwd_ttl_iat;

    uint64_t fwd_psh_flag_count;
    uint64_t fwd_urg_flag_count;

    uint64_t bwd_psh_flag_count;
    uint64_t bwd_urg_flag_count;

    uint64_t fin_flag_count;
    uint64_t syn_flag_count;
    uint64_t rst_flag_count;
    uint64_t psh_flag_count;
    uint64_t ack_flag_count;
    uint64_t urg_flag_count;
    uint64_t cwr_flag_count;
    uint64_t ece_flag_count;

    // insert fwd/bwd header length
    uint64_t fwd_ttl_header_length;
    uint64_t bwd_ttl_header_length;

    uint64_t fwd_ttl_segment_size;
    uint64_t bwd_ttl_segment_size;

    uint64_t fwd_act_data_pkt;
    uint64_t bwd_act_data_pkt;

    uint64_t fwd_seg_min;
    uint64_t bwd_seg_min;

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
    bool is_updated[8];
};

struct characteristics
{
    struct logger_value logger_value;

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


void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet);
int calculate_avg_variance(struct log *log, struct logger_value *logger_value);
static void collect_log(struct log *log, struct logger_value *value);

bool extract(const void *item, void *udata);

static bool endOfInterval;
static u_int64_t startOfThisInterval;

static struct hashmap *logger_value;
static struct hashmap *blocklist_map;

uint64_t log_hash(const void *item, uint64_t seed0, uint64_t seed1)
{
    const struct logger_value *log = item;
    return hashmap_sip(&log->key, sizeof(struct key), seed0, seed1);
}

int log_compare(const void *a, const void *b, void *udata)
{
    const struct logger_value *ua = a;
    const struct logger_value *ub = b;
    return memcmp(&ua->key, &ub->key, sizeof(struct key));
}

static int logger_counter = 0;
static int lines_processed = 0;

int main(int argc, char **argv)
{
    endOfInterval = true;
    startOfThisInterval = 0;

    logger_value = hashmap_new(sizeof(struct logger_value), 10, 0, 0, log_hash, log_compare, NULL, NULL);
    blocklist_map = hashmap_new(sizeof(struct logger_value), 10, 0, 0, log_hash, log_compare, NULL, NULL);

    if (logger_value == NULL)
    {
        fprintf(stderr, "Error creating hashmap\n");
        return -1;
    }

    if (blocklist_map == NULL)
    {
        fprintf(stderr, "Error creating hashmap\n");
        return -1;
    }

    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    char source[PCAP_BUF_SIZE];
    int i, maxCountSyn = 0, maxCountHttp = 0, maxIdxSyn = 0, maxIdxHttp = 0;

    if (argc != 2)
    {
        printf("usage: %s filename\n", argv[0]);
        return -1;
    }

    fp = pcap_open_offline(argv[1], errbuf);
    if (fp == NULL)
    {
        fprintf(stderr, "\npcap_open_offline() failed: %s\n", errbuf);
        return 0;
    }

    if (pcap_loop(fp, 0, packetHandler, NULL) < 0)
    {
        fprintf(stderr, "\npcap_loop() failed: %s\n", pcap_geterr(fp));
        return 0;
    }

    hashmap_scan(logger_value, extract, NULL);
    hashmap_free(blocklist_map);
    hashmap_free(logger_value);
    return 0;
}

void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    struct log log = {0};
    const struct ether_header *ethernetHeader;
    const struct ip *ipHeader;
    const struct tcphdr *tcpHeader;
    const struct udphdr *udpHeader;
    char sourceIP[INET_ADDRSTRLEN];
    char destIP[INET_ADDRSTRLEN];
    u_int sourcePort, destPort;
    u_char *data;
    int dataLength = 0;
    int i;

    if (endOfInterval)
    {
        startOfThisInterval = pkthdr->ts.tv_sec * 1000000 + pkthdr->ts.tv_usec;
        endOfInterval = false;
    }

    ethernetHeader = (struct ether_header *)packet;
    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP)
    {

        ipHeader = (struct ip *)(packet + sizeof(struct ether_header));
        inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIP, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), destIP, INET_ADDRSTRLEN);

        log.src_address = ntohl(ipHeader->ip_src.s_addr);
        log.dest_address = ntohl(ipHeader->ip_dst.s_addr);

        if (ipHeader->ip_p == IPPROTO_TCP)
        {
            tcpHeader = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            log.protocol = IPPROTO_TCP;
            log.src_port = ntohs(tcpHeader->source);
            log.dest_port = ntohs(tcpHeader->dest);
            log.tcp_flags = ntohs(tcpHeader->th_flags);
            log.packet_bytes = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
            log.timestamp = (pkthdr->ts.tv_sec * 1000 )+ (pkthdr->ts.tv_usec / 1000);
        }
        else if (ipHeader->ip_p == IPPROTO_UDP)
        {
            udpHeader = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            log.protocol = IPPROTO_UDP;
            log.src_port = ntohs(udpHeader->source);
            log.dest_port = ntohs(udpHeader->dest);
            // log.tcp_flags = tcpHeader->th_flags;
            log.packet_bytes = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
            log.timestamp = pkthdr->ts.tv_sec * 1000 + pkthdr->ts.tv_usec / 1000;
        }

        struct key key = {0};

        switch (log.src_address)
        {
        case 3232238130:
        case 3450774852:
        case 3232238131:
        case 3450774850:
        case 3232238099:
        case 3232238097:
        case 3232238096:
        case 3232238092:
        case 3232238089:
        case 3232238085:
        case 3232238088:
        case 3232238094:
        case 3232238095:
        case 3232238105:
            log.is_fwd_packet = false;
            key.src_address = log.src_address;
            key.dest_address = log.dest_address;
            key.src_port = log.src_port;
            key.dest_port = log.dest_port;
            key.protocol = log.protocol;
            break;
        default:
            log.is_fwd_packet = true;
            key.src_address = log.dest_address;
            key.dest_address = log.src_address;
            key.src_port = log.dest_port;
            key.dest_port = log.src_port;
            key.protocol = log.protocol;
            log.src_port = key.src_port;
            log.dest_port = key.dest_port;
        }

        struct logger_value value = {0};
        value.log = log;
        value.key = key;

        struct logger_value *temp = hashmap_get(logger_value, &value.key);
        if (!temp)
        {
            hashmap_set(logger_value, &value);
            collect_log(&log, &value);
        }
        else
        {
            collect_log(&log, temp);
        }
    }
}

void __always_inline process_log(struct logger_value logger_value, struct characteristics *characteristics)
{
    characteristics->logger_value = logger_value;
    characteristics->ttl_iat = characteristics->logger_value.fwd_ttl_iat + characteristics->logger_value.bwd_ttl_iat;

    struct fixed_point tmp1;
    struct fixed_point tmp2;

    static struct fixed_point duration;
    tmp1 = to_fixed_point(characteristics->logger_value.ttl_packet_count - 1, 8);
    tmp2 = characteristics->logger_value.ttl_mean_iat;
    duration = multiply(tmp1, tmp2);

    tmp1 = to_fixed_point(characteristics->logger_value.ttl_packet_bytes, 8);
    characteristics->flow_bytes = divide(tmp1, duration);

    tmp1 = to_fixed_point(characteristics->logger_value.ttl_packet_count, 8);
    characteristics->flow_packets = divide(tmp1, duration);

    tmp1 = to_fixed_point(characteristics->logger_value.fwd_packet_count, 8);
    characteristics->fwd_flow_packets = divide(tmp1, duration);

    tmp1 = to_fixed_point(characteristics->logger_value.bwd_packet_count, 8);
    characteristics->bwd_flow_packets = divide(tmp1, duration);

    tmp1 = to_fixed_point(characteristics->logger_value.fwd_ttl_header_length, 8);
    tmp2 = to_fixed_point(characteristics->logger_value.fwd_packet_count, 8);
    characteristics->fwd_mean_header_length = divide(tmp1, tmp2);

    tmp1 = to_fixed_point(characteristics->logger_value.bwd_ttl_header_length, 8);
    tmp2 = to_fixed_point(characteristics->logger_value.bwd_packet_count, 8);
    characteristics->bwd_mean_header_length = divide(tmp1, tmp2);

    tmp1 = to_fixed_point(characteristics->logger_value.fwd_ttl_segment_size, 8);
    tmp2 = to_fixed_point(characteristics->logger_value.fwd_packet_count, 8);
    characteristics->fwd_mean_segemnt_size = divide(tmp1, tmp2);

    tmp1 = to_fixed_point(characteristics->logger_value.bwd_ttl_segment_size, 8);
    tmp2 = to_fixed_point(characteristics->logger_value.bwd_packet_count, 8);
    characteristics->bwd_mean_segemnt_size = divide(tmp1, tmp2);

    // calculate std dev
    get_variance(&characteristics->logger_value.ttl_packet_size_variance, characteristics->logger_value.ttl_packet_count, &characteristics->logger_value.ttl_packet_size_variance);
    fixed_sqrt(characteristics->logger_value.ttl_packet_size_variance, &characteristics->ttl_std_dev_packet_size);

    get_variance(&characteristics->logger_value.fwd_packet_size_variance, characteristics->logger_value.fwd_packet_count, &characteristics->logger_value.fwd_packet_size_variance);
    fixed_sqrt(characteristics->logger_value.fwd_packet_size_variance, &characteristics->fwd_std_dev_packet_size);

    get_variance(&characteristics->logger_value.bwd_packet_size_variance, characteristics->logger_value.bwd_packet_count, &characteristics->logger_value.bwd_packet_size_variance);
    fixed_sqrt(characteristics->logger_value.bwd_packet_size_variance, &characteristics->bwd_std_dev_packet_size);

    get_variance(&characteristics->logger_value.ttl_iat_variance, characteristics->logger_value.ttl_packet_count, &characteristics->logger_value.ttl_iat_variance);
    fixed_sqrt(characteristics->logger_value.ttl_iat_variance, &characteristics->ttl_std_dev_iat);

    get_variance(&characteristics->logger_value.fwd_iat_variance, characteristics->logger_value.fwd_packet_count, &characteristics->logger_value.fwd_iat_variance);
    fixed_sqrt(characteristics->logger_value.fwd_iat_variance, &characteristics->fwd_std_dev_iat);

    get_variance(&characteristics->logger_value.bwd_iat_variance, characteristics->logger_value.bwd_packet_count, &characteristics->logger_value.bwd_iat_variance);
    fixed_sqrt(characteristics->logger_value.bwd_iat_variance, &characteristics->bwd_std_dev_iat);

    tmp1 = to_fixed_point(characteristics->logger_value.fwd_packet_count, 8);
    tmp2 = to_fixed_point(characteristics->logger_value.bwd_packet_count, 8);
    characteristics->up_down_ratio = divide(tmp1, tmp2);

    if (characteristics->up_down_ratio.number == 0 && tmp1.number == 0)
    {
        characteristics->up_down_ratio = to_fixed_point(1, 8);
    }
    else if (characteristics->up_down_ratio.number < 0)
    {
        characteristics->up_down_ratio.number = -characteristics->up_down_ratio.number;
    }
}

int calculate_avg_variance(struct log *log, struct logger_value *logger_value)
{
    if (!log || !logger_value)
    {
        return -1;
    }
    static struct fixed_point tmp1;
    static struct fixed_point tmp2;

    logger_value->ttl_packet_count = logger_value->fwd_packet_count + logger_value->bwd_packet_count;

    tmp1 = to_fixed_point(logger_value->ttl_packet_bytes, 8);
    tmp2 = to_fixed_point(logger_value->ttl_packet_count, 8);
    logger_value->ttl_mean_packet_size = divide(tmp1, tmp2);

    tmp1 = to_fixed_point(log->packet_bytes, 8);
    variance(tmp1, tmp2, logger_value->ttl_mean_packet_size, &logger_value->ttl_packet_size_variance);

    tmp1 = to_fixed_point(logger_value->ttl_iat, 8);
    tmp2 = to_fixed_point(logger_value->ttl_packet_count, 8);
    logger_value->ttl_mean_iat = divide(tmp1, tmp2);

    int32_t iat = (log->timestamp - logger_value->timestamp);
    tmp1 = to_fixed_point(iat, 8);
    tmp2 = to_fixed_point(logger_value->ttl_packet_count, 8);
    variance(tmp1, tmp2, logger_value->ttl_mean_iat, &logger_value->ttl_iat_variance);

    if (!log->is_fwd_packet)
    {
        tmp1 = to_fixed_point(logger_value->fwd_ttl_packet_bytes, 8);
        tmp2 = to_fixed_point(logger_value->fwd_packet_count, 8);
        logger_value->fwd_mean_packet_size = divide(tmp1, tmp2);

        tmp1 = to_fixed_point(log->packet_bytes, 8);
        variance(tmp1, tmp2, logger_value->fwd_mean_packet_size, &logger_value->fwd_packet_size_variance);

        tmp1 = to_fixed_point(logger_value->fwd_ttl_iat, 8);
        tmp2 = to_fixed_point(logger_value->fwd_packet_count, 8);
        logger_value->fwd_mean_iat = divide(tmp1, tmp2);

        tmp1 = to_fixed_point(iat, 8);
        tmp2 = to_fixed_point(logger_value->fwd_packet_count, 8);
        variance(tmp1, tmp2, logger_value->fwd_mean_iat, &logger_value->fwd_iat_variance);
    }
    else
    {
        tmp1 = to_fixed_point(logger_value->bwd_ttl_packet_bytes, 8);
        tmp2 = to_fixed_point(logger_value->bwd_packet_count, 8);
        logger_value->bwd_mean_packet_size = divide(tmp1, tmp2);

        tmp1 = to_fixed_point(log->packet_bytes, 8);
        variance(tmp1, tmp2, logger_value->bwd_mean_packet_size, &logger_value->bwd_packet_size_variance);

        tmp1 = to_fixed_point(logger_value->bwd_ttl_iat, 8);
        tmp2 = to_fixed_point(logger_value->bwd_packet_count, 8);
        logger_value->bwd_mean_iat = divide(tmp1, tmp2);

        tmp1 = to_fixed_point(iat, 8);
        tmp2 = to_fixed_point(logger_value->bwd_packet_count, 8);
        variance(tmp1, tmp2, logger_value->bwd_mean_iat, &logger_value->bwd_iat_variance);
    }
    return 0;
}

void collect_log(struct log *log, struct logger_value *value)
{
    value->ttl_packet_bytes += log->packet_bytes;
    if (log->packet_bytes < value->min_packet_bytes)
    {
        value->min_packet_bytes = log->packet_bytes;
    }
    else if (value->is_updated[6] == false)
    {
        value->min_packet_bytes = log->packet_bytes;
        value->is_updated[6] = true;
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

    int64_t iat = 0;

    if (value->timestamp == 0)
    {
        value->timestamp = log->timestamp;
    }
    else
    {
        iat = (log->timestamp - value->timestamp);
    }
    value->ttl_iat += iat;
    if (iat < value->min_iat)
    {
        value->min_iat = iat;
    }
    else if (value->is_updated[2] == false)
    {
        value->min_iat = iat;
        value->is_updated[2] = true;
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
        else if (value->is_updated[0] == false)
        {
            value->fwd_min_packet_bytes = log->packet_bytes;
            value->is_updated[0] = true;
        }
        else if (log->packet_bytes > value->fwd_max_packet_bytes)
        {
            value->fwd_max_packet_bytes = log->packet_bytes;
        }

        value->fwd_ttl_iat += iat;
        if (value->timestamp != 0)
        {
            if (iat < value->fwd_min_iat)
            {
                value->fwd_min_iat = iat;
            }
            else if (value->is_updated[3] == false)
            {
                value->fwd_min_iat = iat;
                value->is_updated[3] = true;
            }
            else if (iat > value->fwd_max_iat)
            {
                value->fwd_max_iat = iat;
            }
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
        if (log->packet_bytes > 0 && log->packet_bytes < 1500)
        {
            if (log->protocol == IPPROTO_TCP)
            {
                value->fwd_ttl_header_length += (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
            }
            else if (log->protocol == IPPROTO_UDP)
            {
                value->fwd_ttl_header_length += (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
            }
            else
            {
                value->fwd_ttl_header_length += (sizeof(struct ether_header) + sizeof(struct ip));
            }
        }
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
        else if (value->is_updated[1] == false)
        {
            value->bwd_min_packet_bytes = log->packet_bytes;
            value->bwd_seg_min = log->packet_bytes;
            value->is_updated[1] = true;
        }
        else if (log->packet_bytes > value->bwd_max_packet_bytes)
        {
            value->bwd_max_packet_bytes = log->packet_bytes;
        }

        value->bwd_ttl_iat += iat;
        if (value->timestamp != 0)
        {
            if (iat < value->bwd_min_iat)
            {
                value->bwd_min_iat = iat;
            }
            else if (value->is_updated[4] == false)
            {
                value->bwd_min_iat = iat;
                value->is_updated[4] = true;
            }
            else if (iat > value->bwd_max_iat)
            {
                value->bwd_max_iat = iat;
            }
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

        if (log->packet_bytes > 0 && log->packet_bytes < 1500)
        {
            if (log->protocol == IPPROTO_TCP)
            {
                value->bwd_ttl_header_length += (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
            }
            else if (log->protocol == IPPROTO_UDP)
            {
                value->bwd_ttl_header_length += (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
            }
            else
            {
                value->bwd_ttl_header_length += (sizeof(struct ether_header) + sizeof(struct ip));
            }
        }
    }

    calculate_avg_variance(log, value);

    value->timestamp = log->timestamp;
}

bool extract(const void *item, void *udata)
{
    struct logger_value *logger_value = (struct logger_value *)item;
    struct log *logger_key = &logger_value->log;
    struct characteristics characteristics = {0};
    process_log(*logger_value, &characteristics);

    struct fixed_point features[58] = {0};

    features[0] = to_fixed_point(logger_value->key.dest_port, 8);
    features[1] = to_fixed_point(logger_value->key.src_port, 8);
    features[2] = to_fixed_point(logger_value->key.protocol, 8);

    features[3] = to_fixed_point(logger_value->fwd_packet_count, 8);
    features[4] = to_fixed_point(logger_value->bwd_packet_count, 8);

    features[39] = to_fixed_point(logger_value->min_packet_bytes, 8);
    features[40] = to_fixed_point(logger_value->max_packet_bytes, 8);
    features[15] = to_fixed_point(logger_value->ttl_packet_bytes, 8);

    features[8] = to_fixed_point(logger_value->fwd_min_packet_bytes, 8);
    features[7] = to_fixed_point(logger_value->fwd_max_packet_bytes, 8);
    features[5] = to_fixed_point(logger_value->fwd_ttl_packet_bytes, 8);

    features[12] = to_fixed_point(logger_value->bwd_min_packet_bytes, 8);
    features[11] = to_fixed_point(logger_value->bwd_max_packet_bytes, 8);
    features[6] = to_fixed_point(logger_value->bwd_ttl_packet_bytes, 8);

    features[20] = to_fixed_point(logger_value->min_iat, 8);
    features[19] = to_fixed_point(logger_value->max_iat, 8);

    features[25] = to_fixed_point(logger_value->fwd_min_iat, 8);
    features[24] = to_fixed_point(logger_value->fwd_max_iat, 8);
    features[21] = to_fixed_point(logger_value->fwd_ttl_iat, 8);

    features[30] = to_fixed_point(logger_value->bwd_min_iat, 8);
    features[29] = to_fixed_point(logger_value->bwd_max_iat, 8);
    features[26] = to_fixed_point(logger_value->bwd_ttl_iat, 8);

    features[31] = to_fixed_point(logger_value->fwd_psh_flag_count, 8);
    features[33] = to_fixed_point(logger_value->fwd_urg_flag_count, 8);

    features[32] = to_fixed_point(logger_value->bwd_psh_flag_count, 8);
    features[34] = to_fixed_point(logger_value->bwd_urg_flag_count, 8);

    features[44] = to_fixed_point(logger_value->fin_flag_count, 8);
    features[45] = to_fixed_point(logger_value->syn_flag_count, 8);
    features[46] = to_fixed_point(logger_value->rst_flag_count, 8);
    features[47] = to_fixed_point(logger_value->psh_flag_count, 8);
    features[48] = to_fixed_point(logger_value->ack_flag_count, 8);
    features[49] = to_fixed_point(logger_value->urg_flag_count, 8);
    features[50] = to_fixed_point(logger_value->cwr_flag_count, 8);
    features[51] = to_fixed_point(logger_value->ece_flag_count, 8);

    features[35] = to_fixed_point(logger_value->fwd_ttl_header_length, 8);
    features[36] = to_fixed_point(logger_value->bwd_ttl_header_length, 8);

    features[54] = to_fixed_point(logger_value->fwd_ttl_segment_size, 8);
    features[55] = to_fixed_point(logger_value->bwd_ttl_segment_size, 8);

    features[56] = to_fixed_point(logger_value->fwd_act_data_pkt, 8);

    features[57] = to_fixed_point(logger_value->fwd_seg_min, 8);

    features[16] = to_fixed_point(logger_value->ttl_packet_count, 8);

    features[41] = logger_value->ttl_mean_packet_size;
    features[9] = logger_value->fwd_mean_packet_size;
    features[13] = logger_value->bwd_mean_packet_size;

    features[43] = characteristics.logger_value.ttl_packet_size_variance;

    features[17] = logger_value->ttl_mean_iat;
    features[22] = logger_value->fwd_mean_iat;
    features[27] = logger_value->bwd_mean_iat;

    features[14] = characteristics.bwd_std_dev_packet_size;
    features[10] = characteristics.fwd_std_dev_packet_size;
    features[42] = characteristics.ttl_std_dev_packet_size;

    features[18] = characteristics.bwd_std_dev_iat;
    features[23] = characteristics.fwd_std_dev_iat;
    features[28] = characteristics.ttl_std_dev_iat;

    features[52] = characteristics.up_down_ratio;

    features[15] = characteristics.flow_bytes;

    features[16] = characteristics.flow_packets;

    features[53] = characteristics.logger_value.ttl_mean_packet_size;

    features[37] = characteristics.fwd_flow_packets;

    features[38] = characteristics.bwd_flow_packets;

    char sourceIP[INET_ADDRSTRLEN];
    char destIP[INET_ADDRSTRLEN];

    int src = ntohl(logger_value->key.src_address);
    int dest = ntohl(logger_value->key.dest_address);

    inet_ntop(AF_INET, &(src), sourceIP, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(dest), destIP, INET_ADDRSTRLEN);

    printf("%s-%s-%d-%d-%d,%s,%d,%s,%d,%d,", destIP, sourceIP, logger_value->key.dest_port, logger_value->key.src_port, logger_value->key.protocol, destIP, logger_value->key.dest_port, sourceIP, logger_value->key.src_port, logger_value->key.protocol);

    for (int i = 3; i < 58; i++)
    {
        printf("%lf,", fix2float(&features[i]));
    }
    printf("\n");

    return true;
}