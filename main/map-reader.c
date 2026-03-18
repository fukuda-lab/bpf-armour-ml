#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>

// 1. Copy the EXACT struct from your eBPF code
struct blocklist_key {
    uint32_t prefixlen;
    uint32_t address;
    int8_t protocol;
    uint16_t src_port;
    uint16_t dest_port;
};

void read_blacklist(int map_fd) {
    struct blocklist_key prev_key = {}; 
    struct blocklist_key next_key;
    uint32_t value;
    
    // For formatting the IP address
    struct in_addr ip_addr;
    char ip_str[INET_ADDRSTRLEN];

    printf("Iterating through LPM Trie Blocklist...\n");

    // 2. Pass NULL as the 'prev_key' to grab the very first node in the Trie
    int err = bpf_map_get_next_key(map_fd, NULL, &next_key);
    
    while (err == 0) {
        // 3. Look up the value associated with this specific key
        if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
            
            // Format IP from raw bytes to a readable string (e.g., "192.168.1.1")
            ip_addr.s_addr = next_key.address;
            inet_ntop(AF_INET, &ip_addr, ip_str, sizeof(ip_str));

            // Convert ports from Network Byte Order back to Host layout
            uint16_t src = ntohs(next_key.src_port);
            uint16_t dst = ntohs(next_key.dest_port);

            printf("Match [%s/%u] Proto: %d, Src: %u, Dst: %u | Value: %u\n",
                   ip_str, next_key.prefixlen, next_key.protocol, src, dst, value);
        }

        // 4. Advance the loop: use the current key to find the next one
        prev_key = next_key;
        err = bpf_map_get_next_key(map_fd, &prev_key, &next_key);
    }

    // -ENOENT just means "Error: No Entity" (we reached the end of the map safely)
    if (err < 0 && err != -ENOENT) {
        printf("Failed to iterate map: %d\n", err);
    } else {
        printf("Finished reading map.\n");
    }
}

int main(int argc, char **argv) {
    // 1. Get the File Descriptor of the loaded map.
    // Replace this path with wherever your map is pinned!
    const char *map_path = "/sys/fs/bpf/blocklist"; 
    
    int map_fd = bpf_obj_get(map_path);
    if (map_fd < 0) {
        fprintf(stderr, "Failed to open map at %s: %s\n", map_path, strerror(errno));
        fprintf(stderr, "(Did you pin the map, and are you running as root?)\n");
        return 1;
    }

    // 2. Read the data
    read_blacklist(map_fd);

    // 3. Clean up
    close(map_fd);
    return 0;
}