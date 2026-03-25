#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include "../lib/libbpf/src/bpf.h"
#include "../lib/libbpf/src/libbpf.h"
#include <unistd.h>

struct blocklist_key {
    uint32_t prefixlen;
    uint32_t address;
    int8_t protocol;
    uint16_t src_port;
    uint16_t dest_port;
};

void read_and_clear_blacklist(int map_fd) {
    struct blocklist_key current_key; 
    struct blocklist_key next_key;
    uint32_t value;
    
    // For formatting the IP address
    struct in_addr ip_addr;
    char ip_str[INET_ADDRSTRLEN];

    printf("Iterating and clearing LPM Trie Blocklist...\n");

    // 2. Pass NULL to grab the very first node in the Trie
    int err = bpf_map_get_next_key(map_fd, NULL, &next_key);
    
    int counter = 0;
    while (err == 0) {
        // Lock in the key we are currently operating on
        current_key = next_key;

        // 3. Look up the value associated with this specific key
        if (bpf_map_lookup_elem(map_fd, &current_key, &value) == 0) {
            
            // Format IP from raw bytes to a readable string (e.g., "192.168.1.1")
            ip_addr.s_addr = current_key.address;
            inet_ntop(AF_INET, &ip_addr, ip_str, sizeof(ip_str));

            // Convert ports from Network Byte Order back to Host layout
            uint16_t src = ntohs(current_key.src_port);
            uint16_t dst = ntohs(current_key.dest_port);

            printf("Match [%s] Proto: %d, Src: %u, Dst: %u\n",
                   ip_str, current_key.protocol, src, dst);
            counter++;
        }

        // 4. CRITICAL STEP: Advance the loop BEFORE deleting the current key.
        // We use 'current_key' to find the next one, storing it in 'next_key'.
        err = bpf_map_get_next_key(map_fd, &current_key, &next_key);

        // 5. Now it is safe to delete the current key
        if (bpf_map_delete_elem(map_fd, &current_key) == 0) {
            // printf(" -> Successfully deleted.\n");
        } else {
            // printf(" -> Failed to delete: %s\n", strerror(errno));
        }
    }

    // -ENOENT just means "Error: No Entity" (we reached the end of the map safely)
    if (err < 0 && err != -ENOENT) {
        printf("Failed to iterate map: %d\n", err);
    } else {
        printf("Found %d entries. \n", counter);
    }
}

int main(int argc, char **argv) {
    // 1. Get the File Descriptor of the loaded map. Hardcoding the path to the pinned map in BPF filesystem.
    const char *map_path = "/sys/fs/bpf/blocklist"; 
    
    int map_fd = bpf_obj_get(map_path);
    if (map_fd < 0) {
        fprintf(stderr, "Failed to open map at %s: %s\n", map_path, strerror(errno));
        fprintf(stderr, "(Did you pin the map, and are you running as root?)\n");
        return 1;
    }

    // 2. Read and delete the data
    read_and_clear_blacklist(map_fd);

    // 3. Clean up
    close(map_fd);
    return 0;
}