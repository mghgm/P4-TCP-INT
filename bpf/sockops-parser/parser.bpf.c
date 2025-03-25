#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct __attribute__((packed)) int_option {
    __u8  Kind : 8;
    __u8  Length : 8;
    __u8  TagFreq : 4;
    __u8  LinkSpd : 4;
    __u8  INTval : 8;
    __u8  HopID : 8;
    __u32 HopLat : 24;
    __u8  INTEcr : 8;
    __u8  LnkSEcr : 4;
    __u8  HIDEcr : 4;
    __u16 HopLatEcr : 16;
};

struct __attribute__((packed)) key_t {
    __u32 src_ip;
    __u32 src_port;
};

// Define BPF map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct key_t);
    __type(value, struct int_option);

} int_option_map SEC(".maps");


SEC("sockops")
int bpf_sockops_parse_tcp_options(struct bpf_sock_ops *skops) {
    // Check if we are in the correct callback
    bpf_printk("Boom!");
    int rv;
    rv = bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_PARSE_ALL_HDR_OPT_CB_FLAG);
    if (rv < 0)
    {
        bpf_printk("Failed to setup flag:: BPF_SOCK_OPS_PARSE_ALL_HDR_OPT_CB_FLAG, %d", rv);
        return 1;
    }

    if (skops->op == BPF_SOCK_OPS_PARSE_HDR_OPT_CB)
    {
	char opt_buf[12] = {0x72, 0x0, 0x0, 0x0,
			    0x0, 0x0, 0x0, 0x0,
			    0x0, 0x0, 0x0, 0x0};
	
	int res;
	res = bpf_load_hdr_opt(skops, (void *)opt_buf, 0x0c, 0);
	if (res > 0)
	{

    	    struct int_option parsed_opt = {0};
	    __builtin_memcpy(&parsed_opt, opt_buf, sizeof(parsed_opt));
            
	    bpf_printk("found!\n");

            struct key_t key = {
            	.src_ip = bpf_ntohl(skops->remote_ip4),
                .src_port = bpf_ntohl(skops->remote_port)
            };
        
            bpf_map_update_elem(&int_option_map, &key, &parsed_opt, BPF_ANY);
        }
    }

    return 1;
}

char _license[] SEC("license") = "GPL";

