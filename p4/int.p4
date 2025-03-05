/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>


//  Types and Constants
const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TCP_PROTO = 0x06;
const bit<8>  IP_PROTO = 253;


#define MAX_HOPS 10

// HEADERS
typedef bit<48> macAddr_v;
typedef bit<32> ip4Addr_v;
typedef bit<9>  egressSpec_v;

typedef bit<31>  switchID_v;
typedef bit<16>  qdepth_util_v;
typedef bit<48>  deq_timedelta_v;
typedef bit<1>   int_echo_v;


header ethernet_h {
    macAddr_v   dstAddr;
    macAddr_v   srcAddr;
    bit<16>     etherType;
}

header ipv4_h {
    bit<4>      version;
    bit<4>      ihl;
    bit<8>      diffserv;
    bit<16>     totalLen;
    bit<16>     identification;
    bit<3>      flags;
    bit<13>     fragOffset;
    bit<8>      ttl;
    bit<8>      protocol;
    bit<16>     hdrChecksum;
    ip4Addr_v   srcAddr;
    ip4Addr_v   dstAddr;
}

header tcp_h {
    bit<16>     src_port;
    bit<16>     dst_port;
    bit<32>     seq_no;
    bit<32>     ack_no;
    bit<4>      data_offset;
    bit<3>      reserved;
    bit<9>      flags;
    bit<16>     window;
    bit<16>     checksum;
    bit<16>     urgent_ptr;
}

header tcp_format_one_option_h {
    bit<8>          kind;
}

header tcp_format_two_option_h {
    bit<8>          kind;
    bit<8>          length;
    varbit<256>     data;
}

struct tcp_format_two_option_top {
    bit<8>          kind;
    bit<8>          length;
}

header tcp_int_option_h {
    bit<8>          kind;
    bit<8>          length;
    switchID_v      switchID;
    qdepth_util_v   qdepth_util;
    deq_timedelta_v deq_timedelta;
    int_echo_v      int_echo;
}

header_union tcp_option_h {
    tcp_format_one_option_h format_one;
    tcp_format_two_option_h format_two;
    tcp_int_option_h        format_int;
}


struct headers_t {
    ethernet_h          ethernet;
    ipv4_h              ipv4;
    tcp_h               tcp;
    tcp_option_h[10]    tcp_options_vec;
}


struct ingress_metadata_t {
    bit<16>  count;
}

struct parser_metadata_t {
    bit<16>  remaining;
}

struct metadata_t {
    bit<16>     tcp_length; // TCP packet size in # of bytes to update checksum
    bit<1>      has_int;    // 1-bit value indicator of existence of int option
    bit<4>      int_idx;    // index of telemetry option in tcp_options_vec
}

parser MyParser(packet_in packet,
                out headers_t hdr,
                inout metadata_t meta,
                inout standard_metadata_t standard_metadata) {

    bit<7> tcp_hdr_bytes_left;

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            TCP_PROTO: parse_tcp;
            default: accept;
        }
    }


    state parse_tcp {
        packet.extract(hdr.tcp);

        transition select(hdr.tcp.data_offset){
            5: accept;
            default: parse_tcp_options;
        }
    }

    

    state parse_tcp_options {
        tcp_hdr_bytes_left = 4 * (bit<7>) (hdr.tcp.data_offset - 5);

        transition parse_next_option;
    }

    state parse_next_option {
        transition select(tcp_hdr_bytes_left) {
            0: accept;
            default: parse_and_lookup_next_option;
        }
    }

    state parse_and_lookup_next_option {
        transition select(packet.lookahead<bit<8>>()) {
            0:          parse_format_one_option;
            1:          parse_format_one_option;
            0xfd:       parse_int_option;
            default:    parse_format_two_option;
        }
    }

    state parse_format_one_option {
        packet.extract(hdr.tcp_options_vec.next.format_one);

        tcp_hdr_bytes_left = tcp_hdr_bytes_left - 1;

        transition parse_next_option;
    }

    state parse_format_two_option {
        bit<32> n = (bit<32>)packet.lookahead<tcp_format_two_option_top>().length;

        packet.extract(hdr.tcp_options_vec.next.format_two, (n - 2) * 8);

        tcp_hdr_bytes_left = tcp_hdr_bytes_left - n;

        transition parse_next_option;
    }

    state parse_int_option {
        packet.extract(hdr.tcp_options_vec.next.format_int);

        transition parse_next_option;
    }

}   

control MyVerifyChecksum(inout headers_t hdr, inout metadata_t meta) {   
    apply {  }
}

control MyIngress(inout headers_t hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action ipv4_forward(macAddr_v dstAddr, egressSpec_v port) {
        standard_metadata.egress_spec = port;
        // hdr.ethernet.srcAddr = hdr.ethernet.dstAddr; // TODO: It should be corrected further
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }

        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }

        size = 1024;
        default_action = NoAction();
    }
    
    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
    }
}

control MyEgress(inout headers_t hdr,
                 inout metadata_t meta,
                 inout standard_metadata_t standard_metadata) {

    action add_int_record(switchID_v swid) {
    
    }

    table int_record {
        key = {}
        actions = { 
	        add_int_record; 
	        NoAction; 
        }
        default_action = NoAction();      
    }
    
    apply {
        if (hdr.tcp.isValid()) {
            int_record.apply();
        }
    } 
}

control MyComputeChecksum(inout headers_t hdr, inout metadata_t meta) {

    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
        
//        update_checksum_with_payload(
//            hdr.tcp.isValid(),
//            { hdr.ipv4.srcAddr,
//              hdr.ipv4.dstAddr,
//              8w0,
//              hdr.ipv4.protocol,
//              meta.tcp_length,
//              hdr.tcp.src_port,
//              hdr.tcp.dst_port,
//              hdr.tcp.seq_no,
//              hdr.tcp.ack_no,
//              hdr.tcp.data_offset,
//              hdr.tcp.reserved,
//              hdr.tcp.flags,    
//              hdr.tcp.window,
//              16w0,
//              hdr.tcp.urgent_ptr,
//              hdr.tcp_int_options.kind,
//              hdr.tcp_int_options.length,
//              hdr.tcp_int_options.switchID,
//              hdr.tcp_int_options.qdepth_util,
//              hdr.tcp_int_options.deq_timedelta,
//              hdr.tcp_int_options.int_echo,
//              hdr.tcp_int_options.padding
//              },
//            hdr.tcp.checksum,
//            HashAlgorithm.csum16
//        );
    }
}

control MyDeparser(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp) ;
        packet.emit(hdr.tcp_options_vec);
    }
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
