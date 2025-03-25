/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>


//  Types and Constants
const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TCP_PROTO = 0x06;
const bit<8>  IP_PROTO = 253;
const bit<8>  INT_KIND = 0x72;
const bit<6>  INT_DSCP = 23;

const bit<8>  INT_OPTION_LENGTH = 0xc;

const bit<19> QUEUE_DEPTH_TH = 0x26666;


#define MAX_HOPS 10

// HEADERS
typedef bit<48> macAddr_v;
typedef bit<32> ip4Addr_v;
typedef bit<9>  egressSpec_v;

typedef bit<8>   switchID_v;
typedef bit<16>  qdepth_util_v;
typedef bit<24>  deq_timedelta_v;
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

//header_union tcp_option_h {
//    tcp_format_one_option_h format_one;
//    tcp_format_two_option_h format_two;
//}

header tcp_options_h {
    varbit<320> data;
}


header tcp_int_option_h {
    bit<8>          kind;
    bit<8>          length;
    bit<4>          TagFreq;
    bit<4>          LinkSpd;
    bit<8>          INTval;
    bit<8>          HopID;
    bit<24>         HopLat;
    bit<8>          INTEcr;
    bit<4>          LnkSEcr;
    bit<4>          HIDEcr;
    bit<16>         HopLatEcr;
}

struct headers_t {
    ethernet_h              ethernet;
    ipv4_h                  ipv4;
    tcp_h                   tcp;
    tcp_int_option_h        tcp_int_option;
    tcp_options_h           tcp_options;
}


struct ingress_metadata_t {
    bit<16>  count;
}

struct parser_metadata_t {
    bit<16>  remaining;
}

struct metadata_t {
    bit<16>     tcp_length; // TCP packet size in # of bytes to update checksum
    varbit<320> tcp_options_data;
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
        bit<6> ip_dscp = (bit<6>)(hdr.ipv4.diffserv >> 2);

        log_msg("bib dscp = {}", {ip_dscp});
        transition select(ip_dscp){
            INT_DSCP: parse_int_traffic;
            default: accept;
        }
    }

    state parse_int_traffic {
        transition select(hdr.ipv4.protocol) {
            TCP_PROTO: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        // TODO: Add verify for data offset ...

        transition select(hdr.tcp.data_offset){
            0x5: accept;
            default: parse_tcp_options;
        }
    }

    state parse_tcp_options {
        tcp_hdr_bytes_left = 0x4 * (bit<7>)(hdr.tcp.data_offset - 0x5);

        // We assume that int option is always the first option
        transition select(packet.lookahead<bit<8>>()) {
            INT_KIND: parse_tcp_int_option;
            default: parse_other_tcp_options;
        }
    }

    state parse_tcp_int_option {
        packet.extract(hdr.tcp_int_option);

        tcp_hdr_bytes_left = tcp_hdr_bytes_left - 0xc;

        transition parse_tcp_options;
    }

    state parse_other_tcp_options {
        bit<32> options_length = (bit<32>)((bit<10>)tcp_hdr_bytes_left * 0x8);
        packet.extract(hdr.tcp_options, options_length);

        transition accept;
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
        hdr.tcp_int_option.setValid();
        hdr.tcp_int_option.kind = INT_KIND;
        hdr.tcp_int_option.length = 0x0c;
        hdr.tcp_int_option.TagFreq = 0x0;
        hdr.tcp_int_option.LinkSpd = 0x0;
        hdr.tcp_int_option.INTval = 0x00;
        hdr.tcp_int_option.HopID = swid;
        hdr.tcp_int_option.HopLat = (bit<24>)standard_metadata.deq_timedelta;
        hdr.tcp_int_option.INTEcr = 0x00;
        hdr.tcp_int_option.LnkSEcr = 0x0;
        hdr.tcp_int_option.HIDEcr = 0x0;
        hdr.tcp_int_option.HopLatEcr = (bit<16>)(standard_metadata.enq_qdepth / 8);

        // Consider the hop as a congested one
        if (standard_metadata.enq_qdepth > QUEUE_DEPTH_TH) {
            hdr.tcp_int_option.INTEcr = hdr.tcp_int_option.INTEcr + 0x1;
        }

        hdr.ipv4.totalLen = hdr.ipv4.totalLen + (bit<16>)INT_OPTION_LENGTH; // TODO: Add some notes

        meta.tcp_length = hdr.ipv4.totalLen - (bit<16>)hdr.ipv4.ihl * 0x4;
        hdr.tcp.data_offset = hdr.tcp.data_offset + (bit<4>)(INT_OPTION_LENGTH / 4);

        log_msg("bib len = {} totalLen = {} ihl = {} offset = {} bib = {}", {meta.tcp_length, hdr.ipv4.totalLen, hdr.ipv4.ihl, hdr.tcp.data_offset, (bit<16>)hdr.tcp.data_offset * (bit<16>)0x4});
    }

    action update_int_record(switchID_v swid) {
        hdr.tcp_int_option.kind = INT_KIND;
        hdr.tcp_int_option.length = 0x0c;
        hdr.tcp_int_option.TagFreq = 0x0;
        hdr.tcp_int_option.LinkSpd = 0x0;
        hdr.tcp_int_option.INTval = 0x00;
        hdr.tcp_int_option.HopID = swid;
        hdr.tcp_int_option.HopLat = (bit<24>)standard_metadata.deq_timedelta;
        hdr.tcp_int_option.INTEcr = 0x00;
        hdr.tcp_int_option.LnkSEcr = 0x0;
        hdr.tcp_int_option.HIDEcr = 0x0;
        hdr.tcp_int_option.HopLatEcr = (bit<16>)(standard_metadata.enq_qdepth / 8);

        // Consider the hop as a congested one
        if (standard_metadata.enq_qdepth > QUEUE_DEPTH_TH) {
            hdr.tcp_int_option.INTEcr = hdr.tcp_int_option.INTEcr + 0x1;
        }

        meta.tcp_length = hdr.ipv4.totalLen - (bit<16>)hdr.ipv4.ihl * 0x4;

        log_msg("bib len = {} totalLen = {} ihl = {} offset = {} bib = {}", {meta.tcp_length, hdr.ipv4.totalLen, hdr.ipv4.ihl, hdr.tcp.data_offset, (bit<16>)hdr.tcp.data_offset * (bit<16>)0x4});

    }

    table int_record {
        key = {
            hdr.tcp_int_option.isValid() : exact;
        }
        actions = { 
	        add_int_record;
            update_int_record;
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
        
       update_checksum_with_payload(
           hdr.tcp.isValid(),
           { hdr.ipv4.srcAddr,
             hdr.ipv4.dstAddr,
             8w0,
             hdr.ipv4.protocol,
             meta.tcp_length,
             hdr.tcp.src_port,
             hdr.tcp.dst_port,
             hdr.tcp.seq_no,
             hdr.tcp.ack_no,
             hdr.tcp.data_offset,
             hdr.tcp.reserved,
             hdr.tcp.flags,    
             hdr.tcp.window,
             hdr.tcp.urgent_ptr,
             
             hdr.tcp_int_option.kind,
             hdr.tcp_int_option.length,
             hdr.tcp_int_option.TagFreq,
             hdr.tcp_int_option.LinkSpd,
             hdr.tcp_int_option.INTval,
             hdr.tcp_int_option.HopID,
             hdr.tcp_int_option.HopLat,
             hdr.tcp_int_option.INTEcr,
             hdr.tcp_int_option.LnkSEcr,
             hdr.tcp_int_option.HIDEcr,
             hdr.tcp_int_option.HopLatEcr,
             hdr.tcp_options
             },
           hdr.tcp.checksum,
           HashAlgorithm.csum16
       );

       
    }
}

control MyDeparser(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp) ;
        packet.emit(hdr.tcp_int_option);
        packet.emit(hdr.tcp_options);
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