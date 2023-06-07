/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_MYTUNNEL = 0x1212;
const bit<16> TYPE_IPV4 = 0x800;
typedef bit<10> PortId_t;
const PortId_t NUM_PORTS = 512;
#define PACKET_COUNT_WIDTH 32
#define TRESHOLD 200
#define BYTE_COUNT_WIDTH 48
//#define PACKET_BYTE_COUNT_WIDTH (PACKET_COUNT_WIDTH + BYTE_COUNT_WIDTH)
#define PACKET_BYTE_COUNT_WIDTH 80

#define PACKET_COUNT_RANGE (PACKET_BYTE_COUNT_WIDTH-1):BYTE_COUNT_WIDTH
#define BYTE_COUNT_RANGE (BYTE_COUNT_WIDTH-1):0

#define FLOW_TABLE_SIZE_EACH 1024
#define HASH_BASE 10w0
#define HASH_MAX 10w1023
typedef bit<PACKET_BYTE_COUNT_WIDTH> PacketByteCountState_t;


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

struct ingress_metadata_t {

    bit<64> my_flowID;
    bit<64> my_estimated_count;
    bit<1> already_matched;
    bit<32> nhop_ipv4;
    bit<64> carry_min;
    bit<64> carry_min_plus_one;
    bit<8> min_stage;
    bit<1> do_recirculate;
    bit<9> orig_egr_port;

    bit<32> hashed_flow;
    bit<32> hashed_flow_opposite;
    bit<32> hashed_address_s3;

    bit<64> random_bits;
    bit<12> random_bits_short;
}

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
    ip4Addr_t realsrcAddr;
    ip4Addr_t realdstAddr;    
}

header myTunnel_t {
    bit<16> proto_id;
    bit<16> dst_id;
    bit<32> IP_MAL;
    bit<48> TIME;
    bit<1> FLAG;
}

struct metadata {
    @name("ingress_metadata")
    ingress_metadata_t   ingress_metadata;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    myTunnel_t   myTunnel;
}

struct packet_data{
    bit<32> src_id;
    bit<32> dst_id;
    bit<48> timestamp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_MYTUNNEL: parse_myTunnel;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_myTunnel {
        packet.extract(hdr.myTunnel);
        transition select(hdr.myTunnel.proto_id) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop();
    }
    direct_counter(CounterType.packets) c;
    register<bit<48>>(1024) last_seen;
    register<bit<64>>(1024) flows;
    register<bit<112>(1) TRESHOLDI;

    action get_inter_packet_gap(out bit<48> interval,bit<32> flow_id)
    {
      bit<48> last_pkt_cnt;
      bit<32> index;
      /* Get the time the previous packet was seen */
      last_seen.read(last_pkt_cnt,flow_id);
      interval = last_pkt_cnt + 1;
      /* Update the register with the new timestamp */
      last_seen.write((bit<32>)flow_id,
      interval);
    }
    action compute_flow_id () {
      meta.ingress_metadata.my_flowID[31:0]=hdr.ipv4.srcAddr;
      meta.ingress_metadata.my_flowID[63:32]=hdr.ipv4.dstAddr;
    }
    action compute_reg_index () {
      // Each flow ID is hashed into d=3 different locations
        hash(meta.ingress_metadata.hashed_flow, HashAlgorithm.crc16, HASH_BASE,
            {hdr.ipv4.srcAddr, 7w11, hdr.ipv4.dstAddr}, HASH_MAX);
        hash(meta.ingress_metadata.hashed_flow_opposite, HashAlgorithm.crc16, HASH_BASE,
            {hdr.ipv4.dstAddr, 7w11, hdr.ipv4.srcAddr}, HASH_MAX);
      }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    action update_origin(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action save_last_seen(bit<112> pkt_data) {
        TRESHOLDI.write(0, pkt_data);
    }
    
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        counters = c;
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    action myTunnel_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    table myTunnel_exact {
        key = {
            hdr.myTunnel.dst_id: exact;
        }
        actions = {
            myTunnel_forward;
            drop;
        }
        size = 1024;
        default_action = drop();
    }
    
    apply {
       if (hdr.ipv4.isValid() && !hdr.myTunnel.isValid()) {
            ipv4_lpm.apply();
            bit<48> tmp;
            bit<32> flow;
            bit<32> flow_opp;
            compute_reg_index();
            bit<48> last_pkt_cnt;
            bit<48> last_pkt_cnt_opp;
            /* Get the time the previous packet was seen */
            flow = meta.ingress_metadata.hashed_flow;
            flow_opp = meta.ingress_metadata.hashed_flow_opposite;
            last_seen.read(last_pkt_cnt,flow);
            last_seen.read(last_pkt_cnt_opp,flow_opp);
            tmp = last_pkt_cnt - last_pkt_cnt_opp + 1;
            get_inter_packet_gap(last_pkt_cnt,flow);
            if(tmp == TRESHOLD) {
                bit<112> pkt_data;
                pkt_data[31:0] = hdr.ipv4.srcAddr;
                pkt_data[63:32] = hdr.ipv4.dstAddr;
                pkt_data[111:64] = last_pkt_cnt;
                save_last_seen(pkt_data);
            }
        }
        if (hdr.myTunnel.isValid()) {
            // process tunneled packets
            myTunnel_exact.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
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
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.myTunnel);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
