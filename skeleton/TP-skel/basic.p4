/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_INT = 0x88B7;
#define MAX_HOPS 30

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

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
}

header int_pai_t {
    bit<32> Quantidade_Filhos;
    bit<16>  next_header;
}

header int_filho_t {
    bit<32> ID_Switch;
    bit<9> Porta_Entrada;
    bit<9> Porta_Saida;
    bit<48> Timestamp;
    bit<6> padding;
    }

struct metadata {
    bit<32>  remaining;
}

struct headers {
    ethernet_t   ethernet;
    int_pai_t    int_pai;
    int_filho_t[MAX_HOPS]  int_filho;
    ipv4_t       ipv4;
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
            TYPE_IPV4: parse_ipv4;
            TYPE_INT:  parse_int_pai;
            default: accept;
        }
    }

    state parse_int_pai {
        packet.extract(hdr.int_pai);
        meta.remaining = hdr.int_pai.Quantidade_Filhos;
        transition select(meta.remaining){
            0: parse_ipv4;
            default: parse_int_filho;
        }
    }

    state parse_int_filho {
        packet.extract(hdr.int_filho.next);
        meta.remaining = meta.remaining - 1;
        transition select(meta.remaining){
            0: parse_ipv4;
            default: parse_int_filho;
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
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
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
        default_action = drop();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    action add_int_pai(){
        hdr.int_pai.setValid();
        hdr.int_pai.Quantidade_Filhos = 0;
        hdr.int_pai.next_header = hdr.ethernet.etherType;

        hdr.ethernet.etherType = TYPE_INT;

    }

    action add_int_filho(){

        hdr.int_filho[hdr.int_pai.Quantidade_Filhos].setValid();
        hdr.int_filho[hdr.int_pai.Quantidade_Filhos].ID_Switch = 0;
        hdr.int_filho[hdr.int_pai.Quantidade_Filhos].Porta_Entrada = standard_metadata.ingress_port;
        hdr.int_filho[hdr.int_pai.Quantidade_Filhos].Porta_Saida = standard_metadata.egress_port;
        hdr.int_filho[hdr.int_pai.Quantidade_Filhos].Timestamp = standard_metadata.egress_global_timestamp;

        hdr.int_pai.Quantidade_Filhos = hdr.int_pai.Quantidade_Filhos + 1;
    }

    apply {
        if(!hdr.int_pai.isValid()){
            add_int_pai();
        }
        add_int_filho();
    }
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
        packet.emit(hdr.int_pai);
        packet.emit(hdr.int_filho);
        packet.emit(hdr.ipv4);
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
