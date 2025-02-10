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
    bit<32> hash_reg;

    /************************************************************************
    **************  A C T I O N   D E F I N I T I O N S   *******************
    *************************************************************************/

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action compute_hash(ip4Addr_t ipAddr1){
        //Get register position
        hash(hash_reg, HashAlgorithm.crc32, (bit<32>)0, {ipAddr1,
                                                        hdr.ipv4.protocol},
                                                        (bit<32>)INDIVIDUAL_COUNTER_ENTRIES);
    }

    action update_metrics() {
        compute_hash(hdr.ipv4.srcAddr);

        Individual_packets_sent.count(hash_reg);
    }

    action update_connection_counter() {
        compute_hash(hdr.ipv4.srcAddr);

        Individual_connections.count(hash_reg);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;

        hdr.ethernet.dstAddr = dstAddr;
        hdr.ethernet.srcAddr = meta.localMac;

        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action redirect(ip4Addr_t dstIp) {
        hdr.ipv4.dstAddr = dstIp;
        hdr.ipv4.hdrChecksum = 0;
    }

    action mark_safe() {
    }

    table address_filter {
        key = {
            hdr.ipv4.srcAddr: lpm;
        }
        actions = {
            redirect;
            mark_safe;
        }
        size = 1024;
        default_action = mark_safe();
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

    table tcp_firewall_metric1 {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            update_metrics;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table tcp_firewall_metric2 {
        key = {
            hdr.ipv4.dstAddr: lpm;
            hdr.tcp.syn: exact;
            hdr.tcp.ack: exact;
        }
        actions = {
            update_connection_counter;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        /* Apply a different table based on Ethertype
        ---------------------------------------------
            This switch will look at the ethertype value and apply a different
            table based on the extracted value.
        */
        if(hdr.ethernet.isValid()) {
            if(hdr.ethernet.etherType == TYPE_IPV4) {
                if (hdr.ipv4.protocol == TYPE_TCP) {
                    tcp_firewall_metric1.apply();
                    tcp_firewall_metric2.apply();
                }

                address_filter.apply();
                ipv4_lpm.apply();
            }
        }
    }
}