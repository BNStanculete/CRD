/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition ethernet;
    }

    state ethernet {
        packet.extract(hdr.ethernet);

        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: ipv4;
            default: accept;
        }
    }

    state ipv4 {
        packet.extract(hdr.ipv4);

        transition select(hdr.ipv4.protocol) {
            TYPE_TCP: tcp;
            default: accept;
        }
    }

    state tcp {
        packet.extract(hdr.tcp);

        transition accept;
    }
}
