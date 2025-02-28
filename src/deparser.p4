/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        
        /* Reassemble the packets based on their header */
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}