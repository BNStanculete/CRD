/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#include "src/headers.p4"
#include "src/registers.p4"
#include "src/parser.p4"
#include "src/ingress.p4"
#include "src/egress.p4"
#include "src/deparser.p4"

/********************************************************************
***********************  S W I T C H  *******************************
**********************************************************************/

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
