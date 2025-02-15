#!/usr/bin/env python3
import sys
import grpc
import os

from time import sleep

sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 'utils/'))

from p4runtime_lib.switch import ShutdownAllSwitchConnections
from modules.controllers import CounterController, FirewallController, SwitchController
from modules.constants import HOSTS


def printGrpcError(e):
    print("gRPC Error:", e.details(), end=' ')
    status_code = e.code()
    print("(%s)" % status_code.name, end=' ')
    traceback = sys.exc_info()[2]
    print("[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno))
    print(traceback.print_tb())

def getAllCounters(firewallController: SwitchController):
    connections = [
        firewallController.getByteCounter("Individual_connections", 0, "Packets"),
        firewallController.getByteCounter("Individual_connections", 1, "Packets"),
        firewallController.getByteCounter("Individual_connections", 2, "Packets"),
    ]

    total_size = [
        firewallController.getByteCounter("Individual_packets_sent", 0),
        firewallController.getByteCounter("Individual_packets_sent", 1),
        firewallController.getByteCounter("Individual_packets_sent", 2),
    ]

    total_packets = [
        firewallController.getByteCounter("Individual_packets_sent", 0, "Packets"),
        firewallController.getByteCounter("Individual_packets_sent", 1, "Packets"),
        firewallController.getByteCounter("Individual_packets_sent", 2, "Packets"),
    ]

    return (connections, total_packets, total_size)

def getPositives(counterController: SwitchController):
    positives = [
        counterController.getByteCounter("positives", 0, "Packets"),
        counterController.getByteCounter("positives", 1, "Packets"),
    ]

    return positives

if __name__ == '__main__':
    # Instantiate a P4Runtime helper from the p4info file
    firewallController = FirewallController()
    counterController = CounterController("s2")
    
    banned_hosts = []

    try:
        # Write the IPv4 forwarding for both switches
        firewallController.writeIPForwardingRules()
        counterController.writeIPForwardingRules()

        # Setup the initial state of the firewall
        firewallController.writeCounterRules()
        firewallController.writeFilterRules(banned_hosts)

        # Setup the initial state of the counter switch
        counterController.writeCounterRules()

        # Print the table rules (DEBUG)
        firewallController.readTableRules()
        counterController.readTableRules()
        print()

        thresholds = [0.4, 0.4, 0.025]
        offenses = [0, 0, 0]
        okcounters = [0, 0, 0]
        maxOffenses = 3
        neededOks = 20
        gracePeriod = 5
        enterTimeout = [0, 0 ,0]
        time_unit_counters = [0, 0, 0]
        global_average_counter = 0
        timeout = 0

        global_metrics = {
            "Connections": 0,
            "Packets": 0,
            "Size": 0,
        }

        host_mapping = {
            0: 1,
            2: 2,
            1: 3,
        }

        while True:
            firewallController.writeFilterRules(banned_hosts, "MODIFY")
            print("Banned hosts: ", banned_hosts)

            connections, packets, packet_size = getAllCounters(firewallController)
            global_average_counter = 0

            # Process raw counter data
            for host_hash in host_mapping.keys():
                if connections[host_hash] > 0:
                    if enterTimeout[host_hash] == 0:
                        timeout = gracePeriod
                        enterTimeout[host_hash] = 1

                        print("Set timeout for 5 seconds to allow for traffic normalization")

                    global_average_counter += 1.0
                    time_unit_counters[host_hash] += 1.0

                    # Make counters relevant to time unit
                    connections[host_hash] /= time_unit_counters[host_hash]
                    packet_size[host_hash] /= packets[host_hash]
                    packets[host_hash] /= time_unit_counters[host_hash]

            # Update global metrics
            if global_average_counter > 0:
                global_metrics["Connections"] = sum(connections) / global_average_counter
                global_metrics["Packets"] = sum(packets) / global_average_counter
                global_metrics["Size"] = sum(packet_size) / global_average_counter
            else:
                global_metrics["Connections"] = 0
                global_metrics["Packets"] = 0
                global_metrics["Size"] = 0

            # Look for rule_breakers
            if timeout == 0:
                for host_hash, host_details in host_mapping.items():
                    host = HOSTS[host_mapping[host_hash]]
                    if time_unit_counters[host_hash] == 0:
                        continue

                    is_rule_breaker = 1
                    deltas = [
                        connections[host_hash] / global_metrics["Connections"],
                        packets[host_hash] / global_metrics["Packets"],
                        packet_size[host_hash] / global_metrics["Size"]
                    ]

                    # print(f"Host {host['IPv4']} deltas: {deltas}")
                    for i in range(len(deltas)):
                        if (deltas[i] >= 1.0 and deltas[i] < 1.0 + thresholds[i]) or (deltas[i] < 1.0 and deltas[i] > 1.0 - thresholds[i]):
                            is_rule_breaker = 0
                            break
                    if is_rule_breaker and not host_mapping[host_hash] in banned_hosts:
                        print(f"Identified rule_breaker: {host['IPv4']} with deltas: {deltas}")
                        offenses[host_hash] += 1
                    elif not is_rule_breaker and host_mapping[host_hash] in banned_hosts:
                        okcounters[host_hash] += 1
                    
                    if okcounters[host_hash] > neededOks and host_mapping[host_hash] in banned_hosts:
                        # Host is assumed clean since he stopped doing co-residency
                        print(f"Removing host {host['IPv4']} from banned.")
                        okcounters[host_hash] = 0
                        offenses[host_hash] = 0
                        banned_hosts.remove(host_mapping[host_hash])

                    if offenses[host_hash] > maxOffenses and host_mapping[host_hash] not in banned_hosts:
                        banned_hosts.append(host_mapping[host_hash])
            else:
                timeout -= 1

                if timeout == 0:
                    print("Timeout expired.")
            positives = getPositives(counterController)

            with open("data/positives.txt", "w") as file:
                file.write(f"True positives: {positives[0]}.\n")
                file.write(f"False positives: {positives[1]}.\n")

            sleep(1)

    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()