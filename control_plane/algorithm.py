from modules.controllers import FirewallController
from modules.parsers import ConfigurationParser
from modules.logger import Logger, LoggingLevel
from modules.constants import HOSTS

from typing import Tuple, List

import grpc

class ControlPlaneAlgorithm:
    def filterTraffic(self):
        # Update all host metrics
        self.__updateMetrics()

        for key in self.__hosts.keys():
            address = HOSTS[self.__hosts[key].Index]["IPv4"]

            self.__logger.log(message=f"Host {address} statistics: ")
            self.__logger.log(message=f"Raw metrics: {self.__hosts[key].Metrics.values()}")
            self.__logger.log(message=f"Normalized metrics: {self.__hosts[key].NormalizedMetrics.values()}")

        # Update traffic filtering
        suspicious_hosts = self.__identifyRuleBreakers()
        self.__logger.log(message=f"Suspicious hosts: {suspicious_hosts}")

        for key in suspicious_hosts:
            if self.__hosts[key].Index in self.__bannedHosts:
                continue
            self.__hosts[key].Offenses += 1

            if self.__hosts[key].Offenses > self.__config["OffensesBeforeBan"]:
                address = HOSTS[self.__hosts[key].Index]["IPv4"]
                self.__logger.log(LoggingLevel.WARNING, f"Banning host {address} for repeted offensses.")
                self.__bannedHosts.append(self.__hosts[key].Index)
                self.__hosts[key].GoodBehaviors = 0

        for key in self.__hosts.keys():
            if self.__hosts[key].Index in self.__bannedHosts and \
               key not in suspicious_hosts:
                self.__hosts[key].GoodBehaviors += 1
            elif self.__hosts[key].Index in self.__bannedHosts:
                # If host is banned and still suspicious, remove acts of good behavior
                if self.__hosts[key].GoodBehaviors > 0:
                    self.__hosts[key].GoodBehaviors -= 1
                
            
            if self.__hosts[key].GoodBehaviors > self.__config["NormalReportsBeforeUnban"] and self.__hosts[key].Index in self.__bannedHosts:
                address = HOSTS[self.__hosts[key].Index]["IPv4"]
                self.__logger.log(LoggingLevel.WARNING, f"Unbanning host {address} for good behavior.")
                self.__hosts[key].GoodBehaviors = 0
                self.__hosts[key].Offenses = 0                
                self.__bannedHosts.remove(self.__hosts[key].Index)

        self.__logger.log(LoggingLevel.INFO, f"Banned hosts: {self.__bannedHosts}")
        self.__switch.writeFilterRules(self.__bannedHosts, "MODIFY")


    def __identifyRuleBreakers(self) -> List[int]:
        """
        Analyzes the metrics according to the configured depth,
        and returns a list of all hosts suspected of co-residency.

        Returns:
            List[int]: A list of suspicious hosts
        """
        suspicious_hosts = []

        for run in range(self.__config["FilteringDepth"]):
            # First run:
            #   -> Compute global average / metric as average of normalized values
            #   -> Compute deltas / host / metric as diff with global average
            #   -> Compute average deltas
            #   -> Select hosts which exceed average by X%

            # Subsequent runs (only for previously selected hosts):
            #   -> Compute global average / metric as average of host deltas
            #   -> Compute deltas / host / metric as diff with global average
            #   -> Compute average deltas
            #   -> Select hosts which exceed average by X%
            
            if run != 0:
                self.__logger.log(message="Previous run statistics: ")
                self.__logger.log(message=f"Global metrics: {self.__globalMetrics.values()}")

                for key in self.__hosts.keys():
                    address = HOSTS[self.__hosts[key].Index]["IPv4"]
                    self.__logger.log(message=f"Host {address} deltas: {self.__hosts[key].Deltas.values()}")
                
                list_of_addresses = []
                for key in suspicious_hosts:
                    address = HOSTS[self.__hosts[key].Index]["IPv4"]
                    list_of_addresses.append(address)
                self.__logger.log(message=f"Suspicious hosts so far: {list_of_addresses}")

            if len(suspicious_hosts) == 1:
                # If we flagged only 1 host at any of the passes, we stop.
                # If we didn't flag anybody we stop.
                break

            if len(suspicious_hosts) == 0 and run > 0:
                break

            if run == 0:
                # Step 1: Update Global metrics
                for metric in self.__globalMetrics.keys():
                    total = 0
                    length = 0

                    for key in self.__hosts.keys():
                        # Skip hosts that have not yet joined the traffic
                        if self.__hosts[key].ElapsedTimeout == 0:
                            continue

                        total += self.avg(self.__hosts[key].NormalizedMetrics[metric])
                        length += 1.0
                    if length > 0:
                        self.__globalMetrics[metric] = total / length
                        self.__globalMetrics[metric] = round(self.__globalMetrics[metric], 2)
                    else:
                        self.__globalMetrics[metric] = 0

                # Step 2: Compute Host deltas
                for metric in self.__globalMetrics.keys():
                    for key in self.__hosts.keys():
                        # Skip hosts that have not yet joined the traffic
                        if self.__hosts[key].ElapsedTimeout == 0:
                            continue

                        if self.__globalMetrics[metric] != 0:
                            self.__hosts[key].Deltas[metric] = abs(1.0 - self.avg(self.__hosts[key].NormalizedMetrics[metric]) / self.__globalMetrics[metric])
                        else:
                            self.__hosts[key].Deltas[metric] = 0.0

                # Step 3: Compute the average deviation
                average_deviation = 0
                length = 0

                for metric in self.__globalMetrics.keys():
                    for key in self.__hosts.keys():
                        # Skip hosts that have not yet joined the traffic
                        if self.__hosts[key].ElapsedTimeout == 0:
                            continue

                        average_deviation += self.__hosts[key].Deltas[metric]
                        length += 1.0
                if length > 0:
                    average_deviation /= length
                    average_deviation = round(average_deviation, 2)

                # Step 4: Flag suspicious hosts
                for key in self.__hosts.keys():
                    # Skip hosts that have not yet joined the traffic
                    if self.__hosts[key].ElapsedTimeout == 0:
                        continue

                    host_deviation = self.__hosts[key].Deltas["Connections"] + \
                                        self.__hosts[key].Deltas["Packets"] + \
                                        self.__hosts[key].Deltas["PacketSize"]
                    host_deviation /= 3
                    host_deviation = round(host_deviation, 2)

                    if abs(host_deviation - average_deviation) >= self.__config["DeviationThreshold"] and host_deviation >= self.__config["DeviationThreshold"]:
                        # This prevents hosts which are reasonably close to the average from being marked suspicious.
                        suspicious_hosts.append(key)

            else:
                # Step 1: Update Global metrics:
                for metric in self.__globalMetrics.keys():
                    total = 0
                    length = 0

                    for host in self.__hosts.keys():
                        # Skip hosts that have not yet joined the traffic
                        if self.__hosts[key].ElapsedTimeout == 0:
                            continue
                        total += self.__hosts[host].Deltas[metric]
                        length += 1.0
                    if length > 0:
                        self.__globalMetrics[metric] = total / length
                        self.__globalMetrics[metric] = round(self.__globalMetrics[metric], 2)
            
                # Step 2: Compute Host deltas
                for metric in self.__globalMetrics.keys():
                    for key in self.__hosts.keys():
                        # Skip hosts that have not yet joined the traffic
                        if self.__hosts[key].ElapsedTimeout == 0:
                            continue

                        if self.__globalMetrics[metric] != 0:
                            self.__hosts[key].Deltas[metric] = abs(1.0 - self.__hosts[key].Deltas[metric] / self.__globalMetrics[metric])
                        else:
                            self.__hosts[key].Deltas[metric] = 0.0

                # Step 3: Compute the average deviation
                average_deviation = 0
                length = 0

                for metric in self.__globalMetrics.keys():
                    for key in self.__hosts.keys():
                        average_deviation += self.__hosts[key].Deltas[metric]
                        length += 1.0
                if length > 0:
                    average_deviation /= length
                    average_deviation = round(average_deviation, 2)
                self.__logger.log(message=f"Average deviation step [{run}]: {average_deviation}")

                # Step 4: Unflag hosts which are no longer suspicious
                to_remove = []
                for key in suspicious_hosts:
                    host_deviation = self.__hosts[key].Deltas["Connections"] + \
                                        self.__hosts[key].Deltas["Packets"] + \
                                        self.__hosts[key].Deltas["PacketSize"]
                    host_deviation /= 3
                    host_deviation = round(host_deviation, 2)
                    address = HOSTS[self.__hosts[key].Index]["IPv4"]
                    self.__logger.log(message=f"Host {address} deviation step [{run}]: {host_deviation}")

                    if abs(host_deviation - average_deviation) < self.__config["DeviationThreshold"]:
                        to_remove.append(key)
                for value in to_remove:
                    suspicious_hosts.remove(value)
        return suspicious_hosts

    def __updateMetrics(self):
        """
        Updates the host metrics for every known host
        """
        for key in self.__hosts.keys():
            self.__hosts[key].updateMetrics((
                self.__switch.getByteCounter("Individual_connections", key, "Packets"),
                self.__switch.getByteCounter("Individual_packets_sent", key, "Packets"),
                self.__switch.getByteCounter("Individual_packets_sent", key)))

    def __init__(self, filterConfiguration: ConfigurationParser.JSONParser):
        self.__logger = Logger()
        self.__config = filterConfiguration
        self.__hosts = {
            0: ControlPlaneAlgorithm.HostMetrics(1),
            2: ControlPlaneAlgorithm.HostMetrics(2),
            1: ControlPlaneAlgorithm.HostMetrics(3)
        }
        self.__globalMetrics = {
            "Connections": 0,
            "Packets": 0,
            "PacketSize": 0   
        }
        self.__bannedHosts = []

        try:
            self.__switch = FirewallController()

            # Setting up the basic rules
            self.__switch.writeIPForwardingRules()
            self.__switch.writeCounterRules()
            self.__switch.writeFilterRules([])
            self.__switch.readTableRules()

        except grpc.RpcError as err:
            self.__logger.log(LoggingLevel.ERROR, f"gRPC Error {err.code().name}: {err.details()}")
    
    def avg(self, item: List) -> float:
        return round(sum(item) / len(item), 2)

    class HostMetrics:
        def updateMetrics(self, newMetrics: Tuple[int, int, int]):
            """
            Updates the metrics for a specific host
            """
            self.Metrics["Connections"].pop(0)
            self.Metrics["Packets"].pop(0)
            self.Metrics["PacketSize"].pop(0)
            self.NormalizedMetrics["Connections"].pop(0)
            self.NormalizedMetrics["Packets"].pop(0)
            self.NormalizedMetrics["PacketSize"].pop(0)
            
            self.Metrics["Connections"].append(newMetrics[0])
            self.Metrics["Packets"].append(newMetrics[1])

            if newMetrics[1] != 0:
                self.Metrics["PacketSize"].append(newMetrics[2] / newMetrics[1])
            else:
                self.Metrics["PacketSize"].append(newMetrics[2])

            self.NormalizedMetrics["Connections"].append(self.Metrics["Connections"][-1] - self.Metrics["Connections"][-2])
            self.NormalizedMetrics["Packets"].append(self.Metrics["Packets"][-1] - self.Metrics["Packets"][-2])
            self.NormalizedMetrics["PacketSize"].append(self.Metrics["PacketSize"][-1])

            for metric in ["Packets"]:
                if 0 in self.NormalizedMetrics[metric]:
                    break
            else:
                # No metrics are 0 (no more data from that host)
                self.ElapsedTimeout = 1


            for metric in ["Packets"]:
                if sum(self.NormalizedMetrics[metric]) != 0:
                    break
            else:
                # All metrics are 0 (no more data from that host)
                self.ElapsedTimeout = 0


        def __init__(self, index: int = 0, metricsSize: int = 5):
            self.Metrics = {
                "Connections": [0 for _ in range(metricsSize)],
                "Packets": [0 for _ in range(metricsSize)],
                "PacketSize": [0 for _ in range(metricsSize)]
            }
            self.NormalizedMetrics = {
                "Connections": [0 for _ in range(metricsSize)],
                "Packets": [0 for _ in range(metricsSize)],
                "PacketSize": [0 for _ in range(metricsSize)]   
            }
            self.Deltas = {
                "Connections": 0,
                "Packets": 0,
                "PacketSize": 0   
            }

            self.Index = index
            self.Offenses = 0
            self.GoodBehaviors = 0
            self.ElapsedTimeout = 0