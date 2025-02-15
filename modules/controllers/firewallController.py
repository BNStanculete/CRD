from modules.constants import HOSTS, PROXY_SERVER_ADDRESS, SERVER_ADDRESS
from modules.controllers import SwitchController

class FirewallController(SwitchController):
    def writeFilterRules(self, banned_addresses: list[int], updateType: str ="INSERT"):
        """
        Updates the firewall filter.

        Args:
            banned_addresses (list[int]): A list of the indexes of all banned hosts
            update_type (str): INSERT or MODIFY indicating whether to update existing rules or not.
        """
        if updateType == "INSERT":
            update_type = self._p4info_helper.UpdateType.INSERT
        else:
            update_type = self._p4info_helper.UpdateType.MODIFY

        for index in range(len(HOSTS)):
            if index not in banned_addresses:
                table_entry = self._p4info_helper.buildTableEntry(
                        table_name="MyIngress.address_filter",
                        match_fields={
                            "hdr.ipv4.srcAddr": (HOSTS[index]["IPv4"], HOSTS[index]["SubnetMask"])
                        },
                        action_name="MyIngress.mark_safe",
                        action_params={ }
                )
            else:
                table_entry = self._p4info_helper.buildTableEntry(
                        table_name="MyIngress.address_filter",
                        match_fields={
                            "hdr.ipv4.srcAddr": (HOSTS[index]["IPv4"], HOSTS[index]["SubnetMask"])
                        },
                        action_name="MyIngress.redirect",
                        action_params={
                            "dstIp": PROXY_SERVER_ADDRESS['IPv4']
                        }
                )
            self._switch.WriteTableEntry(table_entry, update_type=update_type)

    def writeCounterRules(self):
        """
        Writes the rules for updating the firewall counters.
        """
        table_entry = self._p4info_helper.buildTableEntry(
                table_name="MyIngress.tcp_firewall_metric1",
                match_fields={
                    "hdr.ipv4.dstAddr": (SERVER_ADDRESS["IPv4"], SERVER_ADDRESS["SubnetMask"])
                },
                action_name="MyIngress.update_metrics",
                action_params={ }
        )
        self._switch.WriteTableEntry(table_entry)

        table_entry = self._p4info_helper.buildTableEntry(
                table_name="MyIngress.tcp_firewall_metric2",
                match_fields={
                    "hdr.ipv4.dstAddr": (SERVER_ADDRESS["IPv4"], SERVER_ADDRESS["SubnetMask"]),
                    "hdr.tcp.syn": 1,
                    "hdr.tcp.ack": 0
                },
                action_name="MyIngress.update_connection_counter",
                action_params={ }
        )
        self._switch.WriteTableEntry(table_entry)

    def __init__(self, switchIndex: int):
        super(FirewallController, self).__init__(switchIndex)
