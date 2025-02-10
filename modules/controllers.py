import p4runtime_lib.bmv2
import p4runtime_lib.helper

from modules.constants import SWITCHES, HOSTS, HOST_CONNECTIONS, SWITCH_CONNECTIONS, PROXY_SERVER_ADDRESS, SERVER_ADDRESS, \
                              ADVERSARY_ADDRESS

class SwitchController:
    def writeIPForwardingRules(self):
        """
        Writes the basic IPv4 forwarding rules for this switch
        """
        for Connection in HOST_CONNECTIONS:
            DST_PORT = -1
            DST_ADDR = (HOSTS[Connection["Host"]]["IPv4"], HOSTS[Connection["Host"]]["SubnetMask"])
            DST_MAC = HOSTS[Connection["Host"]]["Mac"]

            if Connection["Switch"] is not self._switch.name:
                for SwitchConnection in SWITCH_CONNECTIONS:
                    if Connection["Switch"] in SwitchConnection["Switches"] and \
                       self._switch.name in SwitchConnection["Switches"]:
                       DST_PORT = SwitchConnection["Port"]
            else:
                DST_PORT = Connection["Port"]
            
            # Skip unreachable hosts
            if DST_PORT < 0:
                continue
            
            table_entry = self._p4info_helper.buildTableEntry(
                table_name="MyIngress.ipv4_lpm",
                match_fields={
                    "hdr.ipv4.dstAddr": DST_ADDR
                },
                action_name="MyIngress.ipv4_forward",
                action_params={
                    "dstAddr": DST_MAC,
                    "port": DST_PORT
                }
            )

            self._switch.WriteTableEntry(table_entry)
        
        # Writing default action
        table_entry = self._p4info_helper.buildTableEntry(
            table_name="MyIngress.ipv4_lpm",
            default_action="MyIngress.drop",
            action_params={ }
        )

        self._switch.WriteTableEntry(table_entry)

    def readTableRules(self):
        """
        Reads the table entries from all tables on the switch.
        """
        print('\n----- Reading tables rules for %s -----' % self._switch.name)
        for response in self._switch.ReadTableEntries():
            for entity in response.entities:
                entry = entity.table_entry
                table_name = self._p4info_helper.get_tables_name(entry.table_id)
                print('%s: ' % table_name, end=' ')
                for m in entry.match:
                    print(self._p4info_helper.get_match_field_name(table_name, m.field_id), end=' ')
                    print('%r' % (self._p4info_helper.get_match_field_value(m),), end=' ')
                action = entry.action.action
                action_name = self._p4info_helper.get_actions_name(action.action_id)
                print('->', action_name, end=' ')
                for p in action.params:
                    print(self._p4info_helper.get_action_param_name(action_name, p.param_id), end=' ')
                    print('%r' % p.value, end=' ')
                print()

    def getByteCounter(self, counter_name: str, index: int = 0, counterType: str = "Bytes") -> int:
        """
        Reads a counter from the switch.

        Args:
            counterName (str): The name of the counter. Must be the same as the name in the P4 file.
            index (int): The index where to read the counter
            counterType (str): What to extract from the counter (Bytes or Packets)

        Returns:
            int: The number of packets / bytes incremented in the counter.
        """

        for response in self._switch.ReadCounters(self._p4info_helper.get_counters_id(counter_name), index):
            for entity in response.entities:
                if counterType == "Bytes":
                    return entity.counter_entry.data.byte_count
                else:
                    return entity.counter_entry.data.packet_count

    def __init__(self, switchIndex: int):
        """
        Initializes a new switch controller.

        The function sets-up a new P4 switch using the P4Info file and JSON file supplied
        from the constants file.

        Args:
            switchIndex (int): The index of the switch data in the `constants.py` file.
        """
        assert switchIndex >= 0 and switchIndex < len(SWITCHES), "Invalid switch index provided."

        switchData = SWITCHES[switchIndex]

        self._p4info_helper = p4runtime_lib.helper.P4InfoHelper(switchData["P4InfoFile"])
        self.__setupSwitch(switchData["BMV2File"], switchData["Switch"])
    
    def __getDeviceSpecs(self, switch_name: str):
        """
        Computes the connection details for a specific switch based on its name.

        Args:
            switch_name (str): The name of the switch. Looks like `s[INTEGER]`

        Returns:
            tuple[str, int]: The connection address (HOST:PORT) and the deviceID.
        """
        BASE_IPv4 = '127.0.0.1'
        BASE_PORT = 50051
        BASE_ID = 0

        delta_index = int(switch_name[1:]) - 1

        return (f'{BASE_IPv4}:{str(BASE_PORT + delta_index)}', BASE_ID + delta_index)

    def __setupSwitch(self, BMV2File: str, switchName: str):
        """
        Initializes a new switch.

        Args:
            BMV2File (str): The path to the switch'es BMV2 file.
        """
        switchAddress, deviceID = self.__getDeviceSpecs(switchName)

        self._switch = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name=switchName,
            address=switchAddress,
            device_id=deviceID,
            proto_dump_file=f'logs/{switchName}-p4runtime-requests.txt')

        self._switch.MasterArbitrationUpdate()
        self._switch.SetForwardingPipelineConfig(p4info=self._p4info_helper.p4info,
                                                  bmv2_json_file_path=BMV2File)

class FirewallController(SwitchController):
    def writeFilterRules(self, banned_addresses, updateType: str ="INSERT"):
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


class CounterController(SwitchController):
    def writeCounterRules(self):
        """
        Writes the rules for updating the switch counters.
        """
        for Host in HOSTS:
            if Host["IPv4"] == ADVERSARY_ADDRESS["IPv4"]:
                table_entry = self._p4info_helper.buildTableEntry(
                        table_name="MyIngress.increment_counters",
                        match_fields={
                            "hdr.ipv4.srcAddr": Host["IPv4"]
                        },
                        action_name="MyIngress.mark_true",
                        action_params={ }
                )
            else:
                table_entry = self._p4info_helper.buildTableEntry(
                        table_name="MyIngress.increment_counters",
                        match_fields={
                            "hdr.ipv4.srcAddr": Host["IPv4"]
                        },
                        action_name="MyIngress.mark_false",
                        action_params={ }
                )
            self._switch.WriteTableEntry(table_entry)

    def __init__(self, switchIndex: int):
        super(CounterController, self).__init__(switchIndex)
