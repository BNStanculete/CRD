import p4runtime_lib.bmv2
import p4runtime_lib.helper

from modules.constants import HOSTS, HOST_CONNECTIONS, SWITCH_CONNECTIONS
from modules.logger import Logger, LoggingLevel

from typing import Tuple, Dict

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
            default_action=True,
            action_name="MyIngress.drop",
            action_params={}
        )

        self._switch.WriteTableEntry(table_entry)

    def readTableRules(self):
        """
        Reads the table entries from all tables on the switch.
        """
        self._logger.log(message=f'----- Reading tables rules for {self._switch.name} -----')
        for response in self._switch.ReadTableEntries():
            for entity in response.entities:
                entry = entity.table_entry
                table_name = self._p4info_helper.get_tables_name(entry.table_id)
                message = f"{table_name} "
                
                for m in entry.match:
                    message += self._p4info_helper.get_match_field_name(table_name, m.field_id) + " "
                    message += '%r' % (self._p4info_helper.get_match_field_value(m),)
                    message += " "
                
                action = entry.action.action
                action_name = self._p4info_helper.get_actions_name(action.action_id)
                message += f"-> {action_name} "
                
                for p in action.params:
                    message += self._p4info_helper.get_action_param_name(action_name, p.param_id) + " "
                    message == '%r' % p.value + " "
                
                self._logger.log(message=message)

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

    def __init__(self, switchName: str, configuration: Dict[str, str]):
        """
        Initializes a new switch controller.

        The function sets-up a new P4 switch using the P4Info file and JSON file supplied
        from via the provided configuration.

        Args:
            switchName (str): The name of the switch. E.g. s1
            configuration (Dict[str, str]): The configuration of the switch, containing two keys (BMV2File, P4InfoFile)
        """
        self._logger = Logger()
        self._p4info_helper = p4runtime_lib.helper.P4InfoHelper(configuration["P4InfoFile"])
        self.__setupSwitch(configuration["BMV2File"], switchName)
    
    def __getDeviceSpecs(self, switch_name: str) -> Tuple[str, int]:
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

        try:
            delta_index = int(switch_name[1:]) - 1

            return (f'{BASE_IPv4}:{str(BASE_PORT + delta_index)}', BASE_ID + delta_index)
        except ValueError:
            self._logger.log(LoggingLevel.ERROR, f"Invalid switch name: {switch_name}.")
            self._logger.log(LoggingLevel.INFO, "Please follow the following format: s[INDEX] (e.g. s1)")
            exit(1)

    def __setupSwitch(self, BMV2File: str, switchName: str):
        """
        Initializes a new switch.

        Args:
            BMV2File (str): The path to the switch'es BMV2 file.
            switchName (str): The name of the switch. E.g. s1
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

        self._logger.log(LoggingLevel.INFO, f"Initialized switch {switchName}.")
        self._logger.log(message=f"Switch address: {switchAddress}, with deviceID: {deviceID}")
