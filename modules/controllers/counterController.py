from modules.constants import HOSTS, ADVERSARY_ADDRESS
from modules.controllers import SwitchController

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

    def __init__(self, switchName: str = "s1"):
        configuration = {
            "P4InfoFile": "build/switch.p4.p4info.txt",
            "BMV2File": "build/switch.json"
        }

        super(CounterController, self).__init__(switchName, configuration)

        self._logger.log(message="Switch class: Counter")