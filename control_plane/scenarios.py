from modules.parsers import ConfigurationParser, ResultParser
from modules.controllers import CounterController

from control_plane import ControlPlaneAlgorithm
from json import dumps
from time import sleep

# Shared variable
global state

def update_counter_data():
    global state
    counterSwitch = CounterController("s2")

    counterSwitch.writeIPForwardingRules()
    counterSwitch.writeCounterRules()
    counterSwitch.readTableRules()

    while state != 3:
        while state == 1:
            # Update counters
            positives = [
                counterSwitch.getByteCounter("positives", 0, "Packets"),
                counterSwitch.getByteCounter("positives", 1, "Packets"),
            ]

            with open("data/positives.json", "w") as file:
                file.write(dumps({
                    "TruePositives": positives[0],
                    "FalsePositives": positives[1]
                }))


def execute_local_scenario(configuration):
    global state
    topofile, filterfile, resultsfile = configuration
    configuration = ConfigurationParser(topofile, filterfile)

    algorithm = ControlPlaneAlgorithm(configuration["filter"])

    while state != 3:
        while state == 1:
            algorithm.filterTraffic()
            sleep(1)
        
        if state == 2:
            parser = ResultParser(resultsFile=resultsfile)
            parser.getTestResults()
            state = 0