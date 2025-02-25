import sys, os

sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '..'))

sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../utils/'))

print(sys.path)

from modules.logger import Logger, LoggingLevel
from control_plane import execute_local_scenario, update_counter_data

from threading import Thread
from argparse import ArgumentParser
from time import sleep

import control_plane

if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument("--loglevel", type=int, help="The lowest logging level allowed.", default=0)
    parser.add_argument("--logfile", type=str, help="The output of the logs.", default="logs/control_plane.log")
    parser.add_argument("--topofile", type=str, help="The path to the topology file.", default="config/topology.json")
    parser.add_argument("--filterfile", type=str, help="The path to the filter config file.", default="config/filter.json")
    parser.add_argument("--resultsfile", type=str, help="The path to the results file.", default="data/results.csv")
    parser.add_argument("--scenario", type=str, help="The test scenario (cloud or local)", default="local")

    # Parse arguments
    args = parser.parse_args()

    if args.loglevel > LoggingLevel.ERROR.value:
        print("[ERROR] Invalid argument value for loglevel: ", args.loglevel)
        exit(1)
    if args.scenario != "local":
        print("[ERROR] Unsupported scenario: ", args.scenario)
        exit(1)

    # First initialization to set the highest logging level and file path
    logger = Logger(args.logfile, args.loglevel)
    control_plane.scenarios.state = 0

    # Run the control plane in a separate thread, and have this thread listen for start / stop commands
    scenario_thread = Thread(target=execute_local_scenario, args=([(args.topofile, args.filterfile, args.resultsfile)]), daemon=True)
    counter_thread = Thread(target=update_counter_data, daemon=True)
    scenario_thread.start()
    counter_thread.start()

    while True:    
        while control_plane.scenarios.state != 2:
            os.system("clear")
            print(f"Scenario running: [{control_plane.scenarios.state}]")
            print(f"---------------------------")
            print(f"Choose one of the following options:")
            print(f"\t1) Start a new test")
            print(f"\t2) Stop testing and collect results")
            print(f"\t3) Exit")
            print()

            try:
                option = int(input("Option: "))
            
                if option == 1:
                    logger.log(LoggingLevel.INFO, "Starting a new test.")
                    control_plane.scenarios.state = 1
                elif option == 2:
                    logger.log(LoggingLevel.INFO, "Testing stopped on main thread.")
                    logger.log(LoggingLevel.INFO, "Collecting test results.")
                    control_plane.scenarios.state = 2
                else:
                    control_plane.scenarios.state = 3
                    scenario_thread.join()
                    exit(0)
            except ValueError:
                continue