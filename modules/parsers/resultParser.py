from modules.logger import Logger, LoggingLevel
from modules.parsers import ConfigurationParser
from csv import reader as CSVReader
from csv import writer as CSVWriter

class ResultParser:
    def getTestResults(self):
        """
        Aggregates data from the positive and negative counters.
        """
        previous_data = []

        try:
            with open(self.__resultsFile, "r") as file:
                if not file.readable():
                    self.__logger.log(LoggingLevel.WARNING, "Cannot read previous results from file. If this is the first run ignore this warning.")
                else:
                    previous_data = list(CSVReader(file))
        except FileNotFoundError:
            self.__logger.log(LoggingLevel.WARNING, "Cannot read previous results from file. If this is the first run ignore this warning.")

        current_run = [
            self.__counters[0]["FalsePositives"],
            self.__counters[0]["TruePositives"],
            self.__counters[1]["FalseNegatives"],
            self.__counters[1]["TrueNegatives"]
        ]

        if None in current_run:
            self.__logger.log(LoggingLevel.ERROR, "Malformed counter data. Cannot record run.")
            self.__logger.log(LoggingLevel.DEBUG, f"Run statistics: {current_run}")
            return

        current_run.append(
            (current_run[1] + current_run[-1]) / sum(current_run))

        if previous_data == []:
            # Add header when this is the first run
            previous_data.append(["FalsePositives", "TruePositives", "FalseNegatives", "TrueNegatives", "Accuracy"])
        previous_data.append(current_run)

        with open(self.__resultsFile, "w") as file:
            if not file.writable():
                self.__logger.log(LoggingLevel.ERROR, f"Cannot write run statistics to file: {self.__resultsFile}")
            else:
                writer = CSVWriter(file)
                writer.writerows(previous_data)

    def __init__(self, positiveCounterFile: str = "data/positives.json", negativeCounterFile: str = "data/negatives.json", resultsFile: str = "data/result.csv"):
        self.__logger = Logger()
        self.__resultsFile = resultsFile
        self.__counters = [
            ConfigurationParser.JSONParser(positiveCounterFile),
            ConfigurationParser.JSONParser(negativeCounterFile)
        ]
        self.__logger.log(LoggingLevel.INFO, "Initialized ResultParser for data aggregation")