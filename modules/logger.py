from modules.annotantions import singleton
from datetime import datetime
from enum import Enum

class LoggingLevel(Enum):
    DEBUG = 0
    INFO = 1
    WARNING = 2
    ERROR = 3

@singleton
class Logger:
    def log(self, logLevel: LoggingLevel = LoggingLevel.DEBUG, message: str = ""):
        """
        Logs a Control Plane message in a file.

        Args:
            logLevel (LoggingLevel): The level of the associated log message. Defaults to DEBUG
            message (str): The message to be logged.
        """
        if logLevel.value < self.__maxLevel or not self.__goodFile:
            return
        
        with open(self.__fileName, "a") as file:
            file.write(
                f"[{datetime.now()}][{logLevel.name}] {message}\n")

    def __init__(self, logFile: str = "logs/control_plane.log", logLevel: LoggingLevel = LoggingLevel.DEBUG):
        self.__maxLevel = logLevel
        self.__fileName = logFile
        self.__goodFile = True

        with open(self.__fileName, "w") as file:
            if not file.writable():
                self.__goodFile = False
                print("[ERROR] Cannot not write to log file: ", logFile)

        self.log(LoggingLevel.INFO, "Initialized Logging Service.")