from annotantions import singleton
from enum import Enum
from datetime import datetime

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
        if logLevel < self.__maxLevel or not self.__goodFile:
            return
        
        self.__file.write(
            f"[{datetime.now().timestamp()}][{logLevel.name}] {message}\n")

    def __init__(self, logFile: str = "logs/control_plane.log", logLevel: LoggingLevel = LoggingLevel.INFO):
        self.__file = open(logFile, "w")
        self.__maxLevel = logLevel
        self.__goodFile = True

        if not self.__file.writable():
            self.__goodFile = False
            print("[ERROR] Cannot not write to log file: ", logFile)

        self.log(LoggingLevel.INFO, "Initialized Logging Service.")

    def __del__(self):
        # Ensure the file is closed upon destruction
        if self.__file.fileno() != -1:
            self.__file.close() 