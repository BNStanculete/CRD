from modules.logger import Logger, LoggingLevel
from json import load, JSONDecodeError
from magic import Magic

class ConfigurationParser:
    def __init__(self, topologyFile: str = "config/topology.json", filterFile: str = "config/filter.json"):
        self.__logger = Logger()
        self.__configs = {
            "topology": ConfigurationParser.JSONParser(topologyFile),
            "filter": ConfigurationParser.JSONParser(filterFile)
        }

    def __getattribute__(self, name: str):
        """
        Gives access to a specific configuration.

        Args:
            name (str): The name of the configuration
        """
        if name in ["topology", "filter"]:
            return self.__configs[name]
        else:
            self.__logger.log(LoggingLevel.WARNING, f"Invalid configuration type: {name}")
            return None

    class JSONParser:
        def __init__(self, configFile: str = ""):
            self.__logger = Logger()
            self.__logger.log(LoggingLevel.INFO, "Initialized ConfigurationParser.")
            self.__loadedJSON = False

            mime = Magic(mime=True)
            if not mime.from_file(configFile) in ["application/json", "text/plain"]:
                self.__logger.log(LoggingLevel.ERROR, f"Invalid file type for configuration: {configFile} !")
                return

            try:
                with open(configFile, "r") as file:
                    if not file.readable():
                        self.__logger.log(LoggingLevel.ERROR, f"Configuration file is not readable: {configFile} !")
                        return

                    self.__config = load(file)
                    self.__loadedJSON = True
            except JSONDecodeError as err:
                self.__logger.log(LoggingLevel.ERROR, f"Error parsing configuration file: {configFile} !")

        def __getattribute__(self, name: str = ""):
            """
            Retrieves a specific configuration option
            """
            if not self.__loadedJSON:
                self.__logger.log(message="Attempt to load data from missing configuration.")
                return None

            if name not in self.__config:
                self.__logger.log(LoggingLevel.WARNING, f"Invalid configuration option: {name}")
                return None
            
            return self.__config[name]
