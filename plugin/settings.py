from binaryninja import Settings

class BangrSettings():
    """Initializing bANGR settings.
    """
    def __init__(self):
        self.__settings = Settings()
        self.__settings.register_group("bANGR", "bANGR")
        self.__settings.register_setting("bANGR.recursionDepth", """
            {
                "title" : "Recursion Depth",
                "type" : "number",
                "default" : 3,
                "minValue" : 0,
                "description" : "The recursion depth that bANGR will analyze.",
                "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
            }
            """)
        self.__settings.register_setting("bANGR.threadCount", """
            {
                "title" : "Thread Count",
                "type" : "number",
                "default" : 4,
                "minValue" : 0,
                "description" : "The number of threads used by bANGR",
                "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
            }
            """)
        self.__settings.register_setting("bANGR.LRUCache", """
            {
                "title" : "Max Memoization",
                "type" : "number",
                "default" : 0,
                "minValue" : 0,
                "description" : "The number of LRUCache items kept by bANGR",
                "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
            }
            """)
        