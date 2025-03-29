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
        