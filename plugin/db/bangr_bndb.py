import json, zlib, base64, atexit
from binaryninja import BinaryView

class BangrBndb:
    """
    A wrapper to the BinaryNinja bndb API.
    """
    
    def __init__(self, bangr_bv:BinaryView):
        """A wrapper to the BinaryNinja bndb API.

        Args:
            bangr_bv (BinaryView): The current BinaryView.
        """
        
        self.__bv: BinaryView = bangr_bv
        
        self.key_list = ["bangr_key_list"]
        temp = self.query("bangr_key_list", list)
        if temp is list:
            self.key_list = temp

        atexit.register(self.store_key_list)
        return
        
    def store(self, key: str, value, compress: bool | None = None) -> int | None:
        """Stores a python data structure supported by the json module to the bndb.

        Args:
            key (str): The key to paired with the data in the bndb.
            value (Any): The python data structure to be stored to the bndb.
            compress (bool | None): Compress the data with zlib.

        Returns:
            str | None: This function will return the size of the data saved to the bndb.
        """
        
        md = self.__encode(value, compress)

        if md is not None:
            self.__bv.store_metadata(key, md)
            self.key_list.append(key)
            # print(md)
            return len(md)
        else:
            return None

        
    
    def __encode(self, value, compress: bool | None  = None) -> str | None:
        """Encodes the data in json.

        Args:
            value (Any): The data that is being serialized to json.
            compress (bool | None): Compress the data with zlib.

        Returns:
            str | None: This function will return the json serialized string of the 'value' parameter.
        """
        
        try:
            json_data = json.dumps(value).encode("ascii")
        except TypeError:
            return None
        
        if compress is not None and compress:
            try:
                return json.dumps({"bangr_type":f"{type(value).__name__}", "b64":base64.b85encode(zlib.compress(json_data, 9)).decode("utf-8")})
            except TypeError:
                return None
        else:
            try:
                return json.dumps(value)
            except TypeError:
                return None
        
    ##############################################################################################
        
    def query(self, key:str, query_data_type: object):
        """Queries the bndb for the data that is paired with the key.
        
        Args:
            key (str): The key of the data in the bndb.
            data_type (object): The data type expected from the key.

        Returns:
            Any | None: This function will return the data saved on the bndb. If the key does not exist then it will return None.
        """
        
        data = self.__decode(self.__query(key), query_data_type)
                
        return data
        
    def __decode(self, json_string, expected_type: object):
        """Decodes the queried json.

        Args:
            data (Any): The json to be decoded.
            expected_type (object): The expected type of the data.

        Raises:
            TypeError: Invalid type for expected type for decompression.
            TypeError: Invalid keys in json.

        Returns:
            Any | None: Returns the expected type or None.
        """
        try:
            json_data = json.loads(json_string)
        except (KeyError, TypeError):
            return None
        if isinstance(json_data, dict):
            if "bangr_type" in json_data.keys():
                if json_data["bangr_type"] == expected_type.__name__:
                    if "b64" in json_data.keys():
                        return json.loads(zlib.decompress(base64.b85decode(json_data["b64"])))
                    else: 
                        return None
                else:
                    print(f"Invalid query function for key.\nExpected Type: {expected_type}, data: {json_data}")
                    return None
            else:
                if expected_type == dict:
                    return json_data
                else:
                    print(f"Invalid dictionary for decompression: {json_data}")
                    return None
        elif isinstance(json_data, expected_type):
            return json_data
        else:
            return None
        
    
    def __query(self, key: str) -> str | None:
        """Queries bndb for metadata.

        Args:
            key (str): The key to query from the bndb.

        Returns:
            str | None: Returns metadata string or None if metadata is not found.
        """
        try:
            metadata: str = self.__bv.query_metadata(key)
        except KeyError:
            return None
        return metadata
    
    ##############################################################################################

    def remove(self, key: str) -> None:
        """Removes metadata from the bndb.

        Args:
            key (str): The key for the metadata to remove.
        """
        
        self.__bv.remove_metadata(key)
        
        try:
            self.key_list.remove(key)
        except ValueError:
            pass
        return
    
    def remove_all(self):
        
        for key in self.key_list:
            self.remove(key)
        self.key_list.clear()


    ##############################################################################################

    def store_key_list(self):
        self.store("bangr_key_list", self.key_list, True)
        return