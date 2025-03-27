from binaryninja import BinaryView, Metadata
import json, zlib, base64

class bangr_bndb:
    """
    A wrapper to the BinaryNinja bndb API.
    """
    
    def __init__(self, bangr_bv:BinaryView):
        """
        A wrapper to the BinaryNinja bndb API.

        Args:
            bangr_bv (BinaryView): The current BinaryView.
        """
        self.__bv: BinaryView = bangr_bv
        
    def store(self, key: str, value, compress: bool | None) -> str | None:
        """
        Stores a python data structure supported by the json module to the bndb.
        Args:
            key (str): The key to paired with the data in the bndb.
            value (Any): The python data structure to be stored to the bndb.
            compress (bool | None): Compress the data with zlib.

        Returns:
            str | None: This function will return the json string saved to the bndb.
        """
        
        written_type = type(value).__name__
        md = self.__encode(value, written_type, compress)
        self.__bv.store_metadata(key, md)
        return md

        
    
    def __encode(self, value, type: str, compress: bool | None) -> str:
        """Encodes the data in json.

        Args:
            value (Any): The data that is being serialized to json.
            type (str): The type of the data.
            compress (bool | None): Compress the data with zlib.

        Returns:
            str: This function will return the json serialized string of the 'value' parameter.
        """
        
        json_data = json.dumps(value).encode("ascii")
        
        if compress is not None and compress:
            return json.dumps({"type":f"{type}", "b64":base64.b64encode(zlib.compress(json_data)).decode("utf-8")})
        else:
            return json.dumps(value)
        
##################################################################################################
        
    def query(self, key:str, data_type: str) -> str | None:
        """Queries the bndb for the data that is paired with the key.
        
        Args:
            key (str): The key of the data in the bndb
            data_type (str): The data type expected from the key

        Raises:
            TypeError: If the type of the data queried does not match what is expected then it will raise an error.

        Returns:
            str | None: This function will return the data saved on the bndb. If the key does not exist then it will return None.
        """
        
        data = self.__query(key)
        decompressed_data = self.__decode(data, data_type)
                
        if decompressed_data is not None:
            return decompressed_data
        elif type(data).__name__ == data_type or data is None:
            return data
        else:
            raise TypeError(f"Unexpected type in query_str: {data}, {type(data)}")
        
    def __decode(self, data, expected_type: str):
        """Decodes the queried json.

        Args:
            data (Any): The json to be decoded.
            expected_type (str): The expected type of the data.

        Raises:
            TypeError: Invalid type for expected type for decompression.
            TypeError: Invalid keys in json.

        Returns:
            Any | None: Returns the expected type or None.
        """

        if type(data) == dict:
            if "type" in data.keys():
                if data["type"] == expected_type:
                    return json.loads(zlib.decompress(base64.b64decode(data["b64"])))
                else:
                    raise TypeError(f"Invalid query function for key.\nExpected Type: {expected_type}, data: {data}")
            else:
                if expected_type == "dict":
                    return data
                else:
                    raise TypeError(f"Invalid dictionary for decompression: {data}")
        return None
        
    
    def __query(self, key: str) -> str | None:
        try:
            meta: Metadata = self.__bv.query_metadata(key)
        except KeyError:
            return None
        return json.loads(meta)
    
##################################################################################################

    def remove(self, key: str) -> None:
        """Removes metadata from the bndb.

        Args:
            key (str): _description_
        """
        self.__bv.remove_metadata(key)
        
        
if __name__ == "main":
        
    bndb = bangr_bndb(BinaryView())
    bndb.store("test", {"fell":"ow"}, True)
    print(bndb.query("test", "dict"))