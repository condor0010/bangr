from binaryninja import BinaryView, Metadata
import json, zlib, base64

class bangr_bndb:
    
    def __init__(self, bangr_bv:BinaryView):
        self.__bv: BinaryView = bangr_bv
        self.bangr_created = {}
        
    def store(self, key: str, value, compress: bool | None):
        
        written_type = type(value).__name__
        md = self.__encode(value, written_type, compress)
        self.__bv.store_metadata(key, md)
        if key in self.bangr_created.keys() and self.bangr_created[key] == written_type:
            raise Exception(f"Metadata already written for key and data type.\n Key: {key}, Data Type: {written_type}")
        else:
            self.bangr_created.update({key:written_type})
        
    
    def __encode(self, value, type: str, compress: bool | None) -> str:
        
        json_data = json.dumps(value).encode("ascii")
        
        if compress is not None and compress:
            return json.dumps({"type":f"{type}", "b64":base64.b64encode(zlib.compress(json_data)).decode("utf-8")})
        else:
            return json.dumps(value)
        
##################################################################################################
        
    def query(self, key:str, data_type: str) -> str:
        
        exists = key in self.bangr_created.keys()
        
        if not exists:
            Exception(f"No Metadata written for key.\n Key: {key}, Data Type: {data_type}")
        elif self.bangr_created[key] != data_type:
            raise Exception(f"No Metadata written for key and data type.\n Key: {key}, Data Type: {data_type}")
        
        data = self.__query(key)
        decompressed_data = self.__decode(data, data_type)
                
        if decompressed_data is not None:
            return decompressed_data
        elif type(data).__name__ == data_type:
            return data
        else:
            raise TypeError(f"Unexpected type in query_str: {data}, {type(data)}")
        
    def __decode(self, data, expected_type: str):
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
        
    
    def __query(self, key: str) -> str:
        meta: Metadata = self.__bv.query_metadata(key)
        return json.loads(meta)
        
        
        
if __name__ == "main":
        
    bndb = bangr_bndb(BinaryView())
    bndb.store("test", {"fell":"ow"}, True)
    print(bndb.query("test", "dict"))
