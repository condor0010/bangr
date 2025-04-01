import unittest
from random import randint, choice
from bangr_bndb import BangrBndb
from binaryninja import BinaryView

class StoreAndQuery(unittest.TestCase):

    def setUp(self):
        self.bdb: BangrBndb = BangrBndb(BinaryView())
        self.test_str: str = """
        Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.
        """
    
    def tearDown(self):
        self.bdb.remove("test")

    def test_SAQString(self):
        print("StoreAndQuery String")
        size = self.bdb.store("test", self.test_str)
        print(f"Size: {size}")
        ret = self.bdb.query("test", str)
        self.assertEqual(self.test_str, ret)

    def test_SAQStringCompress(self):
        print("StoreAndQuery String Compressed")
        size = self.bdb.store("test", self.test_str, True)
        print(f"Size: {size}")
        ret = self.bdb.query("test", str)
        self.assertEqual(self.test_str, ret)
    
    def test_SAQInt(self):
        print("StoreAndQuery Int")
        rand = randint(0, 2**32)
        size = self.bdb.store("test", rand)
        print(f"Size: {size}")
        ret = self.bdb.query("test", int)
        self.assertEqual(rand, ret)

    def test_SAQIntCompressed(self):
        print("StoreAndQuery Int Compressed")
        rand = randint(2**8, 2**32)
        size = self.bdb.store("test", rand, True)
        print(f"Size: {size}")
        ret = self.bdb.query("test", int)
        self.assertEqual(rand, ret)

    def test_SAQList(self):
        print("StoreAndQuery List")
        test_list = [randint(2**8, 2**32) for i in range(randint(128, 256))]
        size = self.bdb.store("test", test_list)
        print(f"Size: {size}")
        ret = self.bdb.query("test", list)
        self.assertEqual(test_list, ret)

    def test_SAQListCompressed(self):
        print("StoreAndQuery List Compressed")
        test_list = [randint(2**8, 2**32) for i in range(randint(128, 256))]
        size = self.bdb.store("test", test_list, True)
        print(f"Size: {size}")
        ret = self.bdb.query("test", list)
        self.assertEqual(test_list, ret)

    def test_SAQDict(self):
        print("StoreAndQuery Dict")
        test_dict = {}
        s_split = self.test_str.split()
        for _ in range(128):
            if randint(0, 1) == 0:
                test_dict.update({choice(s_split): randint(2**8, 2**32)})
            else:
                test_dict.update({choice(s_split): choice(s_split)})
        size = self.bdb.store("test", test_dict)
        print(f"Size: {size}")
        ret = self.bdb.query("test", dict)
        self.assertEqual(test_dict, ret)

    def test_SAQDictCompressed(self):
        print("StoreAndQuery Dict Compressed")
        test_dict = {}
        s_split = self.test_str.split()
        for _ in range(128):
            if randint(0, 1) == 0:
                test_dict.update({choice(s_split): randint(2**8, 2**32)})
            else:
                test_dict.update({choice(s_split): choice(s_split)})
        size = self.bdb.store("test", test_dict, True)
        print(f"Size: {size}")
        ret = self.bdb.query("test", dict)
        self.assertEqual(test_dict, ret)


class TypeProblems(unittest.TestCase):

    def setUp(self):
        self.bdb: BangrBndb = BangrBndb(BinaryView())
    
    def tearDown(self):
        self.bdb.remove("test")
    
    def test_TPQueryWrong(self):
        print("TypeProblemsQueryWrong")
        self.bdb.store("test", 3)
        ret = self.bdb.query("test", str)
        self.assertIs(ret, None)
    
    def test_TPQueryWrongCompressed(self):
        print("TypeProblemsQueryWrongCompressed")
        self.bdb.store("test", 3, True)
        ret = self.bdb.query("test", str)
        self.assertIs(ret, None)

    def test_TPQueryMissing(self):
        print("TypeProblemsQueryMissing")
        ret = self.bdb.query("test", int)
        self.assertIs(ret, None)

    def test_TPRemoveMissing(self):
        print("TypeProblemsRemoveMissing")
        self.bdb.remove("test")

class StoreRemoveQuery(unittest.TestCase):

    def setUp(self):
        self.bdb: BangrBndb = BangrBndb(BinaryView())
        self.test_str: str = """
        Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.
        """
    
    def test_SRQString(self):
        print("StoreRemoveQuery String")
        size = self.bdb.store("test", self.test_str)
        print(f"Size: {size}")
        self.bdb.remove("test")
        ret = self.bdb.query("test", str)
        self.assertIs(ret, None)

    def test_SRQStringCompressed(self):
        print("StoreRemoveQuery String Compressed")
        size = self.bdb.store("test", self.test_str, True)
        print(f"Size: {size}")
        self.bdb.remove("test")
        ret = self.bdb.query("test", str)
        self.assertIs(ret, None)

    def test_SRQInt(self):
        print("StoreRemoveQuery Int")
        rand = randint(0, 2**32)
        size = self.bdb.store("test", rand)
        print(f"Size: {size}")
        self.bdb.remove("test")
        ret = self.bdb.query("test", int)
        self.assertIs(ret, None)

    def test_SRQIntCompressed(self):
        print("StoreRemoveQuery Int Compressed")
        rand = randint(0, 2**32)
        size = self.bdb.store("test", rand, True)
        print(f"Size: {size}")
        self.bdb.remove("test")
        ret = self.bdb.query("test", int)
        self.assertIs(ret, None)

    def test_SRQList(self):
        print("StoreRemoveQuery List")
        test_list = [randint(2**8, 2**32) for i in range(randint(128, 256))]
        size = self.bdb.store("test", test_list)
        self.bdb.remove("test")
        print(f"Size: {size}")
        ret = self.bdb.query("test", list)
        self.assertIs(ret, None)

    def test_SRQListCompressed(self):
        print("StoreRemoveQuery List")
        test_list = [randint(2**8, 2**32) for i in range(randint(128, 256))]
        size = self.bdb.store("test", test_list, True)
        self.bdb.remove("test")
        print(f"Size: {size}")
        ret = self.bdb.query("test", list)
        self.assertIs(ret, None)

    def test_SRQDict(self):
        print("StoreRemoveQuery Dict")
        test_dict = {}
        s_split = self.test_str.split()
        for _ in range(128):
            if randint(0, 1) == 0:
                test_dict.update({choice(s_split): randint(2**8, 2**32)})
            else:
                test_dict.update({choice(s_split): choice(s_split)})
        size = self.bdb.store("test", test_dict)
        self.bdb.remove("test")
        print(f"Size: {size}")
        ret = self.bdb.query("test", dict)
        self.assertIs(ret, None)

    def test_SRQDictCompressed(self):
        print("StoreRemoveQuery Dict Compressed")
        test_dict = {}
        s_split = self.test_str.split()
        for _ in range(128):
            if randint(0, 1) == 0:
                test_dict.update({choice(s_split): randint(2**8, 2**32)})
            else:
                test_dict.update({choice(s_split): choice(s_split)})
        size = self.bdb.store("test", test_dict, True)
        self.bdb.remove("test")
        print(f"Size: {size}")
        ret = self.bdb.query("test", dict)
        self.assertIs(ret, None)

class StoreReplace(unittest.TestCase):

    def setUp(self):
        self.bdb: BangrBndb = BangrBndb(BinaryView())
        self.test_str: str = """
        Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.
        """
    
    def tearDown(self):
        self.bdb.remove("test")

    def test_SRString(self):
        print("StoreReplace String")
        replacement = "replaced"
        size = self.bdb.store("test", self.test_str)
        print(f"Size: {size}")
        size = self.bdb.store("test", replacement)
        print(f"Size: {size}")
        ret = self.bdb.query("test", str)
        self.assertEqual(replacement, ret)

    def test_SRStringCompressed(self):
        print("StoreReplace String Compressed")
        size = self.bdb.store("test", self.test_str, True)
        print(f"Size: {size}")
        replacement = "replaced"
        size = self.bdb.store("test", replacement, True)
        print(f"Size: {size}")
        ret = self.bdb.query("test", str)
        self.assertEqual(replacement, ret)

    def test_SRInt(self):
        print("StoreReplace Int")
        rand = randint(0, 2**32)
        size = self.bdb.store("test", rand)
        print(f"Size: {size}")
        replacement = randint(0, 2**32)
        size = self.bdb.store("test", replacement)
        print(f"Size: {size}")
        ret = self.bdb.query("test", int)
        self.assertEqual(replacement, ret)

    def test_SRIntCompressed(self):

        print("StoreReplace Int Compressed")

        rand = randint(0, 2**32)

        size = self.bdb.store("test", rand, True)
        print(f"Size: {size}")

        replacement = randint(0, 2**32)

        size = self.bdb.store("test", replacement, True)
        print(f"Size: {size}")
        
        ret = self.bdb.query("test", int)
        self.assertEqual(replacement, ret)
        
    def test_SRList(self):

        print("StoreReplace List")

        test_list = [randint(2**8, 2**32) for i in range(randint(128, 256))]
        
        size = self.bdb.store("test", test_list)
        print(f"Size: {size}")

        replacement = [randint(2**8, 2**32) for i in range(randint(128, 256))]

        size = self.bdb.store("test", replacement)
        print(f"Size: {size}")

        ret = self.bdb.query("test", list)
        self.assertEqual(replacement, ret)

    def test_SRListCompressed(self):\
    
        print("StoreReplace List Compressed")

        test_list = [randint(2**8, 2**32) for i in range(randint(128, 256))]
        
        size = self.bdb.store("test", test_list, True)
        print(f"Size: {size}")

        replacement = [randint(2**8, 2**32) for i in range(randint(128, 256))]

        size = self.bdb.store("test", replacement, True)
        print(f"Size: {size}")

        ret = self.bdb.query("test", list)
        self.assertEqual(replacement, ret)

    def test_SRDict(self):

        print("StoreReplace Dict")

        test_dict = {}
        s_split = self.test_str.split()

        for _ in range(128):
            if randint(0, 1) == 0:
                test_dict.update({choice(s_split): randint(2**8, 2**32)})
            else:
                test_dict.update({choice(s_split): choice(s_split)})

        size = self.bdb.store("test", test_dict)
        print(f"Size: {size}")

        replacement = {}

        for _ in range(128):
            if randint(0, 1) == 0:
                replacement.update({choice(s_split): randint(2**8, 2**32)})
            else:
                replacement.update({choice(s_split): choice(s_split)})

        size = self.bdb.store("test", replacement)
        print(f"Size: {size}")

        ret = self.bdb.query("test", dict)
        self.assertEqual(replacement, ret)

    def test_SRDictCompressed(self):

        print("StoreReplace Dict Compressed")

        test_dict = {}
        s_split = self.test_str.split()

        for _ in range(128):
            if randint(0, 1) == 0:
                test_dict.update({choice(s_split): randint(2**8, 2**32)})
            else:
                test_dict.update({choice(s_split): choice(s_split)})
    
        size = self.bdb.store("test", test_dict)
        print(f"Size: {size}")

        replacement = {}

        for _ in range(128):
            if randint(0, 1) == 0:
                replacement.update({choice(s_split): randint(2**8, 2**32)})
            else:
                replacement.update({choice(s_split): choice(s_split)})

        size = self.bdb.store("test", replacement)
        print(f"Size: {size}")

        ret = self.bdb.query("test", dict)
        self.assertEqual(replacement, ret)

    

if __name__ == '__main__':
    unittest.main()