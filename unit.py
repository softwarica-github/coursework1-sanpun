import unittest
from unittest.mock import Mock
from client import *

class TestClientFunctions(unittest.TestCase):

    def test_xor_cypher(self):
        input_string = "Hello, World!"
        key = "key"

        # Test encryption
        encrypted = xor_cypher(input_string, key)
        # Test decryption by applying the cipher again
        decrypted = xor_cypher(encrypted.decode('utf-8'), key).decode('utf-8')

        # Check if the decrypted text matches the original input
        self.assertEqual(input_string, decrypted)

if __name__ == '__main__':
    unittest.main() 