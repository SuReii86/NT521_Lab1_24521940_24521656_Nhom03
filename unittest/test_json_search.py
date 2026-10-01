import unittest
from recursive_json_search import *
from test_data import *


class json_search_test(unittest.TestCase):
    '''test module to test search function in `recursive_json_search.py`'''

    # ---- Test chức năng gốc ----
    def test_search_found(self):
        '''key should be found, return list should not be empty'''
        self.assertTrue([] != json_search(key1, data))

    def test_search_not_found(self):
        '''key should not be found, should return an empty list'''
        self.assertTrue([] == json_search(key2, data))

    def test_is_a_list(self):
        '''Should return a list'''
        self.assertIsInstance(json_search(key1, data), list)

    # ---- Security test (theo threat_model.md) ----
    def test_security_role_access_control(self):
        '''SR1: VIEWER is denied apiKey (SNMP credential), ADMIN is allowed'''
        with self.assertRaises(PermissionError):
            json_search("apiKey", data, "VIEWER")
        self.assertEqual(json_search("apiKey", data, "ADMIN"),
                         [{"apiKey": "SNMP-COMMUNITY-STRING-7f3a9c"}])

    def test_security_nested_fields_filtered(self):
        '''SR2: searching a container as VIEWER must not leak sensitive child fields'''
        out = str(json_search("deviceDetails", data, "VIEWER"))
        for leaked in ("apiKey", "SNMP-COMMUNITY-STRING", "macAddress", "serialNumber"):
            self.assertNotIn(leaked, out)

    def test_security_circular_reference(self):
        '''SR5: circular reference must not cause infinite recursion'''
        c = {"issueSummary": "ok"}
        c["self"] = c
        self.assertEqual(json_search("issueSummary", c), [{"issueSummary": "ok"}])


if __name__ == '__main__':
    unittest.main()