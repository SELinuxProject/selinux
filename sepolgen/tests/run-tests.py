import unittest
import sys

sys.path.insert(0, "../src/.")
from test_access import *
from test_audit import *
from test_refpolicy import *
from test_refparser import *
from test_policygen import *
from test_matching import *
from test_interfaces import *
from test_objectmodel import *
from test_module import *

if __name__ == "__main__":
    unittest.main()
