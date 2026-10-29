import os
import sys

# Make "import common" and "import abusech" work from the tests folder.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "feeds"))
