import os
import sys

HERE = os.path.dirname(__file__)

# Make "import common", "import score" and "import vt" work from the tests folder.
for folder in ("feeds", "scoring", "enrichment", "dashboard"):
    sys.path.insert(0, os.path.join(HERE, "..", folder))
