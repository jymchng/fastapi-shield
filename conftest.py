import os
import sys

ROOT = os.path.dirname(__file__)
SRC = os.path.join(ROOT, "src")
EXAMPLES_APP_SRC = os.path.join(ROOT, "examples", "app", "src")
EXAMPLES_APP_PKG = os.path.join(EXAMPLES_APP_SRC, "app")

for p in (SRC, EXAMPLES_APP_SRC, EXAMPLES_APP_PKG):
    if p not in sys.path:
        sys.path.insert(0, p)
