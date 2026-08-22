"""``python -m guardllm.gateway``."""

import sys

from guardllm.gateway.server import main

if __name__ == "__main__":
    sys.exit(main())
