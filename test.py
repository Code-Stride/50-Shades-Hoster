# -*- coding: utf-8 -*-
# Wrapper for modularized bot code to maintain full backward-compatibility with existing runs.
import sys
import os

# Adjust path if needed to ensure local imports work
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from main import main

if __name__ == '__main__':
    main()
