#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AWS DevSecOps Game - Main Launcher

This script launches the AWS DevSecOps Game with a terminal-based user interface.
"""

import os
import sys

# Ensure the working directory is the script directory
os.chdir(os.path.dirname(os.path.abspath(__file__)))

# Add the current directory to the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from game.engine import GameEngine
from game.cli.terminal_ui import TerminalUI

def main():
    """Main entry point for the game."""
    try:
        # Create and initialize game engine
        game_engine = GameEngine()
        
        # Create and run terminal UI
        terminal_ui = TerminalUI(game_engine)
        terminal_ui.run()
        
    except KeyboardInterrupt:
        print("\nGame terminated by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\nError running game: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

