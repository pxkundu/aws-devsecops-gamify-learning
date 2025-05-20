#!/usr/bin/env python3
"""
AWS DevSecOps Game - A terminal-based learning game for AWS DevSecOps best practices.
"""

import sys
import logging
from rich.logging import RichHandler

from game.cli.menu import MainMenu
from game.utils.aws_handler import AWSHandler
from game.utils.game_state import GameState

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)]
)
log = logging.getLogger("aws_devsecops_game")

def main():
    """Main entry point for the game."""
    log.info("Starting AWS DevSecOps Game...")
    
    # Initialize AWS handler and validate credentials
    aws_handler = AWSHandler()
    if not aws_handler.validate_credentials():
        log.error("Failed to validate AWS credentials. Please ensure you have valid AWS credentials configured.")
        sys.exit(1)
    
    # Initialize game state
    game_state = GameState()
    
    # Start the main menu
    menu = MainMenu(game_state, aws_handler)
    menu.display()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting AWS DevSecOps Game. Thank you for playing!")
        sys.exit(0)
    except Exception as e:
        log.exception(f"Unexpected error: {e}")
        sys.exit(1)

