"""
Main menu interface for the AWS DevSecOps Game, built with Rich.
"""

import os
import sys
import logging
from typing import Optional, Dict, List, Callable

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.markdown import Markdown
from rich.text import Text

from game.utils.game_state import GameState
from game.utils.aws_handler import AWSHandler

log = logging.getLogger("aws_devsecops_game")

console = Console()

class MainMenu:
    """Main menu interface for the AWS DevSecOps Game."""
    
    def __init__(self, game_state: GameState, aws_handler: AWSHandler):
        """
        Initialize the main menu.
        
        Args:
            game_state: GameState object to manage game progress
            aws_handler: AWSHandler object for AWS operations
        """
        self.game_state = game_state
        self.aws_handler = aws_handler
        self.console = Console()
        self.menu_options = {
            "1": ("New Game", self.new_game),
            "2": ("Continue Game", self.continue_game),
            "3": ("Help", self.show_help),
            "4": ("About", self.show_about),
            "5": ("Exit", self.exit_game),
        }
    
    def clear_screen(self):
        """Clear the terminal screen."""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def display_header(self):
        """Display the game header."""
        self.clear_screen()
        header_text = Text()
        header_text.append("AWS DevSecOps Game", style="bold green")
        header_text.append("\nLearn AWS security best practices through interactive challenges", style="italic")
        
        self.console.print(Panel(header_text, expand=False))
    
    def display(self):
        """Display the main menu and handle user input."""
        while True:
            self.display_header()
            
            # Show menu options
            table = Table(show_header=False, box=None)
            table.add_column("Option", style="cyan")
            table.add_column("Description")
            
            for key, (option_text, _) in self.menu_options.items():
                table.add_row(f"[{key}]", option_text)
            
            self.console.print(table)
            
            # Get user choice
            choice = Prompt.ask("Select an option", choices=list(self.menu_options.keys()))
            
            # Execute the selected option
            _, action = self.menu_options[choice]
            action()
    
    def new_game(self):
        """Start a new game."""
        self.display_header()
        
        # Check if there's an existing game
        if self.game_state.has_saved_game() and not Confirm.ask("Starting a new game will erase your previous progress. Continue?"):
            return
        
        # Create a new game state
        self.game_state.reset()
        self.game_state.save()
        
        self.console.print(Panel("New game created! You're ready to start your DevSecOps journey.", title="New Game"))
        
        # Ask for user name
        player_name = Prompt.ask("What's your name?")
        self.game_state.set_player_name(player_name)
        self.game_state.save()
        
        self.console.print(f"Welcome, {player_name}!")
        Prompt.ask("Press Enter to continue")
        
        # Start the first scenario
        self.start_game()
    
    def continue_game(self):
        """Continue an existing game."""
        self.display_header()
        
        if not self.game_state.has_saved_game():
            self.console.print(Panel("No saved game found. Please start a new game.", title="Continue Game"))
            Prompt.ask("Press Enter to continue")
            return
        
        if not self.game_state.load():
            self.console.print(Panel("Failed to load saved game. Please start a new game.", title="Continue Game"))
            Prompt.ask("Press Enter to continue")
            return
        
        self.console.print(Panel(f"Welcome back, {self.game_state.player_name}!\nResuming from level: {self.game_state.current_level}", title="Continue Game"))
        Prompt.ask("Press Enter to continue")
        
        # Start the game at the current level
        self.start_game()
    
    def start_game(self):
        """Start or resume the game at the current level."""
        self.display_header()
        self.console.print("Game would start here with the current level loaded.")
        # TODO: Implement actual game loading and scenario management
        Prompt.ask("Game implementation pending. Press Enter to return to the main menu")
    
    def show_help(self):
        """Display help information."""
        self.display_header()
        
        help_text = """
        # AWS DevSecOps Game Help
        
        This game helps you learn AWS security best practices through interactive challenges.
        
        ## Game Controls
        - Use the number keys to select menu options
        - Press Enter to confirm selections
        - Press Ctrl+C at any time to exit
        
        ## Game Objectives
        - Complete security challenges to earn points
        - Learn practical AWS security skills
        - Apply DevSecOps best practices in real-world scenarios
        
        ## AWS Access
        The game uses read-only AWS operations by default. Any operation that would create, 
        modify, or delete resources will be clearly marked and requires confirmation.
        """
        
        self.console.print(Markdown(help_text))
        Prompt.ask("Press Enter to continue")
    
    def show_about(self):
        """Display information about the game."""
        self.display_header()
        
        about_text = """
        # About AWS DevSecOps Game
        
        This game was created to help cloud practitioners learn AWS security best practices
        in an interactive and engaging way.
        
        ## Features
        - Hands-on learning with real AWS services
        - Progressive difficulty across multiple scenarios
        - Focus on DevSecOps principles
        - Safe, read-only interactions with AWS
        
        ## Topics Covered
        - IAM permissions and least privilege
        - Security group configurations
        - Cloud infrastructure security
        - Compliance and audit
        - Container security
        - CI/CD security integration
        """
        
        self.console.print(Markdown(about_text))
        Prompt.ask("Press Enter to continue")
    
    def exit_game(self):
        """Exit the game."""
        self.display_header()
        
        if Confirm.ask("Are you sure you want to exit?"):
            self.console.print("Thank you for playing the AWS DevSecOps Game!")
            sys.exit(0)

