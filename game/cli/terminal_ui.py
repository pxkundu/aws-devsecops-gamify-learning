#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AWS DevSecOps Game - Terminal User Interface

This module provides a terminal-based user interface for the AWS DevSecOps learning game.
It uses prompt_toolkit to create an interactive terminal experience with menus,
keyboard navigation, and rich formatting.
"""

import os
import sys
from typing import List, Dict, Any, Optional, Callable
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from game.engine import GameEngine, Challenge

# Initialize Rich console for formatted output
console = Console()

# ASCII Art for game title
ASCII_TITLE = r"""
  _____  _____ _____ _____                                                                
 |  __ \|  ___|_   _|_   _|                                                               
 | |  \/| |__   | |   | |                                                                 
 | | __ |  __|  | |   | |                                                                 
 | |_\ \| |___  | |   | |                                                                
  \____/\____/  \_/   \_/                                                                 
                                                                                          
    ___         _      ___                _____                                           
   /   \ _ __  | |    / _ \  ___  _   _  /__   \ ___   _ __   ___                        
  / /\ /| '_ \ | |   | | | |/ _ \| | | |   / /\// _ \ | '_ \ / __|                       
 / /_// | | | || |___| |_| |  __/| |_| |  / /  | (_) || |_) |\__ \                       
/___,'  |_| |_||_____|\_____\___| \__, | \/     \___/ | .__/ |___/                       
                                  |___/                |_|                                
"""

# Game menu options
MENU_OPTIONS = [
    ('start', 'Start Game', 'Begin from the first available challenge'),
    ('continue', 'Continue', 'Resume from last played challenge'),
    ('challenges', 'Challenges', 'Browse available challenges by category'),
    ('progress', 'Progress', 'View your current progress'),
    ('help', 'Help', 'Show help and instructions'),
    ('exit', 'Exit', 'Exit the game')
]

# Simple style constants
CYAN = "[cyan]"
BLUE = "[blue]"
GREEN = "[green]"
YELLOW = "[yellow]"
RED = "[red]"
WHITE = "[white]"
BOLD = "[bold]"
DIM = "[dim]"
BOLD_BLUE = f"{BOLD}{BLUE}"
BOLD_GREEN = f"{BOLD}{GREEN}"
BOLD_RED = f"{BOLD}{RED}"
BOLD_YELLOW = f"{BOLD}{YELLOW}"


class MenuOption:
    """Represents a menu option with key, text, and description."""
    
    def __init__(self, key: str, text: str, description: str = ''):
        self.key = key
        self.text = text
        self.description = description
        self.selected = False
        
    def __repr__(self):
        return f"MenuOption(key={self.key}, text={self.text})"


class TerminalUI:
    """
    Terminal-based user interface for the AWS DevSecOps Game.
    
    Provides interactive menus, challenge selection, and game state visualization.
    """
    
    def __init__(self, game_engine: GameEngine):
        """
        Initialize the terminal UI with a game engine.
        
        Args:
            game_engine: The game engine to use for game state and operations
        """
        self.game_engine = game_engine
        
        # Initialize UI state
        self.current_menu = [MenuOption(key, text, desc) for key, text, desc in MENU_OPTIONS]
        self.current_view = 'main_menu'
        self.selected_category = None
        self.current_challenge = None
    
    def _handle_aws_warning(self):
        """Display a warning about missing AWS credentials but allow continuing."""
        warning_panel = Panel(
            f"{YELLOW}⚠ AWS credentials are not valid or not configured.{YELLOW}\n\n"
            "You can still:\n"
            "• Browse all challenges\n"
            "• Learn about AWS security concepts\n"
            "• Complete challenges that don't require AWS access\n\n"
            f"{DIM}To enable all features, configure valid AWS credentials and restart the game.{DIM}",
            title=f"{YELLOW}AWS Credentials Warning{YELLOW}",
            border_style="yellow"
        )
        console.print(warning_panel)
        console.print("\nPress Enter to continue...")
        input()

    def run(self):
        """Run the terminal UI application."""
        try:
            # Show splash screen
            console.print(f"{CYAN}{ASCII_TITLE}{CYAN}")
            console.print(f"\n{BOLD_BLUE}Welcome to the AWS DevSecOps Game!{BOLD_BLUE}")
            console.print(f"{WHITE}Learn AWS security best practices through interactive challenges.{WHITE}\n")
            
            # Initialize game engine
            if not self.game_engine.game_initialized:
                if not self.game_engine.initialize_game():
                    console.print(f"\n{BOLD_RED}Failed to initialize game. Exiting.{BOLD_RED}")
                    sys.exit(1)
                
                # Show welcome message if successful
                console.print(f"\n{BOLD_GREEN}Game initialized successfully!{BOLD_GREEN}")
                
                # Handle AWS credential warning if needed
                if not self.game_engine.aws_credentials_valid:
                    self._handle_aws_warning()
            
            # Main menu loop
            self._show_main_menu()
            while True:
                console.print(f"\n{BOLD_BLUE}Main Menu{BOLD_BLUE}")
                for i, option in enumerate(self.current_menu, 1):
                    console.print(f"{i}. {option.text}")
                console.print(f"\n{DIM}Enter q to quit, h for help, b to go back{DIM}")
                
                choice = console.input("\nSelect an option: ").strip().lower()
                
                if choice == 'q':
                    self._exit_game()
                    break
                elif choice == 'h':
                    self._show_help()
                    continue
                elif choice == 'b':
                    if self.current_view != 'main_menu':
                        self._go_back()
                    continue
                
                try:
                    index = int(choice) - 1
                    if 0 <= index < len(self.current_menu):
                        option = self.current_menu[index]
                        self._handle_selection(option)
                    else:
                        console.print(f"{RED}Invalid selection. Please try again.{RED}")
                except ValueError:
                    console.print(f"{RED}Invalid input. Please enter a number.{RED}")
                
        except KeyboardInterrupt:
            console.print("\nGame terminated by user.")
            sys.exit(0)
        except Exception as e:
            console.print(f"\n{BOLD_RED}Error running game: {e}{BOLD_RED}")
            import traceback
            console.print(traceback.format_exc())
            sys.exit(1)
    
    def _show_main_menu(self):
        """Show the main menu."""
        self.current_view = 'main_menu'
        self.current_menu = [MenuOption(key, text, desc) for key, text, desc in MENU_OPTIONS]
    
    def _handle_selection(self, option: MenuOption):
        """
        Handle menu option selection.
        
        Args:
            option: The selected menu option
        """
        # Handle navigation options
        if option.key == 'main_menu':
            self._show_main_menu()
            return
        elif option.key == 'back':
            self._go_back()
            return
        elif option.key == 'start_challenge':
            if self.current_challenge:
                self.game_engine.start_challenge(self.current_challenge)
            return
        elif option.key == 'view_solution':
            # TODO: Implement solution viewing
            console.print("\n[bold yellow]Solution view not yet implemented[/bold yellow]")
            input("\nPress Enter to continue...")
            return
            
        # Handle main menu options
        if self.current_view == 'main_menu':
            if option.key == 'start':
                self._start_game()
            elif option.key == 'continue':
                self._continue_game()
            elif option.key == 'challenges':
                self._show_challenge_categories()
            elif option.key == 'progress':
                self._show_progress()
            elif option.key == 'help':
                self._show_help()
            elif option.key == 'exit':
                self._exit_game()
        # Handle category selection
        elif self.current_view == 'categories':
            self.selected_category = option.key
            self._show_category_challenges(option.key)
        # Handle challenge selection
        elif self.current_view == 'challenges':
            self._show_challenge_details(option.key)
        # If we got here with an unknown option, log it
        else:
            logger.warning(f"Unknown option or view: {option.key} in view {self.current_view}")
    
    def _go_back(self):
        """
        Go back to the previous screen.
        """
        if self.current_view == 'challenges':
            self._show_challenge_categories()
        elif self.current_view == 'challenge_details':
            self._show_category_challenges(self.selected_category)
        else:
            self._show_main_menu()
    
    def _exit_game(self):
        """
        Exit the game.
        """
        # Save progress before exiting
        self.game_engine.save_progress()
        sys.exit(0)
    
    def _show_challenge_categories(self):
        """Show the challenge categories."""
        self.current_view = 'categories'
        
        # Create menu options from categories
        categories = []
        for cat_name, cat_data in self.game_engine.categories.items():
            if cat_data.get('enabled', True):
                icon = cat_data.get('icon', '🔷')
                desc = cat_data.get('description', '')
                categories.append(MenuOption(cat_name, f"{icon} {cat_name}", desc))
        
        self.current_menu = categories
    
    def _show_category_challenges(self, category: str):
        """
        Show challenges for a specific category.
        
        Args:
            category: The category to show challenges for
        """
        self.current_view = 'challenges'
        
        # Get challenges for this category
        challenges = [
            c for c in self.game_engine.challenges.values()
            if c.category == category
        ]
        
        # Sort by difficulty
        difficulty_order = {
            "Beginner": 1,
            "Intermediate": 2,
            "Advanced": 3
        }
        challenges.sort(key=lambda c: difficulty_order.get(c.difficulty, 999))
        
        # Create menu options
        options = []
        for challenge in challenges:
            # Determine if challenge is locked (prerequisites not met)
            prerequisites_met = self.game_engine.check_prerequisites(challenge.id)
            
            # Set status icon
            if challenge.completed:
                status = "✓"
                status_text = "[completed]Completed[/completed]"
            elif not prerequisites_met:
                status = "🔒"
                status_text = "[locked]Locked[/locked]"
            else:
                status = "◯"
                status_text = "[not-completed]Not Started[/not-completed]"
                
            # Get difficulty styling
            diff_style = f"difficulty.{challenge.difficulty.lower()}"
            
            # Create menu option
            option_text = f"{status} {challenge.name} [{diff_style}]({challenge.difficulty})[/{diff_style}]"
            option_desc = f"{status_text} | Points: {challenge.points} | {challenge.estimated_time or 'No time estimate'}"
            
            options.append(MenuOption(challenge.id, option_text, option_desc))
                
            self.current_menu = options
    
    def _show_challenge_details(self, challenge_id: str):
        """
        Show details for a specific challenge.
        
        Args:
            challenge_id: The ID of the challenge to show
        """
        self.current_view = 'challenge_details'
        self.current_challenge = challenge_id
        
        challenge = self.game_engine.challenges[challenge_id]
        prerequisites_met = self.game_engine.check_prerequisites(challenge_id)
        
        # Create action options based on challenge state
        options = []
        
        if challenge.completed:
            # Challenge is already completed
            options.append(MenuOption(
                'view_solution', 
                '📖 View Solution', 
                'Review the solution for this challenge'
            ))
        elif prerequisites_met:
            # Challenge is available to start
            options.append(MenuOption(
                'start_challenge', 
                '▶️ Start Challenge', 
                'Begin this challenge'
            ))
        
        # Always add these options
        options.append(MenuOption(
            'back', 
            '⬅️ Back to Challenges', 
            'Return to challenge list'
        ))
        options.append(MenuOption(
            'main_menu', 
            '🏠 Main Menu', 
            'Return to main menu'
        ))
        
        self.current_menu = options
        
        # Display challenge details using Rich
        console.clear()
        
        # Show challenge details
        self.game_engine.display_challenge_info(challenge_id)
        
        # Wait for user to continue
        console.print("\n[dim]Press any key to continue...[/dim]")
        input()
    
    def _start_game(self):
        """Start the game from the beginning."""
        # Get the first challenge in the beginner path
        if 'beginner_path' in self.game_engine.progression_paths:
            path = self.game_engine.progression_paths['beginner_path']
            if path.challenges:
                first_challenge_id = path.challenges[0]
                if first_challenge_id in self.game_engine.challenges:
                    # Show this challenge
                    self._show_challenge_details(first_challenge_id)
                    return
        
        # Fallback: find the first beginner challenge
        for challenge in self.game_engine.challenges.values():
            if challenge.difficulty == "Beginner" and not challenge.prerequisites:
                self._show_challenge_details(challenge.id)
                return
        
        # If we got here, no suitable starting challenge was found
        console.print(f"\n{BOLD_RED}Cannot Start Game{BOLD_RED}")
        console.print("No suitable starting challenge found. Please check the game configuration.")
        input("\nPress Enter to continue...")
        self._show_main_menu()
    
    def _continue_game(self):
        """Continue the game from where the player left off."""
        # Check if there's a current challenge
        current_id = self.game_engine.player_progress.current_challenge_id
        
        if current_id and current_id in self.game_engine.challenges:
            # Continue with current challenge
            self._show_challenge_details(current_id)
            return
            
        # Find the next incomplete challenge
        available_challenges = self.game_engine.get_available_challenges()
        incomplete_challenges = [c for c in available_challenges if not c.completed]
        
        if incomplete_challenges:
            # Go to first incomplete challenge
            self._show_challenge_details(incomplete_challenges[0].id)
            return
            
        # If all challenges are complete or none are available
        console.print(f"\n{BOLD_YELLOW}No Challenges to Continue{BOLD_YELLOW}")
        console.print(
            "There are no incomplete challenges available to continue.\n"
            "Either all challenges have been completed or none are available yet."
        )
        input("\nPress Enter to continue...")
        self._show_main_menu()
    
    def _show_progress(self):
        """Show the player's progress."""
        # Display progress summary using Rich
        console.clear()
        self.game_engine.display_progress_summary()
        
        # Wait for user to continue
        console.print("\n[dim]Press any key to continue...[/dim]")
        input()
        
        # Return to main menu
        self._show_main_menu()
    
    def _show_help(self):
        """Show help information."""
        # Display help using Rich
        console.clear()
        
        console.print(Panel(
            "The AWS DevSecOps Game is an interactive learning tool that teaches AWS security best practices "
            "through hands-on challenges. Complete challenges to earn points and badges.\n\n"
            "[bold]How to Play:[/bold]\n"
            "• Enter a number to select a menu option\n"
            "• Press [q] to quit the current screen or [b] to go back\n"
            "• Press [h] to show this help screen\n\n"
            "[bold]Challenge Categories:[/bold]\n"
            "• IAM: Learn identity and access management security\n"
            "• Security Groups: Master network security configuration\n"
            "• Cloud Security: Protect AWS infrastructure resources\n"
            "• Compliance: Implement regulatory compliance controls\n"
            "• Container Security: Secure Docker containers and ECR repositories\n"
            "• CI/CD Security: Implement secure development pipelines\n\n"
            "[bold]Progression:[/bold]\n"
            "Challenges are organized by difficulty (Beginner → Intermediate → Advanced).\n"
            "Some challenges have prerequisites that must be completed first.\n"
            "Complete all challenges in a path to earn special badges and bonus points.\n\n"
            "[bold]AWS Credentials:[/bold]\n"
            "Challenges use your configured AWS credentials to perform read-only operations.\n"
            "No resources will be created or modified without explicit confirmation.",
            title="[bold]AWS DevSecOps Game Help[/bold]",
            border_style="blue"
        ))
        
        # Wait for user to continue
        console.print("\n[dim]Press any key to continue...[/dim]")
        input()


# Main execution block
if __name__ == "__main__":
    # Import here to avoid circular imports
    from game.engine import GameEngine
    
    # Create and initialize game engine
    game_engine = GameEngine()
    
    # Create and run the terminal UI
    terminal_ui = TerminalUI(game_engine)
    terminal_ui.run()

