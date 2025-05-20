#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AWS DevSecOps Game Engine

This module contains the core game engine that powers the AWS DevSecOps learning game.
It handles loading challenges, tracking progress, validating AWS credentials,
and providing a rich terminal user interface.

All AWS operations are read-only by default for security.
"""

import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Any, Tuple, Union

import boto3
import jsonschema
import yaml
from botocore.exceptions import BotoCoreError, ClientError
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text
from game.scenarios.iam_challenges import IAMChallengeLoader

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("game.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("aws_devsecops_game")

# Initialize Rich console for UI
console = Console()


class DifficultyLevel(Enum):
    """Challenge difficulty levels"""
    BEGINNER = "Beginner"
    INTERMEDIATE = "Intermediate" 
    ADVANCED = "Advanced"


@dataclass
class Challenge:
    """Data class representing a game challenge"""
    id: str
    name: str
    difficulty: str
    points: int
    aws_permissions: List[str]
    learning_objectives: List[str]
    prerequisites: List[str] = field(default_factory=list)
    estimated_time: Optional[str] = None
    completed: bool = False
    attempts: int = 0
    completion_date: Optional[datetime] = None
    category: Optional[str] = None


@dataclass
class ProgressionPath:
    """Data class representing a challenge progression path"""
    name: str
    description: str
    challenges: List[str]
    completion_reward: Dict[str, Any]
    completed: bool = False


@dataclass
class PlayerProgress:
    """Data class for tracking player progress"""
    completed_challenges: Set[str] = field(default_factory=set)
    points: int = 0
    current_challenge_id: Optional[str] = None
    badges: List[str] = field(default_factory=list)
    hints_used: Dict[str, int] = field(default_factory=dict)
    last_played: Optional[datetime] = None


class GameEngine:
    """
    Core game engine for the AWS DevSecOps Game.
    
    This class handles loading challenges, tracking player progress,
    validating AWS credentials, and managing the overall game flow.
    """
    
    def __init__(self, config_path: str = None, save_path: str = None):
        """
        Initialize the game engine.
        
        Args:
            config_path: Path to the challenges YAML configuration file
            save_path: Path where player progress will be saved
        """
        self.config_path = config_path or os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "data",
            "challenges.yaml"
        )
        self.save_path = save_path or os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "data",
            "player_progress.json"
        )
        
        # Game state
        self.config: Dict[str, Any] = {}
        self.categories: Dict[str, Dict[str, Any]] = {}
        self.challenges: Dict[str, Challenge] = {}
        self.progression_paths: Dict[str, ProgressionPath] = {}
        self.player_progress = PlayerProgress()
        self.game_initialized = False
        
        # AWS session and credential status
        self.aws_session = None
        self.aws_credentials_valid = False
        
        logger.info("Game engine initialized")
    
    def load_config(self) -> bool:
        """
        Load and validate the game configuration from YAML.
        
        Returns:
            bool: True if loading and validation successful, False otherwise
        """
        try:
            with open(self.config_path, 'r') as file:
                self.config = yaml.safe_load(file)
            
            # Basic validation
            required_keys = ["version", "game_config", "categories", "progression_paths", "schema"]
            for key in required_keys:
                if key not in self.config:
                    logger.error(f"Missing required key in config: {key}")
                    return False
            
            # Load categories and challenges
            self.categories = self.config["categories"]
            
            # Load challenges into our data structure
            for category_name, category_data in self.categories.items():
                if not category_data.get("enabled", True):
                    continue
                    
                for challenge_data in category_data.get("challenges", []):
                    challenge = Challenge(
                        id=challenge_data["id"],
                        name=challenge_data["name"],
                        difficulty=challenge_data["difficulty"],
                        points=challenge_data["points"],
                        aws_permissions=challenge_data["aws_permissions"],
                        learning_objectives=challenge_data["learning_objectives"],
                        prerequisites=challenge_data.get("prerequisites", []),
                        estimated_time=challenge_data.get("estimated_time"),
                        category=category_name
                    )
                    self.challenges[challenge.id] = challenge
            
            # Load progression paths
            for path_id, path_data in self.config["progression_paths"].items():
                self.progression_paths[path_id] = ProgressionPath(
                    name=path_data["name"],
                    description=path_data["description"],
                    challenges=path_data["challenges"],
                    completion_reward=path_data["completion_reward"]
                )
            
            # Validate schema
            schema = self.config["schema"].get("challenge", {})
            required_fields = schema.get("required", [])
            for challenge in self.challenges.values():
                challenge_dict = {k: v for k, v in challenge.__dict__.items() 
                                if k not in ["completed", "attempts", "completion_date"]}
                for field in required_fields:
                    if field not in challenge_dict or challenge_dict[field] is None:
                        logger.error(f"Challenge {challenge.id} missing required field: {field}")
                        return False
            
            logger.info(f"Successfully loaded {len(self.challenges)} challenges "
                       f"across {len(self.categories)} categories")
            return True
            
        except FileNotFoundError:
            logger.error(f"Config file not found: {self.config_path}")
            return False
        except yaml.YAMLError as e:
            logger.error(f"Error parsing YAML configuration: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error loading configuration: {e}")
            return False
    
    def load_progress(self) -> bool:
        """
        Load player progress from save file.
        
        Returns:
            bool: True if loading successful, False otherwise
        """
        try:
            if not os.path.exists(self.save_path):
                logger.info("No existing save file found. Starting fresh.")
                return True
                
            with open(self.save_path, 'r') as file:
                data = json.load(file)
                
            # Convert JSON data to PlayerProgress object
            self.player_progress.completed_challenges = set(data.get("completed_challenges", []))
            self.player_progress.points = data.get("points", 0)
            self.player_progress.current_challenge_id = data.get("current_challenge_id")
            self.player_progress.badges = data.get("badges", [])
            self.player_progress.hints_used = data.get("hints_used", {})
            
            # Parse last_played if it exists
            if "last_played" in data and data["last_played"]:
                self.player_progress.last_played = datetime.fromisoformat(data["last_played"])
            
            # Update completed status in challenges
            for challenge_id in self.player_progress.completed_challenges:
                if challenge_id in self.challenges:
                    self.challenges[challenge_id].completed = True
            
            # Check for progression path completion
            for path in self.progression_paths.values():
                path.completed = all(
                    challenge_id in self.player_progress.completed_challenges
                    for challenge_id in path.challenges
                )
            
            logger.info(f"Loaded player progress: {len(self.player_progress.completed_challenges)} "
                       f"challenges completed, {self.player_progress.points} points")
            return True
            
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing progress JSON: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error loading progress: {e}")
            return False
    
    def save_progress(self) -> bool:
        """
        Save player progress to file.
        
        Returns:
            bool: True if save successful, False otherwise
        """
        try:
            # Ensure save directory exists
            os.makedirs(os.path.dirname(self.save_path), exist_ok=True)
            
            # Update last played time
            self.player_progress.last_played = datetime.now()
            
            # Prepare data for serialization
            data = {
                "completed_challenges": list(self.player_progress.completed_challenges),
                "points": self.player_progress.points,
                "current_challenge_id": self.player_progress.current_challenge_id,
                "badges": self.player_progress.badges,
                "hints_used": self.player_progress.hints_used,
                "last_played": self.player_progress.last_played.isoformat() 
                                if self.player_progress.last_played else None
            }
            
            with open(self.save_path, 'w') as file:
                json.dump(data, file, indent=2)
                
            logger.info(f"Progress saved to {self.save_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving progress: {e}")
            return False
    
    def validate_aws_credentials(self) -> bool:
        """
        Validate AWS credentials using a read-only operation.
        
        Returns:
            bool: True if credentials are valid, False otherwise
        """
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]Validating AWS credentials..."),
                console=console
            ) as progress:
                task = progress.add_task("Validating", total=None)
                
                # Initialize a session using environment variables or AWS config
                self.aws_session = boto3.Session()
                
                # Use STS get-caller-identity - a safe read-only operation
                sts_client = self.aws_session.client('sts')
                response = sts_client.get_caller_identity()
                
                # Show validation results
                progress.update(task, completed=True)
            
            account_id = response.get('Account')
            user_arn = response.get('Arn')
            
            # Mask most of the account ID for security
            if account_id:
                masked_account = f"{account_id[:4]}****{account_id[-4:]}"
            else:
                masked_account = "Unknown"
            
            console.print(Panel(
                f"[green]✓[/green] [bold]AWS Credentials Validated[/bold]\n\n"
                f"Account: [cyan]{masked_account}[/cyan]\n"
                f"User: [cyan]{user_arn}[/cyan]\n"
                f"Region: [cyan]{self.aws_session.region_name}[/cyan]",
                title="[bold]AWS Authentication[/bold]",
                border_style="green"
            ))
            
            logger.info(f"AWS credentials validated for user {user_arn}")
            self.aws_credentials_valid = True
            return True
            
        except (BotoCoreError, ClientError) as e:
            console.print(Panel(
                f"[red]✗[/red] [bold]AWS Credential Validation Failed[/bold]\n\n"
                f"Error: {str(e)}\n\n"
                f"Please ensure your AWS credentials are properly configured:\n"
                f"1. Check your environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)\n"
                f"2. Or verify your AWS CLI configuration (~/.aws/credentials)",
                title="[bold]AWS Authentication Error[/bold]",
                border_style="red"
            ))
            
            logger.error(f"AWS credential validation failed: {e}")
            self.aws_credentials_valid = False
            return False
    
    def initialize_game(self) -> bool:
        """
        Initialize the game by loading config and progress.
        
        Returns:
            bool: True if initialization successful, False otherwise
        """
        console.print("[bold blue]Initializing AWS DevSecOps Game...[/bold blue]")
        
        # Step 1: Load configuration
        config_loaded = self.load_config()
        if not config_loaded:
            console.print("[bold red]Failed to load game configuration.[/bold red]")
            return False
        
        # Step 2: Try AWS credentials but don't fail if invalid
        self.aws_credentials_valid = False
        if self.config["game_config"].get("auto_validate_aws_credentials", True):
            self.aws_credentials_valid = self.validate_aws_credentials()
            if not self.aws_credentials_valid:
                console.print(
                    "\n[bold yellow]Warning: AWS credentials are not valid.[/bold yellow]\n"
                    "[yellow]You can still browse and learn about the challenges, but you won't be able to\n"
                    "execute AWS operations until valid credentials are configured.[/yellow]\n"
                )
        
        # Step 3: Initialize challenge loaders with AWS session
        self._initialize_challenge_loaders()
        
        # Step 4: Load player progress
        progress_loaded = self.load_progress()
        if not progress_loaded:
            console.print("[bold yellow]Warning: Could not load previous progress. Starting fresh.[/bold yellow]")
            # Don't fail initialization, just start fresh
        
        self.game_initialized = True
        logger.info("Game initialization completed successfully")
        return True
        
    def _initialize_challenge_loaders(self):
        """Initialize all challenge category loaders."""
        # Create challenge loaders
        self.challenge_loaders = {
            'IAM': IAMChallengeLoader(self.aws_session if self.aws_credentials_valid else None)
        }
        
        # Load challenges from loaders
        for category, loader in self.challenge_loaders.items():
            for challenge_id in loader.list_challenges():
                challenge = loader.get_challenge(challenge_id)
                if challenge:
                    self.challenges[challenge_id] = challenge
    
    def mark_challenge_completed(self, challenge_id: str) -> None:
        """
        Mark a challenge as completed and update player progress.
        
        Args:
            challenge_id: ID of the challenge to mark as completed
        """
        if challenge_id not in self.challenges:
            logger.warning(f"Attempted to complete unknown challenge: {challenge_id}")
            return
            
        challenge = self.challenges[challenge_id]
        
        # Skip if already completed
        if challenge.id in self.player_progress.completed_challenges:
            return
            
        # Mark as completed
        challenge.completed = True
        challenge.completion_date = datetime.now()
        self.player_progress.completed_challenges.add(challenge.id)
        
        # Award points
        self.player_progress.points += challenge.points
        
        # Check if any progression paths are completed
        for path_id, path in self.progression_paths.items():
            if not path.completed and all(
                c_id in self.player_progress.completed_challenges 
                for c_id in path.challenges
            ):
                # Path completed - mark as complete and award bonus points
                path.completed = True
                self.player_progress.points += path.completion_reward.get("points", 0)
                
                # Award badge if any
                if "badge" in path.completion_reward:
                    self.player_progress.badges.append(path.completion_reward["badge"])
                    
                console.print(
                    f"\n[bold green]🏆 Congratulations! You've completed the "
                    f"[cyan]{path.name}[/cyan] path![/bold green]"
                )
                console.print(
                    f"[green]You've been awarded [bold]{path.completion_reward.get('points', 0)}[/bold] "
                    f"bonus points and the [bold]{path.completion_reward.get('badge', '')}[/bold] badge![/green]"
                )
        
        # Save progress after completion
        self.save_progress()
        
        # Show completion message
        console.print(f"\n[bold green]✓ Challenge completed: [cyan]{challenge.name}[/cyan][/bold green]")
        console.print(f"[green]You earned [bold]{challenge.points}[/bold] points![/green]")
        
        logger.info(f"Challenge {challenge_id} marked as completed")
    
    def get_available_challenges(self, category: str = None) -> List[Challenge]:
        """
        Get a list of available challenges, optionally filtered by category.
        
        Args:
            category: Category name to filter by (optional)
            
        Returns:
            List of Challenge objects that are available to the player
        """
        available = []
        
        for challenge in self.challenges.values():
            # Filter by category if specified
            if category and challenge.category != category:
                continue
                
            # Check if prerequisites are met
            if self.check_prerequisites(challenge.id):
                available.append(challenge)
                
        # Sort by difficulty level
        difficulty_order = {
            DifficultyLevel.BEGINNER.value: 1,
            DifficultyLevel.INTERMEDIATE.value: 2,
            DifficultyLevel.ADVANCED.value: 3
        }
        
        available.sort(key=lambda c: difficulty_order.get(c.difficulty, 999))
        
        return available
    
    def check_prerequisites(self, challenge_id: str) -> bool:
        """
        Check if prerequisites for a challenge are met.
        
        Args:
            challenge_id: ID of the challenge to check
            
        Returns:
            True if all prerequisites are met, False otherwise
        """
        if challenge_id not in self.challenges:
            logger.warning(f"Attempted to check prerequisites for unknown challenge: {challenge_id}")
            return False
            
        challenge = self.challenges[challenge_id]
        
        # Check if AWS credentials are required and valid
        if challenge.aws_permissions and not self.aws_credentials_valid:
            # Challenge requires AWS but credentials are not valid
            logger.info(f"Challenge {challenge_id} requires AWS credentials, which are not valid")
            return False
        
        # If no prerequisites, challenge is available
        if not challenge.prerequisites:
            return True
            
        # Check if all prerequisites are completed
        for prereq_id in challenge.prerequisites:
            if prereq_id not in self.player_progress.completed_challenges:
                return False
                
        return True
    
    def start_challenge(self, challenge_id: str) -> bool:
        """
        Start a challenge and set it as the current challenge.
        
        Args:
            challenge_id: ID of the challenge to start
            
        Returns:
            True if challenge was started successfully, False otherwise
        """
        if not self.game_initialized:
            logger.error("Attempted to start challenge before game initialization")
            return False
            
        if challenge_id not in self.challenges:
            logger.warning(f"Attempted to start unknown challenge: {challenge_id}")
            return False
            
        challenge = self.challenges[challenge_id]
        
        # Check if challenge prerequisites are met
        if not self.check_prerequisites(challenge_id):
            # Prerequisites info is shown in the check_prerequisites method
            return False
            
        # Check if challenge requires specific AWS permissions
        required_permissions = challenge.aws_permissions if hasattr(challenge, 'aws_permissions') else []
        if required_permissions and self.aws_session:
            try:
                # Don't actually check permissions - this would require IAM:SimulatePrincipalPolicy
                # Just warn the user about the required permissions
                console.print(f"[bold blue]ℹ This challenge requires the following AWS permissions:[/bold blue]")
                for perm in required_permissions:
                    console.print(f"[blue]• {perm}[/blue]")
            except Exception as e:
                logger.warning(f"Error checking AWS permissions: {e}")
                # Continue anyway, the challenge will fail if permissions are insufficient
        
        # Set as current challenge
        self.player_progress.current_challenge_id = challenge_id
        
        # Increment attempts if not already completed
        if challenge_id not in self.player_progress.completed_challenges:
            if hasattr(challenge, 'attempts'):
                challenge.attempts += 1
            
        # Save progress
        self.save_progress()
        
        # Start the challenge
        console.print(f"\n[bold blue]Starting challenge: {challenge_id}[/bold blue]")
        success = challenge.start()
        
        if success:
            # Mark as completed and save progress
            self.mark_challenge_completed(challenge_id)
            
            # Get and display score if available
            if hasattr(challenge, 'get_score'):
                score, max_score = challenge.get_score()
                console.print(f"\n[green]Challenge completed! Score: {score}/{max_score}[/green]")
        
        # Save progress again after completion
        self.save_progress()
        
        logger.info(f"Challenge {challenge_id} {'completed' if success else 'attempted'}")
        return success
    
    def get_current_progress(self) -> Dict[str, Any]:
        """
        Get a summary of the player's current progress.
        
        Returns:
            Dictionary containing progress summary
        """
        total_challenges = len(self.challenges)
        completed_challenges = len(self.player_progress.completed_challenges)
        completion_percentage = (completed_challenges / total_challenges * 100) if total_challenges > 0 else 0
        
        # Count challenges by category
        category_progress = {}
        for category_name in self.categories.keys():
            category_challenges = [c for c in self.challenges.values() if c.category == category_name]
            completed_in_category = [c for c in category_challenges if c.id in self.player_progress.completed_challenges]
            
            if category_challenges:
                percentage = len(completed_in_category) / len(category_challenges) * 100
            else:
                percentage = 0
                
            category_progress[category_name] = {
                "total": len(category_challenges),
                "completed": len(completed_in_category),
                "percentage": percentage
            }
        
        # Get completed paths
        completed_paths = [p.name for p in self.progression_paths.values() if p.completed]
        
        return {
            "points": self.player_progress.points,
            "total_challenges": total_challenges,
            "completed_challenges": completed_challenges,
            "completion_percentage": completion_percentage,
            "category_progress": category_progress,
            "badges": self.player_progress.badges,
            "completed_paths": completed_paths,
            "last_played": self.player_progress.last_played
        }
    
    def display_challenge_info(self, challenge_id: str) -> None:
        """
        Display detailed information about a challenge.
        
        Args:
            challenge_id: ID of the challenge to display
        """
        if challenge_id not in self.challenges:
            console.print(f"[bold red]Challenge not found: {challenge_id}[/bold red]")
            return
            
        challenge = self.challenges[challenge_id]
        
        # Determine color based on difficulty
        difficulty_color = {
            DifficultyLevel.BEGINNER.value: "green",
            DifficultyLevel.INTERMEDIATE.value: "yellow",
            DifficultyLevel.ADVANCED.value: "red"
        }.get(challenge.difficulty, "white")
        
        # Check if prerequisites are met and AWS status
        prerequisites_met = self.check_prerequisites(challenge_id)
        
        # Determine why prerequisites aren't met
        if not prerequisites_met and challenge.aws_permissions and not self.aws_credentials_valid:
            prereq_status = "[red]✗ AWS credentials required[/red]"
        else:
            prereq_status = "[green]✓ Met[/green]" if prerequisites_met else "[red]✗ Not met[/red]"
        
        # Get prerequisite challenge names
        prereq_names = []
        for prereq_id in challenge.prerequisites:
            if prereq_id in self.challenges:
                name = self.challenges[prereq_id].name
                if prereq_id in self.player_progress.completed_challenges:
                    prereq_names.append(f"[green]✓ {name}[/green]")
                else:
                    prereq_names.append(f"[red]✗ {name}[/red]")
        
        # Format completion status
        completed = challenge_id in self.player_progress.completed_challenges
        completion_status = "[green]✓ Completed[/green]" if completed else "[yellow]⟲ Not completed[/yellow]"
        
        completion_date = ""
        if completed and challenge.completion_date:
            completion_date = f" on {challenge.completion_date.strftime('%Y-%m-%d %H:%M')}"

        # Create rich panel with challenge details
        console.print(Panel(
            f"[bold]{challenge.name}[/bold]\n\n"
            f"{challenge.description if hasattr(challenge, 'description') else 'No description available.'}\n\n"
            f"[bold]Difficulty:[/bold] [{difficulty_color}]{challenge.difficulty}[/{difficulty_color}]\n"
            f"[bold]Points:[/bold] {challenge.points}\n"
            f"[bold]Category:[/bold] {challenge.category}\n"
            f"[bold]Estimated Time:[/bold] {challenge.estimated_time or 'Not specified'}\n"
            f"[bold]Status:[/bold] {completion_status}{completion_date}\n"
            f"[bold]Prerequisites:[/bold] {prereq_status}\n" +
            (f"  " + "\n  ".join(prereq_names) + "\n" if prereq_names else "  None\n") +
            f"[bold]Learning Objectives:[/bold]\n" +
            "\n".join(f"  • {obj}" for obj in challenge.learning_objectives),
            title=f"[bold blue]Challenge: {challenge.id}[/bold blue]",
            border_style="blue"
        ))
        
        # Show AWS permissions required
        if challenge.aws_permissions:
            console.print(Panel(
                "\n".join(f"• {perm}" for perm in challenge.aws_permissions),
                title="[bold blue]Required AWS Permissions (Read-Only)[/bold blue]",
                border_style="cyan"
            ))
    
    def display_progress_summary(self) -> None:
        """
        Display a summary of the player's progress.
        """
        progress = self.get_current_progress()
        
        # Create a table for category progress
        category_table = Table(title="Category Progress")
        category_table.add_column("Category", style="cyan")
        category_table.add_column("Completed", style="green")
        category_table.add_column("Total", style="blue")
        category_table.add_column("Progress", style="yellow")
        
        for category, stats in progress["category_progress"].items():
            progress_bar = self._create_progress_bar(stats["percentage"])
            category_table.add_row(
                category,
                str(stats["completed"]),
                str(stats["total"]),
                progress_bar
            )
        
        # Determine overall progress color
        progress_color = "red"
        if progress["completion_percentage"] > 30:
            progress_color = "yellow"
        if progress["completion_percentage"] > 70:
            progress_color = "green"
            
        overall_progress = self._create_progress_bar(progress["completion_percentage"])
        
        # Create panel with overall progress
        console.print(Panel(
            f"[bold]Total Points:[/bold] {progress['points']}\n"
            f"[bold]Challenges Completed:[/bold] {progress['completed_challenges']}/{progress['total_challenges']}\n"
            f"[bold]Overall Progress:[/bold] {overall_progress}\n\n"
            f"[bold]Badges Earned:[/bold] " + 
            (", ".join(progress["badges"]) if progress["badges"] else "None yet") + "\n"
            f"[bold]Paths Completed:[/bold] " + 
            (", ".join(progress["completed_paths"]) if progress["completed_paths"] else "None yet") + "\n"
            f"[bold]Last Played:[/bold] " + 
            (progress["last_played"].strftime("%Y-%m-%d %H:%M") if progress["last_played"] else "Never"),
            title="[bold blue]Player Progress Summary[/bold blue]",
            border_style="blue"
        ))
        
        console.print(category_table)
    
    def _create_progress_bar(self, percentage: float, width: int = 20) -> str:
        """
        Create a text-based progress bar.
        
        Args:
            percentage: Progress percentage (0-100)
            width: Width of the progress bar in characters
            
        Returns:
            Formatted progress bar string
        """
        filled = int(width * percentage / 100)
        empty = width - filled
        
        # Choose color based on percentage
        color = "red"
        if percentage > 30:
            color = "yellow"
        if percentage > 70:
            color = "green"
        
        # Create the progress bar with blocks and dashes
        filled_part = "█" * filled
        empty_part = "-" * empty
        
        # Format with color and percentage
        return f"[{color}]{filled_part}[/{color}][dim]{empty_part}[/dim] [{color}]{percentage:.1f}%[/{color}]"


# Main execution block for testing
if __name__ == "__main__":
    try:
        # Initialize the game engine
        console.print("[bold]AWS DevSecOps Game - Initialization Test[/bold]")
        console.print("[dim]This will test loading the game configuration and validating AWS credentials.[/dim]\n")
        
        game_engine = GameEngine()
        
        # Initialize the game
        if game_engine.initialize_game():
            console.print("\n[bold green]✓ Game engine initialized successfully![/bold green]")
            
            # Display some stats
            console.print(f"\n[bold]Loaded [cyan]{len(game_engine.challenges)}[/cyan] challenges across [cyan]{len(game_engine.categories)}[/cyan] categories.[/bold]")
            
            # Show challenge count by category
            category_table = Table(title="Challenge Categories")
            category_table.add_column("Category", style="cyan")
            category_table.add_column("Icon", style="cyan")
            category_table.add_column("Challenge Count", justify="right", style="green")
            
            for category_name, category_data in game_engine.categories.items():
                challenges = [c for c in game_engine.challenges.values() if c.category == category_name]
                icon = category_data.get("icon", "🔷")
                category_table.add_row(category_name, icon, str(len(challenges)))
            
            console.print(category_table)
            
            # Show progression paths
            path_table = Table(title="Progression Paths")
            path_table.add_column("Path", style="cyan")
            path_table.add_column("Description", style="white")
            path_table.add_column("Challenges", justify="right", style="green")
            path_table.add_column("Reward", style="magenta")
            
            for path_id, path in game_engine.progression_paths.items():
                reward = f"{path.completion_reward.get('points', 0)} points, {path.completion_reward.get('badge', 'No')} badge"
                path_table.add_row(path.name, path.description, str(len(path.challenges)), reward)
            
            console.print(path_table)
            
            # Show a sample progress bar
            console.print("\n[bold]Sample Progress Bars:[/bold]")
            console.print(f"10% Progress: {game_engine._create_progress_bar(10)}")
            console.print(f"50% Progress: {game_engine._create_progress_bar(50)}")
            console.print(f"90% Progress: {game_engine._create_progress_bar(90)}")
            
            # Display a sample challenge
            if game_engine.challenges:
                console.print("\n[bold]Sample Challenge Info:[/bold]")
                # Pick a sample challenge (first one)
                sample_challenge_id = next(iter(game_engine.challenges.keys()))
                game_engine.display_challenge_info(sample_challenge_id)
        else:
            console.print("\n[bold red]✗ Game engine initialization failed.[/bold red]")
            console.print("[red]Check the logs for more information.[/red]")
    
    except Exception as e:
        console.print(f"[bold red]Error during testing: {e}[/bold red]")
        logger.exception("Exception during engine testing")

