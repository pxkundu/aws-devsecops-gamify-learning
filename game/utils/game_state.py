"""
Game state management for the AWS DevSecOps Game.
"""

import os
import json
import logging
from typing import Dict, Any, Optional, List

log = logging.getLogger("aws_devsecops_game")

class GameState:
    """
    Manages the game state, including player progress, scores, and game settings.
    Provides functionality to save and load game state.
    """
    
    DEFAULT_STATE = {
        "player_name": "",
        "current_level": 1,
        "score": 0,
        "completed_levels": [],
        "achievements": [],
        "game_version": "1.0.0"
    }
    
    def __init__(self, save_dir: str = None):
        """
        Initialize the game state.
        
        Args:
            save_dir: Directory to save game state files. Defaults to ~/.aws_devsecops_game
        """
        self.player_name = ""
        self.current_level = 1
        self.score = 0
        self.completed_levels: List[int] = []
        self.achievements: List[str] = []
        self.game_version = "1.0.0"
        
        # Set save directory
        if save_dir is None:
            self.save_dir = os.path.expanduser("~/.aws_devsecops_game")
        else:
            self.save_dir = save_dir
            
        # Create save directory if it doesn't exist
        if not os.path.exists(self.save_dir):
            try:
                os.makedirs(self.save_dir)
                log.info(f"Created save directory at {self.save_dir}")
            except Exception as e:
                log.error(f"Failed to create save directory: {e}")
    
    @property
    def save_file(self) -> str:
        """Get the full path to the save file."""
        return os.path.join(self.save_dir, "game_state.json")
    
    def reset(self) -> None:
        """Reset the game state to default values."""
        self.player_name = ""
        self.current_level = 1
        self.score = 0
        self.completed_levels = []
        self.achievements = []
    
    def set_player_name(self, name: str) -> None:
        """Set the player's name."""
        self.player_name = name
    
    def add_score(self, points: int) -> int:
        """
        Add points to the player's score.
        
        Args:
            points: Number of points to add
            
        Returns:
            The new total score
        """
        self.score += points
        return self.score
    
    def complete_level(self, level_number: int) -> None:
        """
        Mark a level as completed.
        
        Args:
            level_number: The level to mark as completed
        """
        if level_number not in self.completed_levels:
            self.completed_levels.append(level_number)
            self.completed_levels.sort()
        
        # Advance to the next level if the completed level is the current one
        if level_number == self.current_level:
            self.current_level += 1
    
    def add_achievement(self, achievement: str) -> None:
        """
        Add an achievement to the player's record.
        
        Args:
            achievement: The achievement to add
        """
        if achievement not in self.achievements:
            self.achievements.append(achievement)
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the game state to a dictionary for serialization.
        
        Returns:
            A dictionary representation of the game state
        """
        return {
            "player_name": self.player_name,
            "current_level": self.current_level,
            "score": self.score,
            "completed_levels": self.completed_levels,
            "achievements": self.achievements,
            "game_version": self.game_version
        }
    
    def from_dict(self, state_dict: Dict[str, Any]) -> None:
        """
        Load game state from a dictionary.
        
        Args:
            state_dict: Dictionary containing game state data
        """
        self.player_name = state_dict.get("player_name", "")
        self.current_level = state_dict.get("current_level", 1)
        self.score = state_dict.get("score", 0)
        self.completed_levels = state_dict.get("completed_levels", [])
        self.achievements = state_dict.get("achievements", [])
        self.game_version = state_dict.get("game_version", "1.0.0")
    
    def save(self) -> bool:
        """
        Save the current game state to disk.
        
        Returns:
            True if the save was successful, False otherwise
        """
        try:
            with open(self.save_file, 'w') as f:
                json.dump(self.to_dict(), f, indent=2)
            log.info(f"Game state saved to {self.save_file}")
            return True
        except Exception as e:
            log.error(f"Failed to save game state: {e}")
            return False
    
    def load(self) -> bool:
        """
        Load the game state from disk.
        
        Returns:
            True if the load was successful, False otherwise
        """
        if not self.has_saved_game():
            return False
            
        try:
            with open(self.save_file, 'r') as f:
                state_dict = json.load(f)
            self.from_dict(state_dict)
            log.info(f"Game state loaded from {self.save_file}")
            return True
        except Exception as e:
            log.error(f"Failed to load game state: {e}")
            return False
    
    def has_saved_game(self) -> bool:
        """
        Check if a saved game exists.
        
        Returns:
            True if a saved game exists, False otherwise
        """
        return os.path.exists(self.save_file)

