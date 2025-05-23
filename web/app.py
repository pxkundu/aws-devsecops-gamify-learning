import streamlit as st
import sys
import os

# Add the parent directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from game.engine import GameEngine
from game.utils.aws_handler import AWSHandler
from game.utils.game_state import GameState

# Configure the page
st.set_page_config(
    page_title="AWS DevSecOps Game",
    page_icon="🎮",
    layout="wide"
)

# Custom CSS
st.markdown("""
    <style>
    .main {
        padding: 2rem;
    }
    .stButton>button {
        width: 100%;
    }
    .game-container {
        background-color: #f0f2f6;
        padding: 2rem;
        border-radius: 10px;
    }
    </style>
""", unsafe_allow_html=True)

# Initialize session state
if 'game_state' not in st.session_state:
    st.session_state.game_state = GameState()
    st.session_state.aws_handler = AWSHandler()
    st.session_state.current_scenario = None

# Header
st.title("🎮 AWS DevSecOps Game")
st.markdown("Learn AWS security best practices through interactive challenges!")

# Main game container
with st.container():
    st.markdown('<div class="game-container">', unsafe_allow_html=True)
    
    # Game status
    st.subheader("Game Status")
    status = st.session_state.game_state.get_status()
    st.write(f"Level: {status.get('level', 1)}")
    st.write(f"Score: {status.get('score', 0)}")
    st.write(f"Completed Scenarios: {status.get('completed_scenarios', 0)}")
    
    # Scenario selection
    st.subheader("Available Scenarios")
    scenarios = st.session_state.game_state.get_available_scenarios()
    
    if scenarios:
        selected_scenario = st.selectbox(
            "Choose a scenario to play:",
            options=[s['name'] for s in scenarios],
            format_func=lambda x: f"{x} - {next(s['description'] for s in scenarios if s['name'] == x)}"
        )
        
        if st.button("Start Scenario"):
            st.session_state.current_scenario = selected_scenario
            st.experimental_rerun()
    
    # Current scenario
    if st.session_state.current_scenario:
        st.subheader(f"Current Scenario: {st.session_state.current_scenario}")
        scenario = next(s for s in scenarios if s['name'] == st.session_state.current_scenario)
        
        st.write(scenario['description'])
        
        # Scenario actions
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Submit Answer"):
                st.write("Checking your answer...")
                # Add answer checking logic here
        
        with col2:
            if st.button("Reset Scenario"):
                st.session_state.current_scenario = None
                st.experimental_rerun()
    
    st.markdown('</div>', unsafe_allow_html=True)

# Footer
st.markdown("---")
st.markdown("Built with ❤️ for AWS DevSecOps learning") 