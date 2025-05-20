# AWS DevSecOps Game

A terminal-based game for learning AWS security best practices through interactive challenges. This game provides hands-on experience with DevSecOps principles in the AWS cloud environment.

## Prerequisites

Before you begin, ensure you have the following prerequisites installed:

- **Python 3.11+** - The game is built with Python 3.11 or later
- **AWS CLI v2** - AWS Command Line Interface for interacting with AWS services
- **Docker** (optional) - Required for container security challenges
- **A terminal with color support** - For the best experience with the Rich UI

## AWS Credentials Setup

The game requires valid AWS credentials to function. It uses read-only AWS operations by default, but you'll need proper credentials configured:

1. **Create an IAM User** (recommended):
   - Sign in to your AWS Management Console
   - Navigate to IAM and create a new user with programmatic access
   - Attach the `ReadOnlyAccess` managed policy (this provides secure, read-only access)

2. **Configure your credentials** using one of these methods:

   a. Using AWS CLI:
   ```bash
   aws configure
   ```
   
   b. Environment variables:
   ```bash
   export AWS_ACCESS_KEY_ID=your_access_key
   export AWS_SECRET_ACCESS_KEY=your_secret_key
   export AWS_REGION=your_preferred_region  # e.g., us-east-1
   ```
   
   c. Creating credentials file manually:
   ```bash
   mkdir -p ~/.aws
   cat > ~/.aws/credentials << EOF
   [default]
   aws_access_key_id = your_access_key
   aws_secret_access_key = your_secret_key
   EOF
   
   cat > ~/.aws/config << EOF
   [default]
   region = your_preferred_region
   EOF
   ```

3. **Verify your configuration**:
   ```bash
   aws sts get-caller-identity
   ```
   If successful, you'll see your AWS account information.

## Installation

1. **Clone or download** this repository:
   ```bash
   git clone https://github.com/yourusername/aws-devsecops-game.git
   cd aws-devsecops-game
   ```

2. **Create a virtual environment** (optional but recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## Running the Game

Start the game by running:

```bash
python main.py
```

If you get a permissions error, make the script executable:
```bash
chmod +x main.py
python main.py
```

## Game Features

- **Interactive CLI**: Navigate through scenarios using a Rich-powered terminal interface
- **Progressive Difficulty**: Scenarios increase in complexity as you learn
- **Read-Only Operations**: By default, all AWS operations are read-only for safety
- **Save/Resume**: Your progress is automatically saved
- **Real-World Scenarios**: Based on actual DevSecOps challenges and AWS best practices

## Security

This game is designed with security in mind:

- All AWS operations are read-only by default
- Any operations that would modify AWS resources require explicit confirmation
- No sensitive AWS credential information is logged or stored

## Topics Covered

- IAM permissions and least privilege principle
- Security group configurations
- Cloud infrastructure security
- Compliance and audit
- Container security
- CI/CD security integration

## Troubleshooting

- **Invalid AWS Credentials**: Ensure your AWS credentials are valid and have read access permissions
- **Missing Dependencies**: Verify all dependencies are installed with `pip install -r requirements.txt`
- **Permission Issues**: Ensure the main.py file is executable (`chmod +x main.py`)
- **Display Issues**: Ensure your terminal supports colors and Unicode characters for the best experience

## License

This project is licensed under the MIT License - see the LICENSE file for details.

