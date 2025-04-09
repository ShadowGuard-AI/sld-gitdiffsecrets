import argparse
import re
import sys
import logging
import os
from tqdm import tqdm
import dotenv
import math

# Load environment variables from .env file (if present)
dotenv.load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Regular expressions for detecting secrets (extend this list as needed)
# IMPORTANT: These are just examples, refine these based on your needs and context.
REGEXES = {
    "API Key": r"[a-zA-Z0-9]{32,45}",  # Simplified API key regex
    "AWS Key": r"AKIA[0-9A-Z]{16}",
    "Secret Key": r"[sS][eE][Cc][Rr][eE][tT][_]?[kK][eE][yY].*=.*['\"]?([a-zA-Z0-9+/=]{32,})['\"]?",
    "Password": r"[pP]assword.*=.*['\"]?([a-zA-Z0-9!@#$%^&*()_+=-]{8,})['\"]?",
    "Authorization": r"[Aa]uthorization: Bearer [a-zA-Z0-9._-]+", #Example for Bearer token
    "Github Token": r"ghp_[a-zA-Z0-9]{36}"
}


def calculate_entropy(data):
    """
    Calculates the Shannon entropy of a given string.
    Args:
        data (str): The string to calculate entropy for.

    Returns:
        float: The Shannon entropy.
    """
    if not data:
        return 0

    entropy = 0
    for x in range(256):
        p_x = float(data.count(chr(x))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)

    return entropy



def scan_diff(diff_content):
    """
    Scans the git diff content for potential secrets using regular expressions and entropy analysis.

    Args:
        diff_content (str): The git diff output as a string.

    Returns:
        list: A list of dictionaries, each containing information about a detected secret.
               Returns an empty list if no secrets are found.
    """
    secrets_found = []

    for line in tqdm(diff_content.splitlines(), desc="Scanning Diff Content"):
        # Only process lines that were added (+) or modified (-)
        if line.startswith("+") or line.startswith("-"):
            line = line[1:].strip() #Remove the + or - and leading/trailing whitespace
            for name, regex in REGEXES.items():
                matches = re.findall(regex, line)
                for match in matches:
                    # Basic entropy check (can be adjusted based on needs)
                    entropy = calculate_entropy(match)
                    if entropy > 4.0:  # Adjust entropy threshold as needed
                        secrets_found.append({
                            "type": name,
                            "match": match,
                            "line": line,
                            "entropy": entropy
                        })

    return secrets_found



def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(description="Scans git diff output for potential secrets.")
    parser.add_argument(
        "-i",
        "--input",
        type=str,
        default=None,
        help="Path to a file containing the git diff output. If not provided, reads from standard input.",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default="secrets.log",
        help="Path to the output file for logging detected secrets. Defaults to secrets.log",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output for debugging.",
    )
    return parser



def main():
    """
    Main function of the sld-GitDiffSecrets tool.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Configure logging based on verbosity
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose mode enabled.")


    try:
        # Read diff content from standard input or file
        if args.input:
            try:
                with open(args.input, "r") as f:
                    diff_content = f.read()
                logging.info(f"Reading diff content from file: {args.input}")
            except FileNotFoundError:
                logging.error(f"Error: File not found: {args.input}")
                sys.exit(1)
            except Exception as e:
                logging.error(f"Error reading file: {args.input} - {e}")
                sys.exit(1)
        else:
            diff_content = sys.stdin.read()  # Read from standard input
            logging.info("Reading diff content from standard input.")

        # Input validation: Check if diff_content is empty
        if not diff_content.strip():
            logging.warning("No diff content provided. Exiting.")
            sys.exit(0)


        # Scan for secrets
        secrets = scan_diff(diff_content)

        # Log the results
        if secrets:
            logging.info(f"Found {len(secrets)} potential secrets.")
            try:
                with open(args.output, "w") as f:
                    for secret in secrets:
                        log_message = f"Type: {secret['type']}, Match: {secret['match']}, Line: {secret['line']}, Entropy: {secret['entropy']}"
                        f.write(log_message + "\n")
                        logging.info(log_message)
                logging.info(f"Secrets logged to: {args.output}")
            except Exception as e:
                logging.error(f"Error writing to log file: {args.output} - {e}")
        else:
            logging.info("No secrets found.")


    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)




if __name__ == "__main__":
    main()