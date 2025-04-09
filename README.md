# sld-GitDiffSecrets
Scans git diff output for potential secrets using regular expressions and entropy analysis. Takes git diff output as standard input. - Focused on Tools for scanning code repositories, configuration files, and text data for unintentionally exposed secrets, such as API keys, passwords, and private keys.  Employs regular expressions and entropy analysis to identify potential sensitive information.

## Install
`git clone https://github.com/ShadowStrikeHQ/sld-gitdiffsecrets`

## Usage
`./sld-gitdiffsecrets [params]`

## Parameters
- `-h`: Show help message and exit
- `-i`: Path to a file containing the git diff output. If not provided, reads from standard input.
- `-o`: Path to the output file for logging detected secrets. Defaults to secrets.log
- `-v`: Enable verbose output for debugging.

## License
Copyright (c) ShadowStrikeHQ
