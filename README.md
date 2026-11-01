# sld-GitDiffSecrets
Scans git diff output for potential secrets using regular expressions and entropy analysis. Takes git diff output from a file or from standard input. Only added and removed lines are scanned; context lines are out of scope and are never scanned. Each finding records the pattern type, the input name or the standard input label, the line number, and the direction marker (added or removed), printed in the log line. Findings never carry the secret itself: a fixed masked marker stands in place of the value, and the full matched value and the full source line appear in no route, not the console, not the output file, and not any log. The entropy gate applies only to the generic API Key pattern; direct pattern matches (Password, Secret Key, the AWS shape, the GitHub shape, and the bearer header) are reported without the gate. Empty input exits 1 with a warning line. A run whose resolved output path equals its input file exits 1 and leaves the input unchanged. A failed output write exits 1 with an output not written line.

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
