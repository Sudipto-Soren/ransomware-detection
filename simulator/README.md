# simulator/ — Track B

Two generators, both confined to a disposable test folder — never real
personal data:

- benign_generator.py — mimics ordinary user file activity
- ransomware_pattern_generator.py — mimics the *observable* ransomware
  I/O pattern using simple reversible transforms, not real cryptography

Portable Python — develop and iterate on Mac. Before final model
training, also run both scripts on Windows at least once (see root
README) so the dataset includes Windows-native rows, since that's the
only environment the finished system deploys to.
