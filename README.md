# NIST Elliptic Curve Seeds Cracker

Attempting to crack the NIST elliptic curve seed values for the $12,288 bounty offered by Filippo Valsorda.

## Background

Jerry Solinas at the NSA generated these seeds in ~1997 by hashing "humorous" English phrases with SHA-1. The exact phrases were forgotten before he passed away in 2023.

Target bounty: $12,288 (tripled if donated to charity)

## Versions

### v1/ - Original Approach (Archive)
The original attempt at cracking the seeds. See `v1/README.md` for details.

### Current (v2) - Daemon-Based Batch Processing
New approach with:
- Systemd daemon for continuous operation
- Batch processing with checkpointing
- John the Ripper with Jumbo rules for maximum coverage
- Template-based phrase generation with deduplication
- Three-phase attack strategy (base phrases → single char insertion → deep noise)

## Current Version Files

- `nist_seeds_cracker.py` - Main daemon script
- `nist_utils.py` - Shared utilities and configuration
- `nist-cracker.service` - Systemd service file
- `nist-seeds-john.txt` - Hash file (12,317 hashes including variations)
- `nist_watcher.py` - Optional monitoring script

## Running

```bash
sudo systemctl start nist-cracker
sudo systemctl status nist-cracker
journalctl -u nist-cracker -f
```

See code comments for detailed documentation.
