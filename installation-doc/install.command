#!/bin/sh
# SentinelGo macOS installer — double-clickable.
#
# Double-click this file in Finder to install SentinelGo. It runs install.sh
# from THIS same folder, which auto-detects the platform binary and copies the
# per-agent config.json that was generated alongside it.
#
# If macOS warns that it is "from an unidentified developer", right-click this
# file and choose "Open" once to allow it.

# Resolve and enter this script's own directory so ./install.sh and the sibling
# binary + config.json are found regardless of where it was launched from.
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR" || exit 1

# Browser downloads lose the executable bit; restore it so install.sh's own
# `exec sudo "$0"` re-exec works. install.sh honors its #!/bin/bash shebang.
chmod +x ./install.sh 2>/dev/null || true
./install.sh "$@"          # install.sh self-elevates via sudo (prompts in this Terminal)
rc=$?

echo
echo "SentinelGo installation finished (exit code $rc)."
echo "Press Return to close this window."
read _ || true
exit "$rc"
