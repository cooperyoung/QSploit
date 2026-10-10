"""Copy the exact portable quantum core into the Qollab companion project."""
from pathlib import Path

root = Path(__file__).resolve().parents[1]
target = root / "qollab"
target.mkdir(exist_ok=True)
for name in ("arithmetic.py", "postprocess.py"):
    (target / name).write_bytes((root / "qsploit" / "quantum" / name).read_bytes())
print("Synced Qollab arithmetic.py and postprocess.py from the tested quantum core.")
