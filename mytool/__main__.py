from __future__ import annotations

import importlib.metadata


def main() -> None:
    name = "python-sysadmin-toolkit"
    print(f"mytool {importlib.metadata.version(name)}")


if __name__ == "__main__":
    main()
