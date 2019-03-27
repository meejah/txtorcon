import os
import sys
import subprocess
from os.path import join


def main():
    """
    This does checks on the release metadata for PyPI and pip-licenses:
    """

    subprocess.run(
        [sys.executable, "setup.py", "bdist_wheel"],
        check=True,
    )
    print(os.listdir("."))
    import txtorcon
    dist_file = join("dist", "txtorcon-{}-py2.py3-none-any.whl".format(txtorcon.__version__))
    print("dist: {}".format(dist_file))
    subprocess.run(
        [sys.executable, "-m", "twine", "check", dist_file],
        check=True,
    )


if __name__ == "__main__":
    main()
