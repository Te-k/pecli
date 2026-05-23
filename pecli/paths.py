import os


PACKAGE_ROOT = os.path.dirname(os.path.abspath(__file__))


def data_path(filename):
    return os.path.join(PACKAGE_ROOT, "data", filename)
