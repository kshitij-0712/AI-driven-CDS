import os


def ensure_dir(path):
    if not os.path.exists(path):
        os.makedirs(path)


def project_root():
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def abs_path(*parts):
    return os.path.join(project_root(), *parts)
