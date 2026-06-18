import importlib, glob, os, sys

def _import_all():
    """
    Import all CIP object modules for all available revisions following the
    filename convention:
        object0xXXXX_RevX.py

    Imported modules are automatically registered in sys.modules.
    """
    pkg_dir = os.path.dirname(__file__)
    files = glob.glob(os.path.join(pkg_dir, f"*_Rev*.py"))

    modules = {}
    for file in files:
            file_name = os.path.basename(file).replace(".py", "")
            object_name, rev = file_name.split("_Rev")
            object_revisions = modules.get(object_name, {})

            module = importlib.import_module(f".{file_name}", package=__name__)
            object_revisions[int(rev)] = module
            sys.modules[f"{__name__}.{file_name}"] = module
            modules[object_name] = object_revisions

    return modules


_object_modules = _import_all()

"""
Create a virtual module for each CIP object without a revision suffix.

The module resolves automatically to the highest available revision of the
object. This allows users to import the latest supported revision without
specifying it explicitly.

For example, if object0x0001_Rev1 and object0x0001_Rev2 are available,
importing object0x0001 exposes the API of object0x0001_Rev2.
"""
for object_name, object_revisions in _object_modules.items():
    latest = object_revisions[max(object_revisions)]
    globals()[object_name] = latest
    sys.modules[f"{__name__}.{object_name}"] = latest

