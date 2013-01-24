import functools
import json
import os
import shlex
import subprocess
import tempfile

import flask
import netaddr

from akanda.router import models


def execute(args, root_helper=None):
    if root_helper:
        cmd = shlex.split(root_helper) + args
    else:
        cmd = args
    return subprocess.check_output(map(str, cmd), stderr=subprocess.STDOUT)


def replace_file(file_name, data):
    """Replaces the contents of file_name with data in a safe manner.

    First write to a temp file and then rename. Since POSIX renames are
    atomic, the file is unlikely to be corrupted by competing writes.

    We create the tempfile on the same device to ensure that it can be renamed.
    """
    base_dir = os.path.dirname(os.path.abspath(file_name))
    tmp_file = tempfile.NamedTemporaryFile('w+', dir=base_dir, delete=False)
    tmp_file.write(data)
    tmp_file.close()
    os.chmod(tmp_file.name, 0644)
    os.rename(tmp_file.name, file_name)


def ensure_directory(dir_path):
    if not os.path.isdir(dir_path):
        os.makedirs(dir_path, 0755)


class ModelSerializer(json.JSONEncoder):
    """
    """
    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        elif isinstance(obj, netaddr.IPNetwork):
            return str(obj)
        elif isinstance(obj, netaddr.IPAddress):
            return str(obj)
        elif isinstance(obj, models.ModelBase):
            if hasattr(obj, 'to_dict'):
                return obj.to_dict()
            else:
                return vars(obj)
        return super(ModelSerializer, self).default(obj)


def json_response(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        retval = f(*args, **kwargs)
        if isinstance(retval, flask.Response):
            return retval
        else:
            return flask.Response(json.dumps(retval, cls=ModelSerializer),
                                  status=200)
    return wrapper


def blueprint_factory(name):
    name_parts = name.split(".")[-2:]
    blueprint_name = "_".join(name_parts)
    url_prefix = "/" + "/".join(name_parts)
    return flask.Blueprint(blueprint_name, name, url_prefix=url_prefix)
