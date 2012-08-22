from json import JSONEncoder
import os
import shlex
import subprocess
import tempfile

import flask


def execute(args, root_helper=None):
    if root_helper:
        cmd = shlex.split(root_helper) + args
    else:
        cmd = args
    return subprocess.check_output(map(str, cmd))


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


class ModelSerializer(JSONEncoder):
    """
    """
    def default(self, obj):
        # import here to avoid circualar imports... ugh; we may need to move
        # this serializer as part of a long-term fix
        import netaddr

        if isinstance(obj, set):
            return list(obj)
        if isinstance(obj, netaddr.IPNetwork):
            return str(obj)
        return super(ModelSerializer, self).default(obj)


def blueprint_factory(name):
    name_parts = name.split(".")[-2:]
    blueprint_name = "_".join(name_parts)
    url_prefix = "/" + "/".join(name_parts)
    return flask.Blueprint(blueprint_name, name, url_prefix=url_prefix)
