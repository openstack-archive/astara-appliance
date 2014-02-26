from traceback import print_exc
from pprint import pformat
import cStringIO

from flask import request
from werkzeug import Response


def handle_traceback(exc):
    out = cStringIO.StringIO()
    print_exc(file=out)
    formatted_environ = pformat(request.environ)
    response = Response(
        '%s\n%s\n' % (out.getvalue(), formatted_environ),
        status=500
    )
    return response
