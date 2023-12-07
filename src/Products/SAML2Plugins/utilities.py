##############################################################################
#
# Copyright (c) 2023 Jens Vagelpohl and Contributors. All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#
##############################################################################
""" Miscellaneous utility functions
"""

import getopt
import json
import os
import sys

pysaml2_py_to_json_usage_text = f"""
USAGE: {sys.argv[0]} /path/to/configuration.py

This script converts a Python-based PySAML2 configuration to a JSON
representation and prints it to the screen. See
https://pysaml2.readthedocs.io/en/latest/howto/config.html for details
on the Python configuration keys.
"""

def pysaml2_py_to_json():
    """ Convert a PySAML2 Python configuration to JSON """
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'h', 'help')
    except getopt.GetoptError as exc:
        pysaml2_py_to_json_usage(sys.stderr, exc)
        sys.exit(2)

    if not args:
        pysaml2_py_to_json_usage(sys.stdout)
        sys.exit(1)

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            pysaml2_py_to_json_usage(sys.stdout)
            sys.exit()

    config_path = args[0]
    config_dir, config_filename = os.path.split(config_path)
    config_module = config_filename.replace('.py', '')
    sys.path.append(os.path.dirname(config_path))
    mod = __import__(config_module)

    print(json.dumps(mod.CONFIG, indent='    '))


def pysaml2_py_to_json_usage(stream, msg=None):
    if msg:
        stream.write(msg)
        stream.write('\n')

    stream.write(pysaml2_py_to_json_usage_text)
