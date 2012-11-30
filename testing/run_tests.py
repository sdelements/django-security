#!/usr/bin/env python

import os, os.path
import sys

path, scriptname = os.path.split(__file__)

sys.path.append(os.path.abspath(path))
sys.path.append(os.path.abspath(os.path.join(path, '..')))

os.environ['DJANGO_SETTINGS_MODULE'] = 'settings'

from django.core import management

management.call_command('test', 'tests')

