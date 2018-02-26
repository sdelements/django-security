# Copyright (c) 2011, SD Elements. See LICENSE.txt for details.

import os
import sys
import subprocess
from distutils.core import setup, Command

with open(os.path.join(os.path.dirname(__file__), 'README.md')) as f:
    readme = f.read()


class Test(Command):
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        errno = subprocess.call([sys.executable, 'testing/manage.py', 'test'])
        raise SystemExit(errno)

setup(name="django-security",
      description='A collection of tools to help secure a Django project.',
      long_description=readme,
      maintainer="SD Elements",
      maintainer_email="django-security@sdelements.com",
      version="0.9.7",
      packages=["security", "security.south_migrations",
                "security.migrations", "security.auth_throttling"],
      url='https://github.com/sdelements/django-security',
      classifiers=[
          'Framework :: Django',
          'Environment :: Web Environment',
          'Programming Language :: Python',
          'Intended Audience :: Developers',
          'Operating System :: OS Independent',
          'License :: OSI Approved :: BSD License',
          'Topic :: Software Development :: Libraries :: Python Modules',
          'Topic :: Security',
      ],
      requires=['django (>=1.8)', 'ua_parser (==0.7.1)'],
      cmdclass={'test': Test})
