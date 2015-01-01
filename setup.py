# Copyright (c) 2011, SD Elements. See LICENSE.txt for details.

import os
import sys
import subprocess
from distutils.core import setup, Command

f = open(os.path.join(os.path.dirname(__file__), 'README.md'))
readme = f.read()
f.close()

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
      version="0.1.24b",
      packages=["security", "security.migrations", "security.auth_throttling"],
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
      install_requires=['django>=1.4',],
      cmdclass={'test': Test})

