# Copyright (c) 2011, SD Elements. See LICENSE.txt for details.

import os
from distutils.core import setup

f = open(os.path.join(os.path.dirname(__file__), 'README'))
readme = f.read()
f.close()

setup(name="django-security",
      description='A collection of tools to help secure a Django project.',
      long_description=readme,
      maintainer="SD Elements",
      maintainer_email="django-security@sdelements.com",
      version="0.1.2",
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
      ],
      install_requires=['django>=1.3,<1.4',],
      )

