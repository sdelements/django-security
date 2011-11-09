# Copyright (c) 2011, SD Elements. See LICENSE.txt for details.

from distutils.core import setup


setup(name="django-security",
      maintainer="SD Elements",
      maintainer_email="django-security@sdelements.com",
      version="0.1.0.1",
      packages=["security", "security.migrations", "security.auth_throttling"],
      install_requires=["django >=1.3, <1.4", "simplejson >=2.1.3, <2.2"]
      )

