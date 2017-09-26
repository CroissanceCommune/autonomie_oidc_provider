import os

from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, 'README.txt')) as f:
    README = f.read()
with open(os.path.join(here, 'CHANGES.txt')) as f:
    CHANGES = f.read()

requires = [
    'pyramid',
    'pyramid-chameleon',
    'pyramid_debugtoolbar',
    'pyramid_tm',
    'SQLAlchemy',
    'transaction',
    'zope.sqlalchemy',
    'waitress',
    ]

tests_require = [
    'WebTest >= 1.3.1',  # py3 compat
    'pytest',  # includes virtualenv
    'pytest-cov',
    ]

dev_require = [
    'libsass',
]

entry_points = {
    "paste.app_factory": "main = autonomie_oidc_provider:main",
    "fanstatic.libraries": [
        "autonomie_oidc_provider=autonomie_oidc_provider.fanstatic:lib"
    ],
    "console_scripts": [
        "oidc-manage=autonomie_oidc_provider.scripts.manager:manage"
    ]
}

setup(name='autonomie_oidc_provider',
      version='0.1b5',
      description='autonomie_oidc_provider',
      long_description=README + '\n\n' + CHANGES,
      classifiers=[
          "Programming Language :: Python",
          "Framework :: Pyramid",
          "Topic :: Internet :: WWW/HTTP",
          "Topic :: Internet :: WWW/HTTP :: WSGI :: Application",
      ],
      author='',
      author_email='',
      url='',
      keywords='web wsgi bfg pylons pyramid',
      packages=find_packages(),
      include_package_data=True,
      zip_safe=False,
      extras_require={
          'testing': tests_require,
          'dev': dev_require,
      },
      install_requires=requires,
      entry_points=entry_points,
      )
