import os
from setuptools import setup, find_packages
import versioneer
import sys

# vagrant doesn't appreciate hard-linking
if os.environ.get('USER') == 'vagrant' or os.path.isdir('/vagrant'):
    del os.link

# https://www.pydanny.com/python-dot-py-tricks.html
if sys.argv[-1] == 'test':
    test_requirements = [
        'pytest',
    ]
    try:
        modules = map(__import__, test_requirements)
    except ImportError as e:
        err_msg = e.message.replace("No module named ", "")
        msg = "%s is not installed. Install your test requirments." % err_msg
        raise ImportError(msg)
    r = os.system('py.test test -v')
    if r == 0:
        sys.exit()
    else:
        raise RuntimeError('tests failed')

setup(
    name="apwgsdk",
    version=versioneer.get_version(),
    cmdclass=versioneer.get_cmdclass(),
    description="APWG Software Development Kid",
    long_description="",
    url="https://github.com/csirtgadgets/apwgsdk-py",
    license='MPL2',
    classifiers=[
       "Topic :: System :: Networking",
       "Intended Audience :: Developers",
        "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)"
    ],
    keywords=['network', 'security'],
    author="Wes Young",
    author_email="wes@csirtgadgets.org",
    packages=find_packages(),
    install_requires=[
        'requests',
        'csirtg_indicator'
    ],
    entry_points={
       'console_scripts': [
           'apwg=apwgsdk.client:main',
       ]
    },
)
