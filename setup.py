from os import system, path
from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='ActiveReign',
    version='1.0.5',
    author = 'm8r0wn',
    author_email = 'm8r0wn@protonmail.com',
    description = 'A network enumeration and attack toolset',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://github.com/m8r0wn/ActiveReign',
    license='GPLv3',
    packages=find_packages(include=[
        "ar3", "ar3.*"
    ]),
    install_requires=[
                    'bs4',
                    'pysmb',
                    'pywinrm',
                    'pypykatz',
                    'requests',
                    'openpyxl',
                    'python-docx',
                    'terminaltables',
                    'ipparser>=0.3.5',
                    'minidump',
    ],
    classifiers = [
                    "Environment :: Console",
                    "Programming Language :: Python :: 3",
                    "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
                    "Topic :: Security"
    ],
    entry_points= {
                    'console_scripts': ['ar3=ar3:main', 'activereign=ar3:main', 'ar3db=ar3.ops.db.db_shell:main']
    })

"""Install Submodules"""
if path.exists('ar3/thirdparty/impacket/setup.py'):
    system("cd ar3/thirdparty/impacket/;python3 setup.py install")
else:
    print("[!] Error installing impacket library, which may cause errors in ActiveReign")
    print("[*] Consider rerunning, or install manually at:")
    print("        https://github.com/SecureAuthCorp/impacket")