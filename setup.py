"""sandboxapi setup.py."""
from setuptools import setup

with open('README.md', encoding='utf-8') as readme:
    long_description = readme.read()

setup(
    name='sandboxapi',
    version='2.0.0.rc0',
    packages=[
        'sandboxapi',
    ],
    url='',
    license='GPLv2',
    author='Chris Morrow for InQuest.net',
    author_email='cmmorrow@inquest.net',
    description='A Python API for building integrations with malware sandboxes.',
    long_description=long_description,
    install_requires=[
        'click',
        'jbxapi',
        'requests',
        'six',
        'xmltodict',
    ],
    classifiers=[
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries',
        'Topic :: Internet',
    ],
    python_requires='>=3.5',
    entry_points={
        'console_scripts': [
            'sandboxapi = sandboxapi.cli:__main__',
        ],
    },
)
