from setuptools import setup, find_packages
from os.path import join, dirname

setup(
    name='efq',
    version='0.0',
    packages=find_packages(),
    long_description=open(join(dirname(__file__), 'README.txt')).read(),
    install_requires=[
        'tornado>=3.2',
        'ujson',
        'toredis',
    ],
    dependency_links=[
        'git+https://github.com/ei-grad/toredis.git#egg=toredis',
    ]
)
