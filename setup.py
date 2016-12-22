from setuptools import setup

setup(
    name='token-services',
    version='0.0.1',
    author='Tristan King',
    author_email='tristan.king@gmail.com',
    packages=['tokenservices'],
    url='http://github.com/tokenbrowser/token-services-lib',
    description='',
    long_description=open('README.md').read(),
    install_requires=[
        'asyncbb'
    ],
    dependency_links=['http://github.com/tristan/asyncbb/tarball/master#egg=asyncbb']
)
