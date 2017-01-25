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
    setup_requires=['pytest-runner'],
    install_requires=[
        'asyncbb==0.0.1',
        'tokenbrowser==0.0.1'
    ],
    dependency_links=[
        'http://github.com/tristan/asyncbb/tarball/master#egg=asyncbb-0.0.1',
        #'http://github.com/tokenbrowser/tokenbrowser-python/tarball/master#egg=tokenbrowser-0.0.1'
        'git+ssh://git@github.com/tokenbrowser/tokenbrowser-python.git#egg=tokenbrowser-0.0.1'
    ],
    tests_require=[
        'pytest',
        'requests'
    ]
)
