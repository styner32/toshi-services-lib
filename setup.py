import sys
from setuptools import setup

# verify python version
if sys.version_info[:2] < (3, 5):
    print("Requires python version 3.5 or greater")
    sys.exit(1)

setup(
    name='toshi-services',
    version='0.0.7',
    author='Tristan King',
    author_email='tristan.king@gmail.com',
    packages=['toshi'],
    url='http://github.com/toshiapp/toshi-services-lib',
    description='',
    long_description=open('README.md').read(),
    setup_requires=['pytest-runner'],
    install_requires=[
        'regex',
        'tornado==5.0.1'
    ],
    dependency_links=[
    ],
    extras_require={
        'ethereum': [
            'ethereum==2.3.1',
            'rlp==0.6.0',
            'coincurve'
        ]
    },
    tests_require=[
        'pytest',
        'requests',
        'testing.common.database',
        'testing.postgresql',
        'testing.redis',
        'asyncpg',
        'mixpanel==4.3.2',
        'msgpack-python',
        'aioredis==1.1.0',
        'botocore==1.8.21',
        'boto3==1.5.7',
        'aiobotocore==0.6.0',
        'moto[server]==1.3.1'
    ]
)
