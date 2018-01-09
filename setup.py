from setuptools import setup

setup(
    name='toshi-services',
    version='0.0.1',
    author='Tristan King',
    author_email='tristan.king@gmail.com',
    packages=['toshi'],
    url='http://github.com/toshiapp/toshi-services-lib',
    description='',
    long_description=open('README.md').read(),
    setup_requires=['pytest-runner'],
    install_requires=[
        'regex',
        'tornado==4.5.1',
        'ethereum==2.3.0',
        'secp256k1'
    ],
    dependency_links=[
    ],
    tests_require=[
        'pytest',
        'requests',
        'testing.common.database',
        'testing.postgresql',
        'testing.redis',
        'asyncpg',
        'mixpanel==4.3.2',
        'redis',
        'msgpack-python',
        'aioredis==0.3.2'
    ]
)
