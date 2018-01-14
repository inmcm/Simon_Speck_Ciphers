from setuptools import setup, find_packages

setup(
    name='SimonSpeckCiphers',
    version='0.9.9',
    description="Implementations of the NSA's Simon and Speck Block Ciphers",
    long_description=open('README.md').read(),
    url='https://github.com/inmcm/Simon_Speck_Ciphers',
    #scripts=['bin/benchmark_simonspeck.py'],
    license='MIT',
    author='Calvin McCoy',
    author_email='calvin.mccoy@gmail.com',
    classifiers=['Development Status :: 4 - Beta',
                 'Intended Audience :: Developers',
                 'Topic :: Cryptography :: Encryption',
                 'License :: OSI Approved :: MIT License',
                 'Programming Language :: Python :: 2',
                 'Programming Language :: Python :: 2.7',
                 'Programming Language :: Python :: 3',
                 'Programming Language :: Python :: 3.4',
                 'Programming Language :: Python :: 3.5',
                 'Programming Language :: Python :: 3.6'],
    keywords='cryptography cipher encryption decryption',
    packages=find_packages(exclude=['tests*']),
    setup_requires=['pytest-runner'],
    tests_require=['pytest']
)
