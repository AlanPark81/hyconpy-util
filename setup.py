from setuptools import setup

setup(name='hyconpy-util',
      version='0.1',
      description='Hycon utility functions in python',
      url='http://github.com/Team-Hycon',
      author='Hycon Team',
      author_email='devrd@hycon.com',
      license='GPL',
      packages=['hyconpy'],
      zip_safe=False, install_requires=['base58', 'Crypto', 'bitcoin', 'bitcoinlib', 'secp256k1'])
