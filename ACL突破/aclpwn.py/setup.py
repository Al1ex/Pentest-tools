from setuptools import setup

setup(name='aclpwn',
      version='1.0.0',
      description='Active Directory ACL exploitation using BloodHound',
      license='MIT',
      classifiers=[
          'Intended Audience :: Information Technology',
          'License :: OSI Approved :: MIT License',
          'Programming Language :: Python :: 2',
          'Programming Language :: Python :: 2.7',
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: 3.5',
          'Programming Language :: Python :: 3.6',
      ],
      author='Dirk-jan Mollema / Fox-IT',
      author_email='dirkjan.mollema@fox-it.com',
      url='https://github.com/fox-it/aclpwn.py',
      packages=['aclpwn'],
      install_requires=['impacket', 'ldap3>=2.5', 'neo4j-driver', 'requests'],
      entry_points={
          'console_scripts': ['aclpwn=aclpwn:main']
      }
     )
