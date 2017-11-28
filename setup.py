from setuptools import setup

setup(
    name='pe',
    version='0.1',
    description='Another PE info tool',
    url='https://github.com/Te-k/pe',
    author='Tek',
    author_email='tek@randhome.io',
    keywords='malware',
    install_requires=['pefile'],
    license='GPLv3',
    packages=['pe', 'pe.plugins'],
    entry_points= {
        'console_scripts': [ 'pe=pe.main:main' ]
    }
)
