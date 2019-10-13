from setuptools import setup

setup(
    name='pe',
    version='0.1.2',
    description='Another PE info tool',
    url='https://github.com/Te-k/pe',
    author='Tek',
    author_email='tek@randhome.io',
    keywords='malware',
    include_package_data=True,
    install_requires=['pefile', 'yara-python', 'python-magic', 'ipython', 'virustotal-api==1.1.11', 'ssdeep==3.4'],
    license='MIT',
    python_requires='>=3.5',
    packages=['pe', 'pe.plugins', 'pe.lib', 'pe.data'],
    package_dir={'pe.lib': 'pe/lib'},
    package_data={'pe': ['pe/data/*.yara']},
    entry_points= {
        'console_scripts': [ 'pe=pe.main:main' ]
    }
)
