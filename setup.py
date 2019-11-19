from setuptools import setup

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='pe',
    version='0.1.2',
    description='Another PE info tool',
    long_description=long_description,
    long_description_content_type="text/markdown",
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
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ]
)
