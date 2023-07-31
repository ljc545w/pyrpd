#-*-coding: utf-8 -*-

import sys
try:
    from setuptools import setup
except:
    from distutils.core import setup
from setuptools import find_packages
from distutils.extension import Extension
from Cython.Build import cythonize

define_macros=[("UNICODE",1),("_UNICODE",1),("_WINDOWS",1),("NDEBUG",1),("_PYTHON",1)]
if sys.maxsize > 2 ** 32:
    define_macros.append(("_WIN64",1))
    
with open("README.md","r",encoding = 'utf-8') as f:
    long_description = f.read()

ext_modules = [
    Extension("pyrpd._pyrpd", 
              sources=["./source/_pyrpd.pyx"],
              libraries=["Advapi32"],
              include_dirs=["../","."],
              define_macros=define_macros,
              language="c++"),
    ]

setup(
    name="pyrpd",
    version="1.0.3",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Jack Li",
    author_email="ljc545w@qq.com",
    url='https://github.com/ljc545w/pyrpd',
    install_requires=[],
    license="MIT License",
    packages=find_packages(),
    platforms=["win"],
    ext_modules = cythonize(ext_modules,compiler_directives={'language_level': '3'}),
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        "Programming Language :: Python",
    ],
)
