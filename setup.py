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

ext_modules = [
    Extension("pyrpd._pyrpd", 
              sources=["./source/_pyrpd.pyx"],
              libraries=["Advapi32"],
              include_dirs=["./include","."],
              define_macros=define_macros,
              extra_compile_args=["/wd4551"],
              language="c++"),
    ]

setup(
    packages=find_packages(),
    platforms=["win"],
    ext_modules = cythonize(ext_modules,compiler_directives={'language_level': '3'}),
)
