#!/usr/bin/env python3.9
# -*- coding: utf-8 -*-
# ######################################################################
#
# SHACKSUM, Compute and verify file hashes with SHA.
# Copyright (C) 2026 MikeTurkey
# contact: voice[ATmark]miketurkey.com
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# ADDITIONAL MACHINE LEARNING PROHIBITION CLAUSE
#
# In addition to the rights granted under the applicable license(GPL-3),
# you are expressly prohibited from using any form of machine learning,
# artificial intelligence, or similar technologies to analyze, process,
# or extract information from this software, or to create derivative
# works based on this software.
#
# This prohibition includes, but is not limited to, training machine
# learning models, neural networks, or any other automated systems using
# the code or output of this software.
#
# The purpose of this prohibition is to protect the integrity and
# intended use of this software. If you wish to use this software for
# machine learning or similar purposes, you must seek explicit written
# permission from the copyright holder.
#
# see also 
#     GPL-3 Licence, https://www.gnu.org/licenses/gpl-3.0.html.en

import sys
if sys.version_info.major == 3 and sys.version_info.minor < 6:
    errmes = 'Error: Need python 3.6 later. [python: {0}]'.format(
        sys.version.split(' ')[0])
    print(errmes, file=sys.stderr)
    exit(1)
import typing
import os
import time
import re
import warnings
import hashlib
import string
import random
import unicodedata


class LPYknife(object):
    @staticmethod
    def allfalse(seq) -> bool:
        try:
            length = len(seq)
        except:
            errmes = ' Argument Type Error in alltrue(). Not list or tuple type.'
            raise TypeError(errmes)
        if length == 0:
            return False
        for b in seq:
            if not (isinstance(b, bool) and isinstance(b, int)):
                return False    # b is not bool or int type.
            if b != False:
                return False   # b is NOT False.
        return True

    @staticmethod
    def get_fileinodev(fpath: str) -> (int, int):
        try:
            fstat = os.stat(fpath)
        except:
            return (0, 0)
        return (fstat.st_ino, fstat.st_dev)

    @staticmethod
    def isbool(chkvar, varname: str = ''):
        if isinstance(chkvar, bool) != True:
            r = False if varname == '' else (
                False, '{0} is not bool type.'.format(varname))
            return r
        r = True if varname == '' else (True, '')
        return r

    @staticmethod
    def retry_iter(retry: int = 2, interval: float = 1.0, timeout: float = -1.0):
        if timeout > 0:
            retry = int(timeout/interval)
        for i in range(retry):
            yield i
            time.sleep(interval)

    @staticmethod
    def randomstrings(total_len: int, letters: str = string.ascii_letters+string.digits,
                      prefix: str = '', suffix: str = '') -> str:
        randomstring_len = total_len - len(prefix) - len(suffix)
        if randomstring_len <= 0:
            raise ValueError(
                '"total_len - length of prefix and suffix" is smaller than 1.')
        ret = ''.join([random.choice(letters)
                      for i in range(randomstring_len)])
        return prefix + ret + suffix


class Const_SHA(object):
    algorithms = ('MD5', 'SHA1', "SHA2-224", "SHA224",
                  "SHA2-256", "SHA256",
                  "SHA2-384", "SHA384",
                  "SHA2-512", "SHA512",
                  "SHA2-512/224", "SHA512-224",
                  "SHA2-512/256", "SHA512-256",
                  "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512")
    styles = ('OPENSSL', 'BSD', 'GNU')


class Args_shacksum(object):
    '''
      shacksum.py argument class
    '''

    def __init__(self):
        self.algorythm: str = ''     # -a, --algorythm, e.g. -a sha2-256, -a sha3-512
        self.check: str = ''     # -c, --check, e.g. -c CHECKSUM.SHA256
        self.style: str = ''     # --style, e.g. --style openssl, --style bsd
        self.verbose: bool = False   # --verbose
        self.version: bool = False   # --version
        self.help: bool = False   # --help
        self.license: bool = False   # --license
        self.stdin:   bool = False   # --stdin
        self.recursive: bool = False  # --recursive, Output recursive fpath.
        if sys.version_info.major == 3 and sys.version_info.minor < 9:
            # e.g. [script] -a sha256 [calcfile1] [file2] ...
            self.calcfiles = list()
        else:
            # e.g. [script] -a sha256 [calcfile1] [file2] ...
            self.calcfiles: list[str] = list()
        if sys.version_info.major == 3 and sys.version_info.minor < 9:
            self._styles = Const_SHA.styles
            self._algorithms = Const_SHA.algorithms
        else:
            self._styles: typing.Final[tuple] = Const_SHA.styles
            self._algorithms: typing.Final[tuple] = Const_SHA.algorithms
        self._checkmode: bool = False
        self._calcmode: bool = False
        return

    def print_attribute(self):
        for k, v in self.__dict__.items():
            mes = '{0}= {1}'.format(k, v)
            print(mes)
        return

    def analyze(self):
        '''
          analyze argument(sys.argv)
        step: analyze() -> check() -> normalize()
        '''
        arg: str  # s: str; errmes: str
        on_algorythm: bool = False
        on_check: bool = False
        on_style: bool = False
        for arg in sys.argv[1:]:
            if arg == '--recursive':
                self.recursive = True
                continue
            if arg == '--stdin':
                self.stdin = True
                continue
            if arg == '--verbose':
                self.verbose = True
                continue
            if arg == '--version':
                self.version = True
                return
            if arg == '--help':
                self.help = True
                return
            if arg == '--license':
                self.license = True
                return
            if on_algorythm:
                self.algorythm = arg
                on_algorythm = False
                continue
            if on_check:
                self.check = arg
                on_check = False
                continue
            if on_style:
                self.style = arg
                on_style = False
                continue
            if arg == '-a' or arg == '--algorythm':
                on_algorythm = True
                continue
            if arg == '-c' or arg == '--check':
                on_check = True
                continue
            if arg == '--style':
                on_style = True
                continue
            self.calcfiles.append(arg)
            continue
        return

    def checkmethod(self):
        errmes: str
        s: str
        checkmode: bool = False
        calcmode:  bool = False
        checkmode = True if self.check != '' else False
        calcmode = True if len(self.calcfiles) >= 1 else False
        calcmode = True if self.stdin else calcmode
        if LPYknife.allfalse([checkmode, calcmode]):
            errmes = 'Error: Empty argument files.'
            print(errmes, file=sys.stderr)
            exit(1)
        self._checkmode = checkmode
        self._calcmode = calcmode
        if self.style != '':
            s = self.style.upper()
            if s not in self._styles:
                errmes = 'Error: Invalid --style option value. OPENSSL, BSD or GNU. [{0}]'
                errmes = errmes.format(self.style)
                print(errmes, file=sys.stderr)
                exit(1)
        if calcmode:
            s = self.algorythm.upper()
            if s not in self._algorithms:
                s = 'Error: Not found --algorithm option. [{0}]'
                errmes = s.format(self.algorythm)
                print(errmes, file=sys.stderr)
                exit(1)
        if checkmode == True:
            if len(self.calcfiles) >= 1:
                errmes = 'Error: Invalid -c, --check option on calcmode.'
                print(errmes, file=sys.stderr)
            s = self.algorythm.upper()
            if s != '' and s not in self._algorithms:
                s = 'Error: Not found --algorithm option. [{0}]'
                errmes = s.format(self.algorythm)
                print(errmes, file=sys.stderr)
                exit(1)
        if self.recursive:
            errmes = 'Error: Not support --recursive option.'
            print(errmes, file=sys.stderr)
            exit(1)
        return

    def normalize(self):
        '''
          Normalize argument of shacksum.py
        '''
        errmes: str
        fpath: str
        if self.style != '':
            self.style = self.style.upper()
            if self.style not in self._styles:
                errmes = 'Error: Invalid --style option value. OPENSSL, BSD or GNU. [{0}]'
                errmes = errmes.format(self.style)
                print(errmes, file=sys.stderr)
                exit(1)
        if self.algorythm != '':
            self.algorythm = self.algorythm.upper()
            if self.algorythm not in self._algorithms:
                s = 'Error: Not found --algorithm option. [{0}]'
                errmes = s.format(self.algorythm)
                print(errmes, file=sys.stderr)
                exit(1)
        if self._checkmode:
            fpath = os.path.abspath(self.check)
            fpath = Main_common.unicodenormalized_fpath_exists(fpath)
            if fpath == '':
                errmes = 'Error: Not found the file. [{0}]'.format(self.check)
                print(errmes, file=sys.stderr)
                exit(1)
            if os.path.isfile(fpath) != True:
                errmes = 'Error: Not regular file. [{0}]'.format(self.check)
                print(errmes, file=sys.stderr)
                exit(1)
            self.check = fpath
        if self._calcmode:
            templist: list = list()
            self.calcfiles = [Main_common.unicodenormalized_fpath_exists(
                fpath) for fpath in self.calcfiles]
            for f in self.calcfiles:
                fpath = Main_common.unicodenormalized_fpath_exists(f)
                if fpath == '':
                    errmes = 'Error: Not found. [{0}]'.format(f)
                    print(errmes, file=sys.stderr)
                    exit(1)
                if os.path.isfile(fpath) != True and os.path.isdir(fpath) != True:
                    errmes = 'Error: Not regular file and directory. [{0}]'.format(
                        fpath)
                    print(errmes, file=sys.stderr)
                    exit(1)
                templist.append(fpath)
            self.calcfiles = templist
            self.algorythm = 'SHA2-256' if self.algorythm == '' else self.algorythm
            self.style = 'OPENSSL' if self.style == '' else self.style
        return


class _Hashrowstringstyle_style_namedtuple(typing.NamedTuple):
    opensslstyle: bool = False
    BSDstyle: bool = False
    GNUstyle: bool = False

    def _maketrue(self, names: list):
        '''
          make true value attribute.
          Turn True if style name string in in styles list.
        names(str): style name string of list.  e.g. ['opensslstyle', 'BSDstyle']
        recipe
          t = _Hashrowstringstyle_style_namedtuple();
          t = t._maketrue(['opensslstyle', 'BSDstyle']);
            t.opensslstyle: True
            t.BSDstyle    : True
            t.GNUstyle    : False
        '''
        name: str
        d = self._asdict()
        result = d
        for name in names:
            if isinstance(name, str) != True:
                errmes = 'Error: names is string of list type.'
                raise TypeError(errmes)
            if name not in d.keys():
                errmes = 'Error: unknown style name [{0}]'.format(name)
                raise ValueError(errmes)
        for name in d.keys():
            if name in names:
                result[name] = True
        t = self._make(result.values())
        return t


class Hashrowstringstyle():
    def __init__(self):
        initstyleattr = _Hashrowstringstyle_style_namedtuple()
        self.guess: tuple = initstyleattr     # Guess row style.
        self._head10: tuple = initstyleattr  # head 10 strings on the row
        self._tailhash: tuple = initstyleattr  # tail string is hash.
        self._beforehashstr: tuple = initstyleattr  # before hash string on the row
        self._afteralgostr: tuple = initstyleattr  # after algorithm string on the row
        self._head32: tuple = initstyleattr  # head 32 strings on the row
        self._tail32: tuple = initstyleattr  # tail 32 strings on the row
        return

    def _analyze_head10(self, row: str) -> tuple:
        s: str
        t: tuple
        style: tuple = _Hashrowstringstyle_style_namedtuple()
        algonames: typing.Final[tuple[str]] = ('MD5', 'SHA1', "SHA2-224", "SHA224",
                                               "SHA2-256", "SHA256",
                                               "SHA2-384", "SHA384",
                                               "SHA2-512", "SHA512",
                                               "SHA2-512/224", "SHA512-224",
                                               "SHA2-512/256", "SHA512-256",
                                               "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512")
        for s in algonames:
            if row.startswith(s):
                t = style._maketrue(['opensslstyle', 'BSDstyle'])
                return t
        return style

    @staticmethod
    def _find_tail_09af_32letterlonger(row: str) -> int:
        '''
          Find '[0-9a-f]{32,512}$' string on the row
        > 0: Match '[0-9a-f]{32,512}$' pattern, The value is index of start.
         -1: Not Match '[0-9a-f]{32,512}$' pattern 
        '''
        ptn: str = r'[0-9a-f]{32,512}$'
        start: int
        end: int
        m = re.search(ptn, row)
        if m == None:
            return -1
        start, end = m.span()
        return start

    def _analyze_tailhash(self, row: str) -> tuple:
        start: int
        style: tuple = _Hashrowstringstyle_style_namedtuple()
        start = self._find_tail_09af_32letterlonger(row)
        if start > 2:  # Find, not head
            return style._maketrue(['opensslstyle', 'BSDstyle'])
        return style  # Not find

    def _analyze_beforehashstr(self, row: str) -> tuple:
        start: int
        s: str
        startpoint: int
        style: tuple = _Hashrowstringstyle_style_namedtuple()
        start = self._find_tail_09af_32letterlonger(row)
        if start < 2:  # Not Find or not head
            return style
        startpoint = start - 3
        s = row[startpoint:]
        if s.startswith(')= '):
            return style._maketrue(['opensslstyle'])
        startpoint = start - 4
        s = row[startpoint:]
        if s.startswith(') = '):
            return style._maketrue(['BSDstyle'])
        return style  # Not match.

    def _analyze_afteralgostr(self, row: str) -> tuple:
        hashinfo: str
        bsdstyle: str
        opensslstyle: str
        style: tuple = _Hashrowstringstyle_style_namedtuple()
        hashinfos: tuple = ('MD5', 'SHA1', "SHA2-224", "SHA224",
                            "SHA2-256", "SHA256",
                            "SHA2-384", "SHA384",
                            "SHA2-512", "SHA512",
                            "SHA2-512/224", "SHA512-224",
                            "SHA2-512/256", "SHA512-256",
                            "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512")
        for hashinfo in hashinfos:
            bsdstyle = '{0} '.format(hashinfo)
            opensslstyle = '{0}('.format(hashinfo)
            if row.startswith(bsdstyle):
                return style._maketrue(['BSDstyle'])
            elif row.startswith(opensslstyle):
                return style._maketrue(['opensslstyle'])
        return style  # Not match.

    def _analyze_head32(self, row: str) -> tuple:
        style: tuple = _Hashrowstringstyle_style_namedtuple()
        m: typing.Union[re.Match, None] = None
        ptn: str = r'^[0-9a-f]{32,512}'
        m = re.match(ptn, row)
        if m == None:
            return style
        else:
            return style._maketrue(['GNUstyle'])

    def analyze(self, row_arg: str):
        errmes: str
        row: str  # s: str
        style: tuple = _Hashrowstringstyle_style_namedtuple()
        if isinstance(row_arg, str) != True:
            errmes = 'Error: row_arg is not string. analyze() method.'
            raise TypeError(errmes)
        row = row_arg.strip()
        self._head10 = self._analyze_head10(row)
        self._tailhash = self._analyze_head10(row)
        self._beforehashstr = self._analyze_beforehashstr(row)
        self._afteralgostr = self._analyze_afteralgostr(row)
        self._head32 = self._analyze_head32(row)
        if self._head32.opensslstyle == False:
            if self._head10.opensslstyle == True and self._tailhash.opensslstyle == True and\
               self._beforehashstr.opensslstyle == True and self._afteralgostr.opensslstyle == True:
                self.guess = style._maketrue(['opensslstyle'])
                return
        if self._head32.BSDstyle == False:
            if self._head10.BSDstyle == True and self._tailhash.BSDstyle == True and\
               self._beforehashstr.BSDstyle == True and self._afteralgostr.BSDstyle == True:
                self.guess = style._maketrue(['BSDstyle'])
                return
        if self._head32.GNUstyle == True:
            if self._head10.GNUstyle == False and self._tailhash.GNUstyle == False and\
               self._beforehashstr.GNUstyle == False and self._afteralgostr.GNUstyle == False:
                self.guess = style._maketrue(['GNUstyle'])
                return
        return

    def print_analyze_attribute(self):
        '''
        print attributes(changeing on analyze())
        '''
        print('style._head10')
        Main_common.print_namedtuple(self._head10)
        print('style._tailhash')
        Main_common.print_namedtuple(self._tailhash)
        print('style._beforehashstr')
        Main_common.print_namedtuple(self._beforehashstr)
        print('style._afteralgostr')
        Main_common.print_namedtuple(self._afteralgostr)
        print('style._head32')
        Main_common.print_namedtuple(self._head32)
        print('style.guess')
        Main_common.print_namedtuple(self.guess)
        return


class _Hashinfo_namedtuple(typing.NamedTuple):
    hashdg: str = ''
    fpath: str = ''
    algo: str = ''
    if sys.version_info.major == 3 and sys.version_info.minor < 9:
        algo_guess: list = ['']
    else:
        algo_guess: list[str] = ['']
    stylename: str = ''
    fpath_abs: str = ''

    def __getvar_hashinfos(self) -> tuple:
        _hashinfos: tuple = ('MD5', 'SHA1', "SHA2-224", "SHA224",
                             "SHA2-256", "SHA256",
                             "SHA2-384", "SHA384",
                             "SHA2-512", "SHA512",
                             "SHA2-512/224", "SHA512-224",
                             "SHA2-512/256", "SHA512-256",
                             "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512")
        return _hashinfos

    def __getvar_hashlengths(self) -> dict:
        _hashlength: dict = {'MD5': 32,
                             'SHA1': 40,
                             "SHA2-224": 56, "SHA224": 56,
                             "SHA2-256": 64, "SHA256": 64,
                             "SHA2-384": 96, "SHA384": 96,
                             "SHA2-512": 128, "SHA512": 128,
                             "SHA2-512/224": 56, "SHA512-224": 56,
                             "SHA2-512/256": 64, "SHA512-256": 64,
                             "SHA3-224": 56, "SHA3-256": 64,
                             "SHA3-384": 96, "SHA3-512": 128}
        return _hashlength

    def _getheadstr_hashalgorithm(self, row: str) -> str:
        hashinfos: tuple = self.__getvar_hashinfos()
        for s in hashinfos:
            if row.startswith(s):
                return s
        return ''

    def _gettailstr_hashdgst(self, hashalgo: str, row: str) -> str:
        sidx: int
        epnt: int
        hashlengths: dict = self.__getvar_hashlengths()
        hashlen: int = hashlengths[hashalgo]
        ptn: str = r''.join([r'[0-9a-f]{', str(hashlen), r'}$'])
        mobj = re.search(ptn, row)
        if mobj == None:
            return ''
        sidx, epnt = mobj.span()
        hashdg: typing.Final[str] = row[sidx: epnt]
        return hashdg

    def _makeinfo_BSDstyle(self, row_arg: str, basedir: str) -> typing.NamedTuple:
        errmes: str  # s: str
        reterr = self._make(['', '', '', [''], '', ''])
        if isinstance(row_arg, str) != True:
            errmes = 'Error: row_arg is not string type on _makeinfo_opensslstyle()'
            raise TypeError(errmes)
        row: str = row_arg.strip()
        hashalgo = self._getheadstr_hashalgorithm(row)
        if hashalgo == '':
            return reterr
        hashdg: str = self._gettailstr_hashdgst(hashalgo, row)
        if hashdg == '':
            return reterr
        fpath: str
        tmpstr: str
        ptn = ') = {0}'.format(hashdg)
        epnt = row.rfind(ptn)
        if epnt == -1:
            return reterr
        tmpstr = row[:epnt]
        ptn = '{0} ('.format(hashalgo)
        fpath = tmpstr.replace(ptn, '', 1)  # replace ptn to '' at once
        if os.path.isabs(fpath):
            fpath_abs = fpath   # fpath is absolute
        else:
            fname: str = os.path.basename(fpath)  # fpath is relative
            fpath_abs: str = os.path.abspath(os.path.join(basedir, fname))
        return self._make([hashdg, fpath, hashalgo, [''], 'BSDstyle', fpath_abs])

    def _makeinfo_opensslstyle(self, row_arg: str, basedir: str) -> typing.NamedTuple:
        errmes: str
        s: str
        reterr = self._make(['', '', '', [''], '', ''])
        if isinstance(row_arg, str) != True:
            errmes = 'Error: row_arg is not string type on _makeinfo_opensslstyle()'
            raise TypeError(errmes)
        row: str = row_arg.strip()
        hashalgo: str = ''
        hashinfos: tuple = self.__getvar_hashinfos()
        for s in hashinfos:
            if row.startswith(s):
                hashalgo = s
                break
        if hashalgo == '':
            return reterr
        sidx: int
        epnt: int
        hashlengths: dict = self.__getvar_hashlengths()
        hashlen: int = hashlengths[hashalgo]
        ptn: str = r''.join([r'[0-9a-f]{', str(hashlen), r'}$'])
        mobj = re.search(ptn, row)
        if mobj == None:
            return reterr
        sidx, epnt = mobj.span()
        hashdg: typing.Final[str] = row[sidx: epnt]
        fpath: str
        tmpstr: str
        ptn = ')= {0}'.format(hashdg)
        epnt = row.rfind(ptn)
        if epnt == -1:
            return reterr
        tmpstr = row[:epnt]
        ptn = '{0}('.format(hashalgo)
        fpath = tmpstr.replace(ptn, '', 1)  # replace ptn to '' at once
        if os.path.isabs(fpath):
            fpath_abs = fpath   # fpath is absolute
        else:
            fpath_abs: str = os.path.abspath(os.path.join(basedir, fpath))
        return self._make([hashdg, fpath, hashalgo, [''], 'opensslstyle', fpath_abs])

    def _makeinfo_GNUstyle(self, row_arg: str, basedir: str) -> typing.NamedTuple:
        errmes: str
        templist: list[str]  # s: str
        reterr = self._make(['', '', '', [''], '', ''])
        row: str = ''
        hashdg: str = ''
        fpath: str = ''
        hashlengths: dict = {}
        algo_guess: list[str] = []
        algo: str = ''
        length: int = ''
        ptn: str = ''
        tempset: set = set()
        fname: str = ''
        fpath_abs: str = ''
        if isinstance(row_arg, str) != True:
            errmes = 'Error: row_arg is not string type on _makeinfo_opensslstyle()'
            raise TypeError(errmes)
        row = row_arg.strip()
        templist = row.split('  ', maxsplit=1)
        if len(templist) != 2:
            return reterr
        hashdg = templist[0]
        fpath = templist[1]
        hashlengths = self.__getvar_hashlengths()
        for algo, length in hashlengths.items():
            ptn = r''.join([r'^[0-9a-f]{', str(length), r'}$'])
            mobj = re.match(ptn, hashdg)
            if mobj == None:
                continue
            algo_guess.append(algo)

        def alias_to_formal(algo: str):
            hashalgo_alias = {'SHA224': 'SHA2-224',
                              'SHA256': 'SHA2-256',
                              'SHA384': 'SHA2-384',
                              'SHA512': 'SHA2-512',
                              "SHA512-224": "SHA2-512/224",
                              'SHA512-256': 'SHA2-512/256'}
            for k, v in hashalgo_alias.items():
                if algo == k:
                    return v
            return algo
        templist = [alias_to_formal(algo) for algo in algo_guess]
        tempset = set(templist)
        algo_guess = list(tempset)
        if os.path.isabs(fpath):
            fpath_abs = fpath   # fpath is absolute
        else:
            fname = os.path.basename(fpath)  # fpath is relative
            fpath_abs = os.path.abspath(os.path.join(basedir, fname))
        return self._make([hashdg, fpath, '', algo_guess, 'GNUstyle', fpath_abs])


class _CalcHashInfo_namedtuple(typing.NamedTuple):
    hashdg: str = ''
    fpath: str = ''
    algo: str = ''
    fpath_abs: str = ''  # absolute fpath
    errmes: str = ''  # calculation error message.
    # Match self.calc() result and row hashdg in --check file.
    matched: bool = False


class Runcheckmode(object):
    @staticmethod
    def getrowinfo_hash(row: str, basedir: str) -> _Hashinfo_namedtuple:
        normrow: str = row.strip()
        if normrow.startswith('#'):
            return None
        style = Hashrowstringstyle()
        style.analyze(row)
        if LPYknife.allfalse([style.guess.opensslstyle, style.guess.BSDstyle, style.guess.GNUstyle]):
            return None
        rowinfo = _Hashinfo_namedtuple()
        if style.guess.opensslstyle:
            rowinfo = rowinfo._makeinfo_opensslstyle(row, basedir)
        if style.guess.BSDstyle:
            rowinfo = rowinfo._makeinfo_BSDstyle(row, basedir)
        if style.guess.GNUstyle:
            rowinfo = rowinfo._makeinfo_GNUstyle(row, basedir)
        if len(rowinfo.hashdg) == 0:
            return None
        return rowinfo

    @staticmethod
    def calc(rowinfo: _Hashinfo_namedtuple, algo: str = '') -> _CalcHashInfo_namedtuple:
        kind: str
        matched: bool
        kind = algo if algo != '' else rowinfo.algo
        flag, errmes, hashdg = Main_common.calc_fhashdgst(
            rowinfo.fpath_abs, kind)
        if flag != True:
            calculated = _CalcHashInfo_namedtuple(
                '', rowinfo.fpath, kind, rowinfo.fpath_abs, errmes, False)
            return calculated  # Error
        matched = True if rowinfo.hashdg == hashdg else False
        calculated = _CalcHashInfo_namedtuple(
            hashdg, rowinfo.fpath, kind, rowinfo.fpath_abs, '', matched)
        return calculated

    @staticmethod
    def print_resultcalc(calchash: _CalcHashInfo_namedtuple, rowinfo, fp, printabs: bool = False, printwithabs: bool = False):
        mes: str
        errmes: str
        fpath: str
        try:
            fp.flush()
        except:
            errmes = 'Error: fp is not file pointer, print_resultcalc()'
            raise TypeError(errmes)
        fpath = calchash.fpath_abs if printabs == True else calchash.fpath
        if calchash.matched:
            mes = 'OK[{0}]: {1}'.format(calchash.algo, fpath)
            mes = unicodedata.normalize('NFD', mes)
            print(mes, file=fp)
        else:
            mes = 'NG[{0}]: {1}\n  hashdg(checkfile): {2}\n  hashdg(calc)     : {3}\n  Error: {4}'
            mes = mes.format(calchash.algo, fpath, rowinfo.hashdg,
                             calchash.hashdg, calchash.errmes)
            mes = unicodedata.normalize('NFD', mes)
            print(mes, file=fp)
            ''' mes = 'NG[{0}]: {1}'.format(calchash.algo, fpath);
            mes = unicodedata.normalize('NFD', mes);
            print(mes, file=fp);
            mes = '  hashdg(checkfile): {0}\n  hashdg(calc)     : {1}'.format(rowinfo.hashdg, calchash.hashdg)
            mes = unicodedata.normalize('NFD', mes);
            print(mes, file=fp);
            mes = '  Error: {0}'.format(calchash.errmes)
            print(mes, file=fp); '''
        if printwithabs:
            mes = '  absolutepath: {0}'.format(calchash.fpath_abs)
            mes = unicodedata.normalize('NFD', mes)
            print(mes, file=fp)
        return

    def run(self, normargs: Args_shacksum):
        checkdirname: str = ''
        templist: list = []
        rowinfo_list: list = []
        rowinfo: str = ''
        calchash: _CalcHashInfo_namedtuple
        matched_list: list[bool] = []
        checkdirname = os.path.dirname(normargs.check)
        with open(normargs.check, 'rt') as fp:
            templist = [Runcheckmode.getrowinfo_hash(
                row, checkdirname) for row in fp]
        rowinfo_list = [namedtpl for namedtpl in templist if namedtpl != None]
        for rowinfo in rowinfo_list:
            if rowinfo.stylename in ['opensslstyle', 'BSDstyle']:
                calchash = self.calc(rowinfo)
                self.print_resultcalc(
                    calchash, rowinfo, sys.stdout, printabs=False, printwithabs=False)
                matched_list.append(calchash.matched)
            elif rowinfo.stylename == 'GNUstyle':
                if normargs.algorythm == '':
                    errmes = 'Error: Not found --algorythm option.'
                    print(errmes, file=sys.stderr)
                    exit(1)
                calchash = self.calc(rowinfo, algo=normargs.algorythm)
                self.print_resultcalc(
                    calchash, rowinfo, sys.stdout, printabs=False, printwithabs=False)
                matched_list.append(calchash.matched)
        if len(matched_list) == 0:
            exit(1)
        elif all(matched_list):
            exit(0)
        else:
            exit(1)


class Runcalcmode(object):
    if sys.version_info.major == 3 and sys.version_info.minor < 9:
        styles = Const_SHA.styles
        algorithms = Const_SHA.algorithms
    else:
        styles: typing.Final[tuple[str]] = Const_SHA.styles
        algorithms: typing.Final[tuple[str]] = Const_SHA.algorithms

    @staticmethod
    def iterator_args(normargs: Args_shacksum):
        f: str
        fpath: str
        inodedevid: tuple
        dedup_list: list = list()
        for f in normargs.calcfiles:
            fpath = f
            inodedevid = LPYknife.get_fileinodev(fpath)
            if inodedevid[0] == 0 or inodedevid[1] == 0:
                continue  # Not read inode and devid
            if inodedevid in dedup_list:
                continue
            if os.path.isfile(fpath):
                # append inode, devid for deduplication
                dedup_list.append(inodedevid)
                yield fpath

    @staticmethod
    def iterator_stdin(normargs: Args_shacksum):
        f: str
        fpath: str
        inodedevid: tuple
        dedup_list: list = list()
        for f in sys.stdin:
            fpath = f.rstrip('\n')
            inodedevid = LPYknife.get_fileinodev(fpath)
            if inodedevid[0] == 0 or inodedevid[1] == 0:
                continue  # Not read inode and devid
            if inodedevid in dedup_list:
                continue
            if os.path.isfile(fpath):
                # append inode, devid for deduplication
                dedup_list.append(inodedevid)
                yield fpath

    def print_hash(self, fpath: str, hashdg: str, algo: str, style: str, fp, absolute: bool = False):
        errmes: str
        mes: str
        ptn: str
        f: str
        if algo not in self.algorithms:
            errmes = 'Error: Unknown algorithm. [{0}]'.format(algo)
            print(errmes, file=sys.stderr)
            exit(1)
        if style not in self.styles:
            errmes = 'Error: Unknown style. [{0}]'.format(style)
            print(errmes, file=sys.stderr)
            exit(1)
        ptn = r'[0-9a-f]{32,512}'
        mobj = re.match(ptn, hashdg)
        if mobj == None:
            errmes = 'Error: RuntimeError, Empty Hash Digest.'
            print(errmes, file=sys.stderr)
            exit(1)
        if os.path.isfile(fpath) != True:
            errmes = 'Error: RuntimeError, Not regular file. [{0}]'.format(
                fpath)
            print(errmes, file=sys.stderr)
            exit(1)
        f = os.path.abspath(fpath) if absolute == True else fpath
        if style == 'OPENSSL':
            mes = '{0}({1})= {2}'.format(algo, f, hashdg)
        elif style == 'BSD':
            mes = '{0} ({1}) = {2}'.format(algo, f, hashdg)
        elif style == 'GNU':
            mes = '{0}  {1}'.format(hashdg, f)
        else:
            RuntimeError('Error: Unknown style.')
        print(mes, file=fp)
        return

    def run(self, normargs: Args_shacksum):
        errmes: str
        if normargs.stdin:
            iterator = self.iterator_stdin  # load fpaths by sys.stdin
        else:
            iterator = self.iterator_args  # load fpaths by arguments.
        for f in iterator(normargs):
            flag, errmes, hashdg = Main_common.calc_fhashdgst(
                f, normargs.algorythm)
            if flag != True:
                print(errmes, file=sys.stderr)
                exit(1)
            self.print_hash(f, hashdg, normargs.algorythm,
                            normargs.style, sys.stdout, absolute=False)
        return


class Main_common(object):
    ver = '0.0.1'
    date = '13 Jan 2026'

    @classmethod
    def show_version(cls):
        print(cls.ver)
        return

    @classmethod
    def show_help(cls):
        mes: str
        scr_version: str = cls.ver
        scr_date: str = cls.date
        scr_fname: str = 'shacksum'
        meses: list = ['{0} created by MikeTurkey'.format(scr_fname),
                       'Version {0}, {1}'.format(scr_version, scr_date),
                       '2026, COPYRIGHT MikeTurkey, All Right Reserved.',
                       'ABSOLUTELY NO WARRANTY. SHACKSUM LICENCE',
                       'The License is based on GPLv3 Licence',
                       'Summary',
                       '  Calculate SHA checksum and Verity checkfile.',
                       'Description',
                       '  -a, --algorythm: calculate with the algorithm.',
                       '    MD5, SHA1, SHA2-224, SHA224, SHA2-256, SHA256, SHA2-384, SHA384,',
                       '    SHA2-512, SHA512, SHA2-512/224, SHA512-224, SHA2-512/256, SHA512-256',
                       '    SHA3-224, SHA3-256, SHA3-384, SHA3-512',
                       '  -c, --check: Hash digest in checkfile check by the algorythm.',
                       '    algorythm priority: --algorythm option(1), The row info in the file(2)',
                       '    Ignore --algorythm option, if the file format are openssl, bsd style.',
                       '  --style: Output by the style. if --check option, Load by the style.',
                       '    openssl: openssl style, openssl dgst command',
                       '      e.g. MD5(/usr/bin/python3)= b804370957619edc6510439fed2b35b0',
                       '    BSD: BSD style, shasum --tag, sha1~sha512 command on FreeBSD',
                       '      e.g. MD5(/usr/bin/python3)= b804370957619edc6510439fed2b35b0',
                       '    GNU: GNU style, shasum, sha1sum~sha512sum GNU edition.',
                       '      e.g. f1768a9ca3017fe929fb463f2fd3c741b1394340  /usr/bin/python3',
                       '  --version: show version and information.',
                       '',
                       'e.g.',
                       '  {0} --version'.format(scr_fname),
                       '  {0} -c CHECKSUM.SHA256'.format(scr_fname),
                       '  {0} -a sha256 *.txt'.format(scr_fname),
                       '  {0} -a sha256 --style openssl *.txt'.format(
                           scr_fname),
                       '  {0} -a sha256 --style BSD *.txt'.format(scr_fname),
                       '  {0} -a sha256 --style GNU *.txt'.format(scr_fname),
                       '']
        if scr_fname == '':
            raise RuntimeError()
        for mes in meses:
            mes = unicodedata.normalize('NFD', mes)
            print(mes)
        return

    @staticmethod
    def show_license():
        meses: list = [
            '',
            'SHACKSUM, Compute and verify file hashes with SHA.',
            'Copyright (C) 2026 MikeTurkey',
            'contact: voice[ATmark]miketurkey.com',
            'license: GPLv3 License',
            '',
            'This program is free software: you can redistribute it and/or modify',
            'it under the terms of the GNU General Public License as published by',
            'the Free Software Foundation, either version 3 of the License, or',
            '(at your option) any later version.',
            '',
            'This program is distributed in the hope that it will be useful,',
            'but WITHOUT ANY WARRANTY; without even the implied warranty of',
            'MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the',
            'GNU General Public License for more details.',
            '',
            'You should have received a copy of the GNU General Public License',
            'along with this program.  If not, see <https://www.gnu.org/licenses/>.',
            '',
            'ADDITIONAL MACHINE LEARNING PROHIBITION CLAUSE',
            '',
            'In addition to the rights granted under the applicable license(GPL-3),',
            'you are expressly prohibited from using any form of machine learning,',
            'artificial intelligence, or similar technologies to analyze, process,',
            'or extract information from this software, or to create derivative',
            'works based on this software.',
            '',
            'This prohibition includes, but is not limited to, training machine',
            'learning models, neural networks, or any other automated systems using',
            'the code or output of this software.',
            '',
            'The purpose of this prohibition is to protect the integrity and',
            'intended use of this software. If you wish to use this software for',
            'machine learning or similar purposes, you must seek explicit written',
            'permission from the copyright holder.',
            '',
            'see also',
            '    GPL-3 Licence: https://www.gnu.org/licenses/gpl-3.0.html.en',
            '    Mike Turkey.com: https://miketurkey.com/']
        for mes in meses:
            mes = unicodedata.normalize('NFD', mes)
            print(mes)
        return

    @staticmethod
    def print_namedtuple(t: tuple):
        '''
        recipe 
        class Point(types.NamedTuple):
            x: int = 10
            y: int = 30
        p = Point()
        print_namedtuple(p);
        '''
        k: str
        d: dict = t._asdict()
        for k, v in d.items():
            print('k:', k, 'v:', v)
        return

    @staticmethod
    def calc_fhashdgst(fpath_arg: str, kind_arg: str, nocalc: bool = False,
                       follow_symlinks: bool = False) -> (int, str, str):
        '''
          Calculation file hash digest.
        Arguments
          fpath_arg(type=str): calculation filepath.
          kind_arg(type=str) : Kind of hash digest. The strings is case-insensitive.
            Enable kind_arg value are 'MD5', 'SHA1', 'SHA224', 'SHA256', 'SHA384', 'SHA512'.
        [proceed]
            Enable kind_arg value are 'MD5', 'SHA1', 'SHA2-224', 'SHA2-256', 'SHA2-384', 'SHA2-512'
                              'SHA2-512/224', "SHA2-512/256",
                              "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512");
          nocalc(type=bool): No-calculation. Return imitation hashdigest for debug.
            True : No calcuration.
                dgst prefix-ptn: 1234567890abcedf 
            False: Calculation.
          follow_symlinks(type=bool): Decide to handle when filepath is symbolic link.
            True : Follow symbolic link.
            False: Do not follow symbolic link.
        Return Value: (flag, errmes, hashdgst)
          flag(type=int): 
            True : Success to calculate.
            False: Failure to calculate.
               10: TypeError.  
               11: FileNotFoundError
               15: ValueError. 
               20: OSError
               30: RuntimeError
          errmes(type=str):
            Empty      : Success.
            Some string: Failure.
          hashdgst(type=str):
            Empty      : Failure.
            Some string: Hash digest string ,if success.
        '''
        retry_func = 2
        interval_func = 1   # interval of retrying.
        interval_func_min = 0.1
        interval_func_max = 120
        length_dic = {'MD5': 32, 'SHA1': 40,
                      'SHA224': 56,  'SHA2-224': 56, 'SHA3-224': 56, 'SHA2-512/224': 56, 'SHA512-224': 56,
                      'SHA256': 64,  'SHA2-256': 64, 'SHA3-256': 64, 'SHA2-512/256': 64, 'SHA512-256': 64,
                      'SHA384': 96,  'SHA2-384': 96, 'SHA3-384': 96,
                      'SHA512': 128, 'SHA2-512': 128, 'SHA3-512': 128}
        print_progress = True  # print progress, if 1GB over.
        print_progress_minsize = 1073741824  # min, 1GB
        try:
            kind = kind_arg.upper()
        except:
            errmes = 'kind_arg type is NOT string. [{0}]'.format(
                repr(kind_arg))
            return 10, errmes, ''
        flag, errmes = LPYknife.isbool(nocalc, varname='nocalc')
        if flag != True:
            return flag, errmes, ''
        flag, errmes = LPYknife.isbool(
            follow_symlinks, varname='follow_symlinks')
        if flag != True:
            return flag, errmes, ''
        if len(kind) >= 13:  # most long length = 12, "SHA2-512/256"
            errmes = 'kind_arg strings is too long. [ kind_arg = {0}]'.format(
                kind_arg)
            return 15, errmes, ''
        chklist = [True for s in length_dic.keys() if s == kind]
        if not any(chklist):
            errmes = 'kind_arg string mismatch MD5, SHA1, SHA224, SHA256,' +\
                     ' SHA384, SHA512. [ kind_arg = {0}]'.format(kind_arg)
            return 15, errmes, ''
        if nocalc:
            headptn = '1234567890abcedf'
            tailptn = kind_arg.upper().lstrip('SHAMD')
            return True, '', LPYknife.randomstrings(length_dic[kind], letters=headptn, prefix=headptn, suffix=tailptn)
        if not (interval_func_min <= interval_func <= interval_func_max):
            errmes = 'interval_func value is out of range. ' +\
                     '[min = {0}, max = {1}, interval_func = {2}]'.format(interval_func_min,
                                                                          interval_func_max,
                                                                          interval_func)
            return False, errmes, ''
        fpath = fpath_arg
        if fpath_arg.endswith('\n'):
            warnmes = '\n  Warning: Find \\n charcators of fpath tail in calc_fhashdgst().' +\
                      ' [fpath={0}] '.format(fpath)
            warnings.warn(warnmes)
        i = fpath.find('\n')
        if i > 1:
            errmes = 'Illegal \\n mark in the fpath strings. [fpath = {0}]'.format(
                fpath)
            raise ValueError(errmes)
        fpath = Main_common.unicodenormalized_fpath_exists(fpath_arg)
        if os.path.isfile(fpath) != True:
            errmes = 'fpath is not regular file. [fpath = {0}]'.format(fpath)
            return False, errmes, ''
        if follow_symlinks != True and os.path.islink(fpath) == True:
            errmes = 'fpath is symbolic link. Not regular file. [fpath = {0}]'.format(
                fpath)
            return False, errmes, ''
        loopflag = False
        for i in LPYknife.retry_iter(retry=retry_func, interval=interval_func):
            try:
                fp = open(fpath, 'rb')
            except:
                continue
            else:
                loopflag = True
                break
        if loopflag == False:
            errmes = 'Can not open the file. [fpath = {0}]'.format(fpath)
            raise RuntimeError(errmes)
            return 11, errmes, ''
        if kind == 'MD5':
            s = hashlib.md5()
        elif kind == 'SHA1':
            s = hashlib.sha1()
        elif kind in ['SHA224', 'SHA2-224']:
            s = hashlib.sha224()
        elif kind in ['SHA256', 'SHA2-256']:
            s = hashlib.sha256()
        elif kind in ['SHA384', 'SHA2-384']:
            s = hashlib.sha384()
        elif kind in ['SHA512', 'SHA2-512', 'SHA2-512/224', 'SHA512-224', "SHA2-512/256", "SHA512-256"]:
            s = hashlib.sha512()
        elif kind in ['SHA3-224']:
            s = hashlib.sha3_224()
        elif kind in ['SHA3-256']:
            s = hashlib.sha3_256()
        elif kind in ['SHA3-384']:
            s = hashlib.sha3_384()
        elif kind in ['SHA3-512']:
            s = hashlib.sha3_512()
        else:
            errmes = 'Hash digest kind is unknown. [kind = {0}]'.format(kind)
            return 15, errmes, ''
        filesize = os.path.getsize(fpath)
        largeblock = 20971520  # 20M
        if filesize < largeblock:
            blocksize = 1048576    # 1M
            loopcount = filesize // blocksize
            remainder = filesize % blocksize
        elif filesize >= largeblock:
            loopcount = filesize // largeblock
            remainder = filesize % largeblock
            blocksize = largeblock
        s_origin = s
        loopflag = False
        for i in LPYknife.retry_iter(retry=retry_func, interval=interval_func):
            try:
                s.update(fp.read(remainder))
                for j in range(0, loopcount):
                    buf = fp.read(blocksize)
                    s.update(buf)
                    del buf
                    if print_progress and filesize > print_progress_minsize:  # 1GB over
                        total = loopcount * blocksize + remainder
                        readbyte = j * blocksize + remainder
                        mes = 'Progress: Total: {0}, Percent: {1}, Read: {2}\r'.format(
                            total, readbyte*100//total, readbyte)
                        print(mes, end='', file=sys.stderr)
            except:
                s = s_origin
                fp.seek(0)
                continue
            else:
                loopflag = True
                break
        if loopflag != True:
            errmes = 'file read error. [fpath = {0}]'.format(fpath)
            return 20, errmes, ''
        fp.close()
        while fp.closed != True:
            n = None
            try:
                n = fp.fileno()
            except:
                break   # file closed completely.
            if isinstance(n, int):
                mes = 'Warning: Wait to close file pointer.'
                print(mes, file=sys.stderr)
            time.sleep(1)
        hexdigest = s.hexdigest()
        if kind in ["SHA2-512/224", "SHA512-224"]:
            hexdigest = hexdigest[:56]  # 56 length.
        if kind in ["SHA2-512/256", "SHA512-256"]:
            hexdigest = hexdigest[:64]  # 64 length.
        return True, '', hexdigest

    @staticmethod
    def unicodenormalized_fpath_exists(fpath: str) -> str:
        '''
          fpath normalize NFC, NFD, NFKC, NFKD
          and try to open normalized fpath.
        Return Value: exists fpath(unicode normalized)
        '''
        f: str
        normalized_list: list = [unicodedata.normalize('NFC', fpath),
                                 unicodedata.normalize('NFD', fpath),
                                 unicodedata.normalize('NFKC', fpath),
                                 unicodedata.normalize('NFKD', fpath)]
        for f in normalized_list:
            if os.path.exists(f):
                return f
        return ''


def main_common():
    s: str
    tmpstrs: list[str]
    tmplist: list[typing.Any]
    result_list: list[str]
    if sys.version_info.major == 3 and sys.version_info.minor < 4:
        errmes = 'Error: python 3.4 later. [python: {0}]'.format(
            sys.version.split(' ')[0])
        errmes = unicodedata.normalize('NFD', errmes)
        print(errmes, file=sys.stderr)
        exit(1)
    args = Args_shacksum()
    args.analyze()
    if args.version:
        Main_common.show_version()
        exit(0)
    if args.help:
        Main_common.show_help()
        exit(0)
    if args.license:
        Main_common.show_license()
        exit(0)
    args.checkmethod()
    normargs = args
    normargs.normalize()
    if normargs._checkmode:
        checkmode = Runcheckmode()  # print('Run check mode')
        checkmode.run(normargs)  # Run --check mode.
        exit(0)
    if normargs._calcmode:
        calcmode = Runcalcmode()
        calcmode.run(normargs)
    else:
        errmes = 'Error: Not found check file. [{0}]'.format(normargs.check)
        errmes = unicodedata.normalize('NFD', errmes)
        print(errmes, file=sys.stderr)
        print('Under construction', file=sys.stderr)
        exit(1)
    exit(0)


def main_shacksum():
    main_common()
    return


if __name__ == '__main__':
    main_shacksum()
    exit(0)
