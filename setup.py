# -*- coding: utf-8 -*-
# Copyright (C) Brian Moe, Branson Stephens (2015)
#
# This file is part of gracedb
#
# gracedb is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# It is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with gracedb.  If not, see <http://www.gnu.org/licenses/>.

import os

from setuptools import setup

version = "1.20"

setup(
  name = "ligo-gracedb",
  version = version,
  maintainer = "Branson Stephens",
  maintainer_email = "branson.stephens@ligo.org",
  description = "Gravitational Wave Candidate Event Database",
  long_description = "The gravitational wave candidate event database (GraceDB) is a system to organize candidate events from gravitational wave searches and to provide an environment to record information about follow-ups. A simple client tool is provided to submit a candidate event to the database.",

  url = "http://www.lsc-group.phys.uwm.edu/daswg/gracedb.html",
  license = 'GPL',
  namespace_packages = ['ligo'],
  provides = ['ligo.gracedb'],
  packages = ['ligo.gracedb', 'ligo.gracedb.test'],

  requires = ['M2Crypto'],

  package_data = { 'ligo.gracedb.test' : ['data/*', 'test.sh', 'README'] },

  scripts = [
    os.path.join('bin','gracedb'),
  ],

)
