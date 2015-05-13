
import os

from distutils.core import setup

version = "1.18.dev1"

setup(
  name = "ligo-gracedb",
  version = version,
  maintainer = "Branson Stephens",
  maintainer_email = "branson.stephens@ligo.org",
  description = "Gravitational Wave Candidate Event Database",
  long_description = "The gravitational wave candidate event database (GraceDB) is a system to organize candidate events from gravitational wave searches and to provide an environment to record information about follow-ups. A simple client tool is provided to submit a candidate event to the database.",

  url = "http://www.lsc-group.phys.uwm.edu/daswg/gracedb.html",
  license = 'GPL',
  provides = ['ligo.gracedb'],
  packages = [ 'ligo.gracedb', 'ligo.gracedb.test'],
  namespace_packages = ['ligo'],
  package_data = { 'ligo.gracedb.test' : ['data/*', 'test.sh', 'README'] },

  requires = ['M2Crypto'],

  scripts = [
    os.path.join('bin','gracedb'),
  ],

)
