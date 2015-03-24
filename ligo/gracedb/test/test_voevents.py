import nose
from ligo.gracedb.rest import GraceDb, HTTPError
from nose.tools import assert_true, assert_equal
import sys, os
import json
import voeventparse
import StringIO
from optparse import OptionParser
import logging

#--------------------------------------------------------------------------------
#--------------------------------------------------------------------------------
# Options
#--------------------------------------------------------------------------------
#--------------------------------------------------------------------------------

op = OptionParser()

op.add_option("-s", "--service-url", dest="test_service",
                help="Test Service URL", metavar="URL",
                default = "https://moe.phys.uwm.edu/branson/api/")
op.add_option("-f", "--logfile", dest="logfile",
                help="filename for logging output", 
                metavar="NAME", default=None)
op.add_option("-d", "--datafile", dest="datafile",
                help="coinc xml file for creating a test event", 
                metavar="NAME", default="cbc-lm.xml")
op.add_option("-i", "--testdatadir", dest="test_data_dir",
                help="the directory containing test data", 
                metavar="NAME", default=os.path.join(os.path.dirname(__file__), "data"))
op.add_option("-v", "--verbose", dest="verbose",
                help="verbose output to logging file",
                action="store_true", default=False)

opts, args = op.parse_args()

if opts.verbose and not opts.logfile:
    raise ValueError, "A logfile must be specified if verbose output is desired."

#--------------------------------------------------------------------------------
#--------------------------------------------------------------------------------
# Setup logging
#--------------------------------------------------------------------------------
#--------------------------------------------------------------------------------

logger = logging.getLogger(__name__)
if opts.verbose:
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.INFO)

formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')

if opts.logfile:
    fh = logging.FileHandler(opts.logfile)
else:
    fh = logging.FileHandler(os.devnull)
fh.setFormatter(formatter)
logger.addHandler(fh)

#--------------------------------------------------------------------------------
#--------------------------------------------------------------------------------
# Main
#--------------------------------------------------------------------------------
#--------------------------------------------------------------------------------

service = opts.test_service
datafile = os.path.join(opts.test_data_dir, opts.datafile)

# Module level global variables
g = GraceDb(service)

# Variables to which we will need access at the module level
event = None
graceid = None
update_voevent = None
retraction_voevent = None
preliminary_voevent = None
preliminary_voevent_text = None

# Utility for getting out a dictionary of ivorns and citation types
def get_citations_dict(v):
    citations_dict = {}
    for e in v.Citations.iterchildren():
        logger.debug("Got tag, value: %s, %s" % (e.tag, e.text))
        if e.tag == 'EventIVORN':
            ivorn = e.text
            citation_type = e.attrib['cite']
            citations_dict[ivorn] = citation_type
    return citations_dict

def setup_module():
    global graceid
    r = g.createEvent("Test", "gstlal", datafile, "LowMass")
    event = r.json()
    graceid = event['graceid']
    logger.info("created event %s\n" % graceid)
    # Upload fake skymap file to use later
    # XXX May want some more error handling.
    r = g.writeLog(graceid, "Fake skymap file.", filename = "fake_skymap.txt",
        filecontents = "Fake skymap.", tagname = "sky_loc")
    r = g.writeLog(graceid, "Fake skymap image file.", filename = "fake_skymap_image.txt",
        filecontents = "Fake skymap image.", tagname = "sky_loc")
    logger.debug("successfully wrote log\n")

def test_create_preliminary_voevent():
    global preliminary_voevent
    global preliminary_voevent_text
    logger.debug("inside test prelim, graceid  = %s\n" % graceid)
    try:
        r = g.createVOEvent(graceid, "Preliminary")
        rdict = r.json()
        assert_true('voevent_type' in rdict.keys())
        logger.debug('got preliminary voevent text = %s\n' % rdict['text'])
        preliminary_voevent_text = rdict['text']
        preliminary_voevent = voeventparse.load(StringIO.StringIO(rdict['text']))
    except HTTPError, e:
        outfile = open('tmp.html', 'w')
        outfile.write(str(e))
        outfile.close()

def test_retrieve_voevent():
    r = g.voevents(graceid)
    voevent_list = r.json()['voevents']
    voevent_list = [v['text'] for v in voevent_list]
    assert_true(len(voevent_list) == 1 and preliminary_voevent_text in voevent_list)

def test_create_update_voevent():
    global update_voevent
    r = g.createVOEvent(graceid, "Update", skymap_filename = "fake_skymap.txt",
        skymap_type = "FAKE", skymap_image_filename = "fake_skymap_image.txt")
    rdict = r.json()
    logger.debug("got update text = %s\n"  % rdict['text'])
    assert_true('voevent_type' in rdict.keys())
    update_voevent = voeventparse.load(StringIO.StringIO(rdict['text']))

def test_ivorns_unique():
    preliminary_ivorn = preliminary_voevent.attrib['ivorn']
    logger.info("preliminary ivorn = %s\n" % preliminary_ivorn)
    update_ivorn = update_voevent.attrib['ivorn']
    logger.info("update ivorn = %s\n" % update_ivorn)
    assert_true(update_ivorn != preliminary_ivorn)

def test_citation_section():
    update_citations = get_citations_dict(update_voevent)
    preliminary_ivorn = preliminary_voevent.attrib['ivorn']
    assert_equal(update_citations[preliminary_ivorn], 'supersedes')

def test_create_retraction_voevent():
    global retraction_voevent
    r = g.createVOEvent(graceid, "Retraction")
    rdict = r.json()
    assert_true('voevent_type' in rdict.keys())
    logger.debug("got retraction text = %s" % rdict['text'])
    retraction_voevent = voeventparse.load(StringIO.StringIO(rdict['text']))

def test_retraction_citations():
    # Parse retraction voevent and check for correct citations
    retraction_citations = get_citations_dict(retraction_voevent)
    preliminary_ivorn = preliminary_voevent.attrib['ivorn']
    update_ivorn = update_voevent.attrib['ivorn']
    cond = retraction_citations[preliminary_ivorn] == 'retraction' 
    cond = cond and retraction_citations[update_ivorn] == 'retraction'
    assert_true(cond)

nose.runmodule()

