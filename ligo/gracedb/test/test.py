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

import unittest
import random
import os
from datetime import datetime
import time

from ligo.gracedb.rest import GraceDb, GraceDbBasic

# Test the GraceDb REST API class.
#
#  To run:
#
#     python $PATH_TO_GRACEDB_LIB/test/test.py
# 
#  Environment Variables:
#
#     TEST_SERVICE
#       defaults to https://moe.phys.uwm.edu/branson/api/
#       live site would be https://gracedb.ligo.org/api/
#
#     TEST_DATA_DIR
#       defaults to $PATH_TO_GRACEDB_LIB/test/data/
#
#       Files expected:
#
#          burst-cwb.txt
#          cbc-lm2.xml
#          cbc-lm.xml
#          cbc-mbta.gwf
#          upload2.data
#          upload.data
#          upload.data.gz
#
#     X509_USER_PROXY
#
#     X509_USER_CERT
#     X509_USER_KEY


TEST_SERVICE = "https://gracedb-test.ligo.org/api/"
# A sleep time in seconds used to slow down the event creation requests
SLEEP_TIME = 1

class TestGracedb(unittest.TestCase):
    """
        This is as much a test of the REST API on the server
        as it is of the REST client.

        Requires a valid x509 cert in a place that the GraceDb
        class can find it and that the cert DN is accepted by
        the test service.

        This is not a complete set of unit tests,
        but it is a decent start.
    """

    def test_root(self):
        """Did root resource retrieval succeed?"""
        self.assertTrue("CBC" in gracedb.groups)
        pass

    def test_get_events(self):
        """Get the events resource.  Make sure first event looks like an event."""
        events = gracedb.events()
        for event in events:
            self.assertTrue('graceid' in event)
            break

    def test_create_log(self):
        """Create an event log message"""
        message = "Message is {0}".format(random.random())
        resp = gracedb.writeLog(eventId, message)
        self.assertEqual(resp.status, 201)
        new_log_uri = resp.getheader('Location')
        new_log = resp.json()
        self.assertEqual(new_log_uri, new_log['self'])
        check_new_log = gracedb.get(new_log_uri).json()
        self.assertEqual(check_new_log['comment'], message)

    def test_get_log(self):
        """Retrieve event log"""
        logs = gracedb.logs(eventId).json()
        self.assertTrue('numRows' in logs)
        pass

    def test_create_emobservation(self):
        """Create an EM observation entry."""
        comment = "Message is {0}".format(random.random())
        # Let's put in some made-up values
        raList = [1.0,1.0,1.0]
        raWidthList = 1.0
        decList = [1.0,1.0,1.0]
        decWidthList = 1.0
        dt = datetime(1900,1,1,1,1,1)
        startTimeList = [dt.isoformat() for i in range(3)]
        durationList = 1.0
        resp = gracedb.writeEMObservation(eventId, 'Test',
            raList, raWidthList, decList, decWidthList,
            startTimeList, durationList, comment)
        self.assertEqual(resp.status, 201)
        new_emobservation_uri = resp.getheader('Location')
        new_emobservation = resp.json()
        self.assertEqual(new_emobservation_uri, new_emobservation['self'])
        check_new_emobservation = gracedb.get(new_emobservation_uri).json()
        self.assertEqual(check_new_emobservation['comment'], comment)

    def test_get_emobservations(self):
        """Retrieve EM Observation List"""
        emos = gracedb.emobservations(eventId).json()
        self.assertTrue('numRows' in emos)

    def test_upload_large_file(self):
        """Upload a large file.  Issue https://bugs.ligo.org/redmine/issues/951"""

        uploadFile = os.path.join(testdatadir, "big.data")
        r = gracedb.writeFile(eventId, uploadFile)
        self.assertEqual(r.status, 201) # CREATED
        r_content = r.json()
        link = r_content['permalink']
        self.assertEqual(
                open(uploadFile, 'r').read(),
                gracedb.get(gracedb.files(eventId).json()['big.data']).read()
                )
        self.assertEqual(
                open(uploadFile, 'r').read(),
                gracedb.get(link).read()
                )

    def test_upload_file(self):
        """Upload and re-upload a file"""

        uploadFile = os.path.join(testdatadir, "upload.data")
        r = gracedb.writeFile(eventId, uploadFile)
        self.assertEqual(r.status, 201) # CREATED
        r_content = r.json()
        link = r_content['permalink']

        self.assertEqual(
                open(uploadFile, 'r').read(),
                gracedb.get(gracedb.files(eventId).json()['upload.data']).read()
                )

        self.assertEqual(
                open(uploadFile, 'r').read(),
                gracedb.get(link).read()
                )

        # Re-upload slightly different file.
        uploadFile2 = os.path.join(testdatadir, "upload2.data")
        r = gracedb.writeFile(
                eventId,
                filename="upload.data",
                filecontents=open(uploadFile2, 'r'))
        self.assertEqual(r.status, 201) # CREATED
        r_content = r.json()
        link2 = r_content['permalink']

        self.assertEqual(
                open(uploadFile2, 'r').read(),
                gracedb.get(gracedb.files(eventId).json()['upload.data']).read()
                )

        self.assertEqual(
                open(uploadFile2, 'r').read(),
                gracedb.get(link2).read()
                )

        self.assertNotEqual(link, link2)


    def test_files(self):
        """Get file info"""
        r = gracedb.files(eventId)
        event = r.json()
        self.assertEqual(r.status, 200)
        self.assertTrue(isinstance(event, dict))

    def test_label_event(self):
        """Label an event"""
        r = gracedb.writeLabel(eventId, "DQV")
        self.assertEqual(r.status, 201) # CREATED
        r = gracedb.labels(eventId, "DQV")
        self.assertEqual(r.status, 200)
        label = r.json()
        self.assertEqual("DQV", label['name'])

    def test_create_cwb(self):
        """Create a CWB event"""
        """burst-cwb.txt"""
        time.sleep(SLEEP_TIME)
        eventFile = os.path.join(testdatadir, "burst-cwb.txt")
        r = gracedb.createEvent("Test", "CWB", eventFile)
        self.assertEqual(r.status, 201) # CREATED
        cwb_event = r.json()
        self.assertEqual(cwb_event['group'], "Test")
        self.assertEqual(cwb_event['pipeline'], "CWB")
        self.assertEqual(float(cwb_event['gpstime']), 1042312876.5090)

    def test_create_lowmass(self):
        """Create a Low Mass event"""
        """cbc-lm.xml"""
        # This is done with the initially created event.
        pass

    def test_create_mbta(self):
        """Create an MBTA event"""
        """cbc-mbta.xml"""
        time.sleep(SLEEP_TIME)
        eventFile = os.path.join(testdatadir, "cbc-mbta.xml")
        mbta_event = gracedb.createEvent(
                "Test", "MBTAOnline", eventFile).json()
        self.assertEqual(mbta_event['group'], "Test")
        self.assertEqual(mbta_event['pipeline'], "MBTAOnline")
        self.assertEqual(float(mbta_event['gpstime']), 1078903329.421037)
        self.assertEqual(mbta_event['far'], 4.006953918826065e-7)

    def test_create_hardwareinjection(self):
        """Create a HardwareInjection event"""
        """sim-inj.xml"""
        time.sleep(SLEEP_TIME)
        eventFile = os.path.join(testdatadir, "sim-inj.xml")
        hardwareinjection_event = gracedb.createEvent(
                "Test", "HardwareInjection", eventFile,
                instrument="H1", source_channel="",
                destination_channel="").json()
        self.assertEqual(hardwareinjection_event['group'], "Test")
        self.assertEqual(hardwareinjection_event['pipeline'], "HardwareInjection")
        self.assertEqual(hardwareinjection_event['instruments'], "H1")

    def test_replace_event(self):
        time.sleep(SLEEP_TIME)
        graceid = eventId

        old_event = gracedb.event(graceid).json()
        self.assertEqual(old_event['group'], "Test")
        self.assertEqual(old_event['search'], "LowMass")
        self.assertEqual(float(old_event['gpstime']), 971609248.151741)

        replacementFile = os.path.join(testdatadir, "cbc-lm2.xml")

        response = gracedb.replaceEvent(graceid, replacementFile)
        self.assertEqual(response.status, 202)

        new_event = gracedb.event(graceid).json()
        self.assertEqual(new_event['group'], "Test")
        self.assertEqual(new_event['search'], "LowMass")
        self.assertEqual(float(new_event['gpstime']), 971609249.151741)

    def test_upload_binary(self):
        """
        Test workaround for Python bug
        http://bugs.python.org/issue11898
        Raises exception if workaround fails.
        """
        uploadFile = os.path.join(testdatadir, "upload.data.gz")
        r = gracedb.writeFile(eventId, uploadFile)
        self.assertEqual(r.status, 201) # CREATED

    def test_unicode_param(self):
        """
        Test workaround for Python bug
        http://bugs.python.org/issue11898
        Raises exception if workaround fails.
        """
        uploadFile = os.path.join(testdatadir, "upload.data.gz")
        r = gracedb.writeFile(eventId, uploadFile)
        self.assertEqual(r.status, 201) # CREATED

    def test_logger(self):
        import logging
        import ligo.gracedb.rest
        import ligo.gracedb.logging
     
        logging.basicConfig()
        log = logging.getLogger('testing')
        log.propagate = False   # Don't write to console

        #gracedb = ligo.gracedb.rest.GraceDb()
        graceid = eventId
     
        log.addHandler(ligo.gracedb.logging.GraceDbLogHandler(gracedb, graceid))

        message = "Message is {0}".format(random.random())
        log.warn(message)

        event_logs = gracedb.logs(graceid).read()
        self.assertTrue(message in event_logs)

    def test_issue717(self):
        # non-backwards-compatibility of cli.Client import.
        # import and use should not cause an import error.
        from ligo import gracedb
        gracedb.Client
        gracedb.ProxyHTTPConnection
        gracedb.error
        gracedb.ProxyHTTPSConnection

    def test_gittag(self):
        # try to make sure GIT_TAG is set properly.
        import errno
        version = "1.20"
        try:
            # If we are in the source dir (setup.py is available)
            # make sure the version above agrees.
            if os.path.exists("setup.py"):
                setup_file = open("setup.py", 'r')
            else:
                setup_file = open("../../../setup.py", 'r')
            v = ""
            for line in setup_file:
                if line.startswith("version"):
                    v = line.split('"')[1]
                    break
            self.assertEqual(v, version)
        except IOError, e:
            if e.errno != errno.ENOENT:
                raise

        # GIT_TAG should look like "gracedb-VERSION-PKG"
        # and VERSION should == version from above.

        from ligo.gracedb import GIT_TAG as package_tag
        package_tag = package_tag.split('-')[1]
        self.assertTrue(package_tag.startswith(v))

        from ligo.gracedb.cli import GIT_TAG as cli_tag
        cli_tag = cli_tag.split('-')[1]
        self.assertTrue(cli_tag.startswith(v))

        self.assertEqual(cli_tag, package_tag)

if __name__ == "__main__":

    global gracedb, testdatadir, createdEvent, eventId

#   Hacky "global" fixture.
#   Do not want to create a millions events
#   in order to test out event-updating features,
#   which is what a normal test case setUp() would do.

    testdatadir = os.path.join(os.path.dirname(__file__), "data")

    service = os.environ.get('TEST_SERVICE', TEST_SERVICE)
    testdatadir = os.environ.get('TEST_DATA_DIR', testdatadir)

    gracedb = GraceDb(service)
    #gracedb = GraceDbBasic(service)
    print "Using service", service

    eventFile = os.path.join(testdatadir, "cbc-lm.xml")
    createdEvent = gracedb.createEvent(
            "Test", "gstlal", eventFile, "LowMass").json()
    eventId = createdEvent["graceid"]

    unittest.main()
