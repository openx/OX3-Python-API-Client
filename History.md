
0.6.1 / 2019-07-23
=================
  * Add ODS endpoint to supported endpoint list

0.6.0 / 2017-06-19
==================
 * Added: Python 3 compatibility
 * Fixed: Non running tests

0.5.2 / 2017-02-02
==================
 * Fixed: packaging for Pypi
 * Added: license information

0.5.0 / 2015-07-26
==================
 * Replaced: urllib2 with requests package
 * Replaced: oauth2 with requests_oauthlib package
 * Added: optional timeout parameter
 * Removed: support for Python 2.4/2.5

0.4.0 / 2013-07-23
==================
 * Added handling for API v2
 * Refined docstrings throughout code

0.3.1 / 2013-06-04
==================
 * Removed: Realm Support
 * Realm can still be given, but has no effect
 * Fixed: Unicode encoding error in REST POSTing

0.3.0 / 2013-03-18
==================
 * Added: HTTP and HTTPS proxy support.
 * Fixed: JSON support for Python 2.4 and 2.5
 * Fixed: OAuth support for Python 2.4
 * Fixed: Version number below (0.2.1)
 

0.2.1 / 2012-09-25
==================
  # Added: `upload_creative` to support uploading creative files.

0.2.0 / 2012-08-29
==================

  * Fixed: JSON parse error when deleting objects with call to `Client.delete()`
  * Added: "Official" support for Python 2.4, 2.5, 2.6
  * Added: `logon` and `logoff` convenience methods.
  * Added: `client_from_file` to load credentials from a config file.
  * `OX3APIClient` is deprecated; use `Client` instead.

0.1.0 / 2012-08-26
==================

  * "Official release"
