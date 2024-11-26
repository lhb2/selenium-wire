Selenium Wire v11
=============

forked from wkeeling/selenium-wire
Remove inside mitmproxy from source and import it from pip,so we can use newnest mitmproxy.

Change logs
~~~~~~~~

* Remove inside mitmproxy from source and import it from pip.
* Change proxy default port to 8080.
* Because mitmproxy deleted raw_content,so request.body and response.body have been decoded.
* Websockets has not been tested.
* Drop support for response.cert.


Compatibilty
~~~~~~~~~~~~

* Python 3.10+
* mitmproxy 11.0.0+
* Selenium 4.0.0+
* Chrome, Firefox, Edge and Remote Webdriver supported
