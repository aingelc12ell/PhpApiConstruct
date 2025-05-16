A sample API Construct

The handler or receiver is a PHP class that requires a valid token to process requests. The timed token is issued on the login request. The token expires after a set time with option to auto-renew within a specified time window. After expiration, the login request has to be issued again.

This repository also includes a PHP Client that works with the handler from the end user. A sample Javacript implementation is also available.

Feel free to expand as you see fit.
