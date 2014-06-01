# TiPinnedCertCheck

Check certificate validity based on a list of pinned certificates and/or public keys. The certificates and public keys must be in PEM format.

## Retrieve Certificates and Public Keys

The included bash scripts can help retrieving certificates and private keys. In order to retrieve the certificate chain for `storage.googleapis.com` in PEM format use:

	./retrieve-cert.sh storage.googleapis.com 443

Then to extract their public keys in PEM format run:

	./retrieve-pubkey.sh
	
The certificates and public keys can be stored in your Titanium project's asset directory. For example in the respective `certificates` or `pubkeys` subdirectories.

	var certCheck = require('nl.totalactivemedia.ti.pinnedcertcheck');
	certCheck.setCertificateDir( Ti.Filesystem.getResourcesDirectory() + "certificates/" );
	certCheck.setPublicKeyDir( Ti.Filesystem.getResourcesDirectory() + "pubkeys/" );

	certCheck.check({
		"host": 'storage.googleapis.com',
	    "callback": function(success, error) {
	    	alert(success ? "Checks passed!" : "Checks failed!");
    	},
	    "checks": {
    		"certificate": true,
    		"pubkey": true
	    }
	});

## Digital Bazaar Forge

This module is based on Digital Bazaar's Forge. A native implementation of TLS in JavaScript.

[https://github.com/digitalbazaar/forge](https://github.com/digitalbazaar/forge)

