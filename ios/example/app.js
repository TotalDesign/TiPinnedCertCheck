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
