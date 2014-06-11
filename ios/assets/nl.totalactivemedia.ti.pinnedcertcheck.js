var forge = require('nl.totalactivemedia.ti.pinnedcertcheck/forge/js/forge'),
	_pinnedCerts = [],
	_pinnedPubKeys = [];

/**
 * Convert binary buffer in network byte order to UTF-8 string
 *
 * @param {Object} buf
 * @return {String} res
 */
var bufferToString = function(buf) {
    var res = '';
    for (var idx = 0; idx < buf.length; idx++) {
        var b = Ti.Codec.decodeNumber({
            source: buf,
            position: idx,
            type: Ti.Codec.TYPE_BYTE,
            byteOrder: Ti.Codec.BIG_ENDIAN
        });

        if (b < 0) {
        	b = 256 + b;
        }

        res += String.fromCharCode(b);
    }
    return res;
};

var _readDir = function(resourcesDir, registry) {
	var dir = Titanium.Filesystem.getFile(resourcesDir);
	var dirFiles = dir.getDirectoryListing();

	if (dirFiles == null) return;

	// Read pinned public keys from public key asset repo
	for (var i = 0; i < dirFiles.length; i++) {
		var file = Ti.Filesystem.getFile(resourcesDir + encodeURIComponent(dirFiles[i])).read();
		if (file) {
			registry.push(file.toString().replace(/(?:\r\n|\r|\n)/g, ''));
		}
	}
};

exports.setPublicKeyDir = function(resourcesDir) {
	_readDir(resourcesDir, _pinnedPubKeys);
};

exports.setCertificateDir = function(resourcesDir) {
	_readDir(resourcesDir, _pinnedCerts);
};

exports.check = function(options) {
	options = _.extend({
		"host": "",
		"callback": function() {},
		"checks": {
			"certificate": true,
			"pubkey": true
		}
	}, options);

	var socket = Ti.Network.Socket.createTCP({
		host: options.host,
		port: 443,
		connected: function() {
			Ti.API.debug('[TiPinnedCertCheck] socket connected');

			Ti.Stream.pump(socket, pumpCallback, 4096, true);

			// start the handshake process
			client.handshake();
		},
		error: function(e) {
			Ti.API.info(e.error);
		}
	});

	var pumpCallback = function(e) {
		// Has the remote socket closed its end?
	    if (e.bytesProcessed < 0) {
	        Ti.API.debug("[TiPinnedCertCheck] socket closing");
	        socket.close();
	        return;
	    }
	    try {
	        if(e.buffer) {
	        	Ti.API.debug('[TiPinnedCertCheck] Bytes received: ' + e.buffer.getLength());
				client.process(bufferToString(e.buffer));
			}
			else {
	            Ti.API.error('[TiPinnedCertCheck] Error: read callback called with no buffer!');
	        }
	    } catch (ex) {
	        Ti.API.error('[TiPinnedCertCheck] ' + ex);
	    }
	};

	// create TLS client
	var client = forge.tls.createConnection({
		server: false,
		verify: function(connection, verified, depth, certs) {

			// Check certificate validity
			var now = new Date();
			if (now >= certs[depth].validity.notBefore && now <= certs[depth].validity.notAfter) {
				Ti.API.debug(String.format('[TiPinnedCertCheck] tls Certificate for %s is valid.', certs[depth].subject.getField('CN').value));
				verified = true;
			}
			else {
				verified = {
					alert: forge.tls.Alert.Description.bad_certificate,
					message: 'Certificate is no longer valid.'
				};
			}

			// Check certificate
			if (options.checks.certificate) {

				if (_.contains(_pinnedCerts, forge.pki.certificateToPem(certs[depth]).replace(/(?:\r\n|\r|\n)/g, ''))) {
					Ti.API.debug(String.format('[TiPinnedCertCheck] tls Certificate match for %s.', certs[depth].subject.getField('CN').value));
					verified = true;
				}
				else {
					verified = {
						alert: forge.tls.Alert.Description.bad_certificate,
						message: 'Certificate does not match pinned one.'
					};
				}
			}

			// Check public key
			if (options.checks.pubkey) {

				if (_.contains(_pinnedPubKeys, forge.pki.publicKeyToPem(certs[depth].publicKey).replace(/(?:\r\n|\r|\n)/g, ''))) {
					Ti.API.debug(String.format('[TiPinnedCertCheck] tls Public key verified for %s.', certs[depth].subject.getField('CN').value));
					verified = true;
				}
				else {
					verified = {
						alert: forge.tls.Alert.Description.bad_certificate,
						message: 'Certificate public key does not match pinned one.'
					};
				}
			}

			return verified;
		},
		connected: function(connection) {
			Ti.API.debug('[TiPinnedCertCheck] tls connected');
			options.callback(true);
		},
		tlsDataReady: function(connection) {
			var data = connection.tlsData.getBytes();

			// Create buffer
			var buffer = Ti.createBuffer({
				length: data.length
			});

			// Fill buffer
			for(var idx = 0; idx < data.length; idx++) {
				buffer.fill(data.charCodeAt(idx), idx, 1);
			}

			Ti.Stream.write(socket, buffer, function() { Ti.API.info("Written " + buffer.getLength() + " bytes to socket"); });

		},
		dataReady: function(connection) {
			// clear data from the server is ready
			var data = connection.data.getBytes();
			Ti.API.info('[TiPinnedCertCheck] tls data received from the server: ' + data);
		},
		closed: function() {
			Ti.API.debug('[TiPinnedCertCheck] tls disconnected');
		},
		error: function(connection, error) {
			Ti.API.debug('[TiPinnedCertCheck] tls error', error);
			options.callback(false, error);
		}
	});

	socket.connect();
};
