var forge = require('nl.totalactivemedia.ti.pinnedcertcheck/forge/js/forge'),
	pinnedCerts = [];

exports.setCertificateDir = function(dir) {
	var dir = Titanium.Filesystem.getFile(dir);
	var dirFiles = dir.getDirectoryListing();

	// Read pinned certificates from certificate asset repo
	for (var i = 0; i < dirFiles.length; i++) {
		var file = Ti.Filesystem.getFile(resourcesDir + encodeURIComponent(dirFiles[i])).read();
		if (file) {
			pinnedCerts.push(file.toString().replace(/(?:\r\n|\r|\n)/g, ''));
		}
	}
};

exports.check = function(host, callback) {
	var socket = Ti.Network.Socket.createTCP({
		host: host,
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

	var bufferToString = function(buf){
	    var res = '';
	    for (var idx = 0; idx < buf.length; idx++){
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
			if (_.contains(pinnedCerts, forge.pki.certificateToPem(certs[depth]).replace(/(?:\r\n|\r|\n)/g, ''))) {
				Ti.API.debug(String.format('[TiPinnedCertCheck] tls Certificate verified for %s.', certs[depth].subject.getField('CN').value));
				verified = true;
			}
			else {
				verified = {
					alert: forge.tls.Alert.Description.bad_certificate,
					message: 'Certificates do not match pinned ones.'
				};
			}

			return verified;
		},
		connected: function(connection) {
			Ti.API.debug('[TiPinnedCertCheck] tls connected');
			callback(true);
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
			callback(false, error);
		}
	});

	socket.connect();
};
