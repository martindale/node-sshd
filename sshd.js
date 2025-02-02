var fs = require('fs'),
	net = require('net'),
	util = require('util'),
	crypto = require('crypto'),
	events = require('events'),
	PacketReader = require('./packetreader'),
	composePacket = require('./packetwriter');

const sshdefs = require('./sshdefs.js');

var hostKey, hostPub, hostDSAKey, hostDSAPub, hostRSAKey, hostRSAPub;

var serverString = "SSH-2.0-sshd.js_0.0.1 Experimental, low-security SSHd implemented in NodeJS";

var settings = {
	'privateRSAKeyFile' : "rsa_host_key",
	'publicRSAKeyFile' : "rsa_host_key.pub",
	'privateDSAKeyFile' : "dsa_host_key",
	'publicDSAKeyFile' : "dsa_host_key.pub",
	'authenticationMethods' : [
		"publickey",
		"keyboard-interactive",
		"password"
	],
	'port' : 22
};

var handlers = {
	'session' : {
		'shell' : false,
		'exec'	: false,
		'subsystem' : false,
		'ptyReq' : false,
		'windowChange' : false
	},
	'authentication' : {
		'keyboardInteractive' : false,
		'publicKey' : false,
		'password' : false
	}
}

var Session = function(conn) {

	var self = this;

	// Some of these probably don't need to be scoped so high
	var	cipher = false,
		cookie,
		conn = conn,
		deciph = false,
		dh,
		e,
		hashIn = [],
		keys = [],
		keyson,
		macC,
		macS,
		macLen = 0,
		seqS = 0,
		seqC = 0,
		session,
		user;

	var	CTSCompressionAlgorithm, // Client-to-server compression algorithm (per compressionAlgorithms, below)
		STCCompressionAlgorithm, // Server-to-client compression algorithm (per compressionAlgorithms, below)
		CTSEncryptionAlgorithm, // Client-to-server encryption algorithm (per encryptionAlgorithms, below)
		STCEncryptionAlgorithm, // Server-to-client encryption algorithm (per encryptionAlgorithms, below)
		CTSMacAlgorithm, // Client-to-server MAC algorithm (per macAlgorithms, below)
		STCMacAlgorithm, // Server-to-client MAC algorithm (per macAlgorithms, below)
		hostKeyAlgorithm, // Server host key algorithm (per hostKeyAlgorithms, below)
		kexAlgorithm; // Key exchange algorithm (per kexAlgorithms, below)

	// Key Exchange Algorithms that this server supports, mapped to crypto()-friendly names
	var kexAlgorithms = {
		'diffie-hellman-group-exchange-sha256' : "SHA256"//,
//		'diffie-hellman-group1-sha1' : "SHA1",
//		'diffie-hellman-group14-sha1'
	};

	// Server host key algorithms that this server supports, mapped to crypto()-friendly names
	var hostKeyAlgorithms = {
		'ssh-rsa' : "RSA-SHA1"//,
//		'ssh-dss' : "DSA-SHA1"
	};

	// Encryption algorithms that this server supports, mapped to crypto()-friendly names
	var encryptionAlgorithms = {
		'aes256-ctr' : "aes-256-ctr",
		'3des-cbc' : "des-ede3-cbc" // I think
	};

	// MAC algorithms that this server supports, mapped to crypto()-friendly names.
	var macAlgorithms = {
		'hmac-md5' : "md5"//,
//		'hmac-sha1' : "sha1"
	};

	// Compression algorithms that this server supports. "none" for now.
	// (Currently used only to generate a list to send to the client during key exchange.)
	var compressionAlgorithms = {
		'none' : "none"
	};

	conn.on(
		'error',
		function (err) {
			console.log('Connection closed due to error.', err);
		}
	);

	conn.on(
		'close',
		function (err) {
			console.log('Connection closed.');
		}
	);

	conn.on(
		'data',
		function(data) {
			if(data.toString('utf-8', 0, 4) === 'SSH-') {
				var eof = data.toString().indexOf('\n');
				console.log('Client header:', data.toString('utf-8', 8, eof-1));
				hashIn.push(data.toString('utf8', 0, eof-1))
				hashIn.push(serverString);
				data = data.slice(eof + 1);
			}
			while(data.length >= 4) {
				var packet = new PacketReader(
					data,
					macLen,
					deciph,
					macC,
					seqC,
					((typeof CTSMacAlgorithm == "undefined") ? "" : macAlgorithms[CTSMacAlgorithm])
				);
				getPacket(packet);
				seqC += 1;
				data = data.slice(packet.totLen);
			}
		}
	);

	crypto.randomBytes(
		16,
		function (err, rand) {
			conn.write(serverString + "\r\n");
			cookie = rand;
			sendPay(
				[	{ byte : sshdefs.SSH_MSG_KEXINIT },
					{ raw : cookie },
					Object.keys(kexAlgorithms),
					Object.keys(hostKeyAlgorithms),
					Object.keys(encryptionAlgorithms),
					Object.keys(encryptionAlgorithms),
					Object.keys(macAlgorithms),
					Object.keys(macAlgorithms),
					Object.keys(compressionAlgorithms),
					Object.keys(compressionAlgorithms),
					[],
					[],
					false,
					{ uint32: 0 }
				]
			);
		}
	);

	var returnFirstMatch = function(obj, arr) {
		for(var a = 0; a < arr.length; a++) {
			if(typeof obj[arr[a]] == "undefined")
				continue;
			return arr[a];
		}
		return false;
	}

	var signBuffer = function(buffer) {
		var signer = crypto.createSign(hostKeyAlgorithms[hostKeyAlgorithm]);
		signer.write(buffer);
		var signature = signer.sign(hostKey);
		return composePacket([hostKeyAlgorithm, signature]);
	}

	var sendPay = function(ast) {
		var payload = composePacket(ast);
		var padLen = (16-((5 + payload.length)%16))+16;
		var buffer = new Buffer(5 + payload.length + padLen);

		buffer.writeUInt32BE(payload.length + 1 + padLen, 0);
		buffer.writeUInt8(padLen, 4);
		payload.copy(buffer, 5);
		buffer.fill(0, 5 + payload.length);

		if(macLen) {
			var asdff = new Buffer(4);
			asdff.writeUInt32BE(seqS, 0);
			var mac = crypto.createHmac(macAlgorithms[STCMacAlgorithm], macS.slice(0, 16)); // TODO: net::ssh key_expander.rb
			mac.write(Buffer.concat([asdff, buffer]))
			mac = new Buffer(mac.digest());
		}

		console.log('>> Type', payload[0], '-', payload.length, 'bytes');
		if(cipher)
			buffer = cipher.update(buffer);
		if(macLen)
			buffer = Buffer.concat([buffer, mac]);
		conn.write(buffer);
		seqS += 1;
	}

	var keyize = function(salt) {
		var sha = crypto.createHash(kexAlgorithms[kexAlgorithm]);
		sha.write(
			Buffer.concat(
				[	composePacket([{ mpint : dh.secret}]),
					new Buffer(session),
					new Buffer(salt),
					new Buffer(session)
				]
			)
		);
		return sha;
	}

	var getPacket = function(packet) {
		var type = packet.getType();
		console.log('<< Type', type, '-', packet.payload.length, 'bytes');

		switch(type) {

			case sshdefs.SSH_MSG_IGNORE:
				break;

			case sshdefs.SSH_MSG_DISCONNECT:
				var code = packet.readUInt32(),
				msg = packet.readString();
				console.log('Client disconnected:', msg, '('+code+')');
				break;

			case sshdefs.SSH_MSG_KEXINIT:
				hashIn.push(packet.payload);
				hashIn.push(
					composePacket(
						[	{ byte : sshdefs.SSH_MSG_KEXINIT },
							{ raw : cookie },
							Object.keys(kexAlgorithms),
							Object.keys(hostKeyAlgorithms),
							Object.keys(encryptionAlgorithms),
							Object.keys(encryptionAlgorithms),
							Object.keys(macAlgorithms),
							Object.keys(macAlgorithms),
							Object.keys(compressionAlgorithms),
							Object.keys(compressionAlgorithms),
							[],
							[],
							false,
							{ uint32: 0 }
						]
					)
				);

				packet.readString(16); // Get rid of the cookie

				kexAlgorithm = returnFirstMatch(kexAlgorithms, packet.readNameList());
				if(typeof kexAlgorithm != "string") {
					self.disconnect(3, "Unable to negotiate KEX algorithm.");
					break;
				}

				hostKeyAlgorithm = returnFirstMatch(hostKeyAlgorithms, packet.readNameList());
				if(typeof hostKeyAlgorithm != "string") {
					self.disconnect(3, "Unable to negotiate server host key algorithm.");
					break;
				}
				if(hostKeyAlgorithm == "ssh-rsa") {
					hostKey = hostRSAKey;
					hostPub = hostRSAPub;
				} else {
					hostKey = hostDSAKey;
					hostPub = hostDSAPub
				}
				hashIn.push(hostPub);

				CTSEncryptionAlgorithm = returnFirstMatch(encryptionAlgorithms, packet.readNameList());
				if(typeof CTSEncryptionAlgorithm != "string") {
					self.disconnect(3, "Unable to negotiate client-to-server encryption algorithm.");
					break;
				}

				STCEncryptionAlgorithm = returnFirstMatch(encryptionAlgorithms, packet.readNameList());
				if(typeof STCEncryptionAlgorithm != "string") {
					self.disconnect(3, "Unable to negotiate server-to-client encryption algorithm.");
					break;
				}

				CTSMacAlgorithm = returnFirstMatch(macAlgorithms, packet.readNameList());
				if(typeof CTSMacAlgorithm != "string") {
					self.disconnect(3, "Unable to negotiate client-to-server MAC algorithm.");
					break;
				}

				STCMacAlgorithm = returnFirstMatch(macAlgorithms, packet.readNameList());
				if(typeof STCMacAlgorithm != "string") {
					self.disconnect(3, "Unable to negotiate server-to-client MAC algorithm.");
					break;
				}

				CTSCompressionAlgorithm = returnFirstMatch(compressionAlgorithms, packet.readNameList());
				if(typeof CTSCompressionAlgorithm != "string") {
					self.disconnect(3, "Unable to negotiate client-to-server compression algorithm.");
					break;
				}

				STCCompressionAlgorithm = returnFirstMatch(compressionAlgorithms, packet.readNameList());
				if(typeof STCCompressionAlgorithm != "string")
					self.disconnect(3, "Unable to negotiate server-to-client compression algorithm.");

				console.log(
					kexAlgorithm,
					hostKeyAlgorithm,
					CTSEncryptionAlgorithm,
					STCEncryptionAlgorithm,
					CTSMacAlgorithm,
					STCMacAlgorithm,
					CTSCompressionAlgorithm,
					STCCompressionAlgorithm
				);
				break;

			case sshdefs.SSH_MSG_KEX_DH_GEX_REQUEST_OLD:
				dhflags = { n : packet.readUInt32() };
				hashIn.push({ uint32 : dhflags.n });
				dh = crypto.getDiffieHellman('modp2');
				hashIn.push({mpint: dh.getPrime()});
				hashIn.push({mpint: new Buffer([2])});
				sendPay(
					[	{ byte : sshdefs.SSH_MSG_KEX_DH_GEX_GROUP },
						{ mpint : dh.getPrime() },
						{ mpint : new Buffer([2]) }
					]
				);
				dh.generateKeys();
				break;

			case sshdefs.SSH_MSG_KEX_DH_GEX_REQUEST:
				dhflags = {
					min: packet.readUInt32(),
					n:   packet.readUInt32(),
					max: packet.readUInt32()
				};
				hashIn.push({ uint32 : dhflags.min });
				hashIn.push({ uint32 : dhflags.n });
				hashIn.push({ uint32 : dhflags.max });
				dh = crypto.getDiffieHellman('modp2');

				// sshdefs.SSH_MSG_KEX_DH_GEX_GROUP
				hashIn.push({ mpint : dh.getPrime() });
				hashIn.push({ mpint : new Buffer([2]) });
				sendPay(
					[	{ byte : sshdefs.SSH_MSG_KEX_DH_GEX_GROUP },
						{ mpint : dh.getPrime() },
						{ mpint : new Buffer([2]) }
					]
				);
				dh.generateKeys();
				break;

			case sshdefs.SSH_MSG_KEX_DH_GEX_INIT:
				e = packet.readMpint();
				dh.secret = dh.computeSecret(e);

				hashIn.push({ mpint : e });
				hashIn.push({ mpint : dh.getPublicKey() });
				hashIn.push({ mpint : dh.secret });

				var sha = crypto.createHash(kexAlgorithms[kexAlgorithm]);
				sha.write(composePacket(hashIn));
				session = sha.digest();
				sendPay(
					[	{ byte : sshdefs.SSH_MSG_KEX_DH_GEX_REPLY },
						hostPub,
						{ mpint : dh.getPublicKey() },
						signBuffer(session)
					]
				);
				break;

			case sshdefs.SSH_MSG_NEWKEYS:
				sendPay([{ byte : sshdefs.SSH_MSG_NEWKEYS }]);
				keyson = true;
				deciph = crypto.createDecipheriv(
					encryptionAlgorithms[CTSEncryptionAlgorithm],
					keyize('C').digest(),
					keyize('A').digest().slice(0,16)
				);
				cipher = crypto.createCipheriv(
					encryptionAlgorithms[STCEncryptionAlgorithm],
					keyize('D').digest(),
					keyize('B').digest().slice(0,16)
				);
				macC = keyize('E').digest();
				macS = keyize('F').digest();
				macLen = 16;
				break;

			case sshdefs.SSH_MSG_SERVICE_REQUEST:
				var service = packet.readString();
				if(service == 'ssh-userauth')
					sendPay([{ byte : sshdefs.SSH_MSG_SERVICE_ACCEPT }, service]);
				else
					sendPay([{ byte : sshdefs.SSH_MSG_DISCONNECT }, {byte: 0}, 'wtf dude']);
				break;

			case sshdefs.SSH_MSG_USERAUTH_REQUEST:
				user = packet.readString();
				var service = packet.readString();
				var method = packet.readString(); // plus more <-- I'll just leave this comment in here until I have reason to figure out what it means.
				if(method == 'none') {
					if(settings.authenticationMethods.indexOf('none') >= 0) {
						sendPay([{ byte : sshdefs.SSH_MSG_USERAUTH_SUCCESS }]);
					} else {
						sendPay(
							[	{ byte : sshdefs.SSH_MSG_USERAUTH_FAILURE },
								settings.authenticationMethods,
								false
							]
						);
					}
				} else if(method == 'keyboard-interactive') {
					var lang = packet.readString();
					var submethods = packet.readString();
					sendPay(
						[	{ byte : sshdefs.SSH_MSG_USERAUTH_INFO_REQUEST },
							"",
							"",
							"",
							{ uint32 : 1 },
							'Password: ',
							false
						]
					);
				} else if(method == 'password') {
					packet.readBool();
					var password = packet.readString();
					if(typeof handlers.authentication.password == "function") {
						handlers.authentication.password.call(
							self,
							{	'username' : user,
								'password' : password
							}
						);
					} else {
						sendPay(
							[	{ byte : sshdefs.SSH_MSG_USERAUTH_FAILURE },
								settings.authenticationMethods,
								false
							]
						);					
					}
				} else if(method == 'publickey') {
					var signed = packet.readBool();
					var key = {
						alg : packet.readString(),
						blob : packet.readString()
					};
					keys.push(key);
					if(!signed) {
						sendPay(
							[	{ byte : sshdefs.SSH_MSG_USERAUTH_PK_OK },
								key.alg,
								key.blob
							]
						);
					} else if(signed && typeof handlers.authentication.publicKey == "function") {
						key.signature = packet.readString();
						handlers.authentication.publicKey.call(
							self,
							{	'username' : user,
								'key' : key
							}
						);
					} else {
						sendPay(
							[	{ byte : sshdefs.SSH_MSG_USERAUTH_FAILURE },
								settings.authenticationMethods,
								false
							]
						);
					}
				} else {
					sendPay(
						[	{ byte : sshdefs.SSH_MSG_USERAUTH_FAILURE },
							settings.authenticationMethods,
							false
						]
					);
				};
				break;

			case sshdefs.SSH_MSG_USERAUTH_INFO_RESPONSE:
				var count = packet.readUInt32();
				var password = packet.readString();
				if(typeof handlers.authentication.keyboardInteractive == "function") {
					handlers.authentication.keyboardInteractive.call(
						self,
						{	'username' : user,
							'password' : password
						}
					);
				} else {
					sendPay(
						[	{ byte : sshdefs.SSH_MSG_USERAUTH_FAILURE },
							settings.authenticationMethods,
							false
						]
					);
				}
				break;

			case sshdefs.SSH_MSG_GLOBAL_REQUEST:
				var type = packet.readString();
				var wantReply = packet.readBool();
				if(type == 'keepalive@openssh.com') {
					sendPay([{ byte : sshdefs.SSH_MSG_REQUEST_SUCCESS }]);
				} else {
					console.log('Global requested', type, 'for but idk');
					if(wantReply)
						sendPay([{ byte : sshdefs.SSH_MSG_REQUEST_FAILURE }]);
				}
				break;

			case sshdefs.SSH_MSG_CHANNEL_OPEN:
				var channel = {
					type : packet.readString(),
					sender : packet.readUInt32(),
					initSize : packet.readUInt32(),
					maxSize : packet.readUInt32()
				}; // plus more <-- I'll just leave this comment in here until I have reason to figure out what it means.

				sendPay(
					[	{ byte : sshdefs.SSH_MSG_CHANNEL_OPEN_CONFIRMATION },
						{ uint32 : channel.sender },
						{ uint32 : channel.sender },
						{ uint32 : channel.initSize },
						{ uint32 : channel.maxSize }
					]
				);
				break;

			case sshdefs.SSH_MSG_CHANNEL_EOF:
				break;

			case sshdefs.SSH_MSG_CHANNEL_CLOSE:
				break;

			case sshdefs.SSH_MSG_CHANNEL_SUCCESS:
				break;

			case sshdefs.SSH_MSG_CHANNEL_REQUEST:
				var recip = packet.readUInt32();
				var type = packet.readString();
				var wantReply = packet.readBool();
				// plus more <-- I'll just leave this comment in here until I have reason to figure out what it means.
				var eventName = "data" + recip;

				if(type == 'shell' && typeof handlers.session.shell == "function") {

					if(wantReply)
						sendPay([{ byte : sshdefs.SSH_MSG_CHANNEL_SUCCESS }, { uint32 : recip }]);

					handlers.session.shell.call(self, recip, eventName);

				} else if(type == 'exec' && typeof handlers.session.exec == "function") {

					if(wantReply)
						sendPay([{ byte : sshdefs.SSH_MSG_CHANNEL_SUCCESS }, { uint32 : recip }]);

					var command = packet.readString();
					handlers.session.exec.call(self, recip, command);

				} else if(type == 'subsystem' && typeof handlers.session.subsystem == "function") {

					if(wantReply)
						sendPay([{ byte : sshdefs.SSH_MSG_CHANNEL_SUCCESS }, { uint32 : recip }]);

					var subsystem = packet.readString();
					handlers.session.subsystem.call(self, recip, eventName, subsystem);

				} else if(type == 'env') {

					console.log('Environment:', packet.readString(), '=', packet.readString());

				} else if(type == 'pty-req' && typeof handlers.session.ptyReq == "function") {

					if(wantReply)
						sendPay([{ byte : sshdefs.SSH_MSG_CHANNEL_SUCCESS }, { uint32 : recip }]);

					var pty = {
						term : packet.readString(),
						widthC : packet.readUInt32(),
						heightC : packet.readUInt32(),
						widthP : packet.readUInt32(),
						heightP : packet.readUInt32(),
						modes : packet.readString()
					};
					handlers.session.ptyReq.call(self, recip, pty);

				} else if(type == 'window-change') {

					if(typeof handlers.session.windowChange == "function") {
						var pty = {
							widthC : packet.readUInt32(),
							heightC : packet.readUInt32(),
							widthP : packet.readUInt32(),
							heightP : packet.readUInt32()
						};
						handlers.session.windowChange.call(self, recip, pty);
					}

				} else if(type == 'signal') {

				} else {

					console.log('Requested', type, 'for', recip, '... but idk');
					if(wantReply) {
						sendPay(
							[	{ byte : sshdefs.SSH_MSG_CHANNEL_FAILURE },
								{ uint32 : recip }
							]
						);
					}

				};
				break;

			case sshdefs.SSH_MSG_CHANNEL_WINDOW_ADJUST:
				break;

			case sshdefs.SSH_MSG_CHANNEL_DATA:
				var channel = packet.readUInt32();
				var data = packet.readString();
				self.emit("data" + channel, data, channel);
				break;

			default:
				console.log(
					'Unimplemented packet',
					type,
					packet.payload,
					packet.payload.toString()
				);
				sendPay(
					[	{ byte : sshdefs.SSH_MSG_UNIMPLEMENTED },
						{ uint32 : recip }
					]
				);
				break;
		};
	}

	this.write = function(payload, channel) { 
		sendPay(
			[	{ byte : sshdefs.SSH_MSG_CHANNEL_DATA },
				{ uint32 : ((typeof channel != "number") ? 0 : channel) },
				payload
			]
		);
	}

	this.sendExitStatus = function(status, channel) {
		sendPay(
			[	{ byte : sshdefs.SSH_MSG_CHANNEL_REQUEST },
				{ uint32 : ((typeof channel != "number") ? 0 : channel) },
				"exit-status",
				false,
				{ uint32 : status }
			]
		);
		sendPay(
			[	{ byte : sshdefs.SSH_MSG_CHANNEL_CLOSE },
				{ uint32 : ((typeof channel != "number") ? 0 : channel) },

			]
		);
	}

	this.disconnect = function(code, reason) {
		sendPay(
			[	{ byte : sshdefs.SSH_MSG_DISCONNECT },
				{ byte : ((typeof code == "number") ? code : 0) },
				((typeof reason == "string") ? reason : ""),
				"en-US"
			]
		);
	}

	this.auth = {
		'success' : function() {
			sendPay([{ byte : sshdefs.SSH_MSG_USERAUTH_SUCCESS }]);
		},
		'failure' : function() {
			sendPay(
				[	{ byte : sshdefs.SSH_MSG_USERAUTH_FAILURE },
					settings.authenticationMethods,
					false
				]
			);
		}
	}

}
util.inherits(Session, events.EventEmitter);

exports.settings = settings;
exports.handlers = handlers;
exports.start = function() {
	hostRSAKey = fs.readFileSync(settings.privateRSAKeyFile).toString();
	hostRSAPub = new Buffer(
		fs.readFileSync(settings.publicRSAKeyFile).toString().split(' ')[1],
		'base64'
	);
	hostDSAKey = fs.readFileSync(settings.privateDSAKeyFile).toString();
	hostDSAPub = new Buffer(
		fs.readFileSync(settings.publicDSAKeyFile).toString().split(' ')[1],
		'base64'
	);
	net.createServer(
		function(conn) {
			console.log('New connection');
			var sess = new Session(conn);
		}
	).listen(settings.port);
}
