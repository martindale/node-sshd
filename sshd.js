var fs = require('fs'),
	net = require('net'),
	util = require('util'),
	crypto = require('crypto'),
	events = require('events'),
	PacketReader = require('./packetreader'),
	composePacket = require('./packetwriter');

const sshdefs = require('./sshdefs.js');

var hostKey, hostPub;

var settings = {
	'privateKeyFile' : "rsa_host_key",
	'publicKeyFile' : "rsa_host_key.pub",
	'authenticationMethods' : [
		"publickey",
		"keyboard-interactive",
		"password"
	]
};

var handlers = {
	'session' : {
		'shell' : false,
		'exec'	: false,
		'subsystem' : false,
		'ptyReq' : false
	},
	'authentication' : {
		'keyboardInteractive' : false,
		'publicKey' : false,
		'password' : false
	}
}

var Session = function(conn) {

	var self = this;

	var cipher, cookie, deciph, dh, e, keyson, macC, macS, session, user;

	var macLen = 0;
	var seqS = 0;
	var seqC = 0;
	var hashIn = [];
	var keys = [];
	var conn = conn;

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
				hashIn.push('SSH-2.0-sshd.js_0.0.1 Experimental, low-security SSHd implemented in NodeJS');
				data = data.slice(eof + 1);
			}
			while(data.length >= 4) {
				var packet = new PacketReader(data, macLen, deciph, macC, seqC);
				getPacket(packet);
				seqC += 1;
				data = data.slice(packet.totLen);
			}
		}
	);

	crypto.randomBytes(
		16,
		function (err, rand) {
			conn.write('SSH-2.0-sshd.js_0.0.1 Experimental, low-security SSHd implemented in NodeJS\r\n');
			cookie = rand;
			sendPay(
				[	{ byte : sshdefs.SSH_MSG_KEXINIT },
					{ raw : cookie },
					['diffie-hellman-group-exchange-sha256'],
					['ssh-rsa'],
					['aes256-ctr'],
					['aes256-ctr'],
					['hmac-md5'],
					['hmac-md5'],
					['none'],
					['none'],
					[],
					[],
					false,
					{ uint32: 0 }
				]
			);
		}
	);

	var signBuffer = function(buffer) {
		var signer = crypto.createSign('RSA-SHA1');
		signer.write(buffer);
		var signature = signer.sign(hostKey);
		return composePacket(['ssh-rsa', signature]);
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
			var mac = crypto.createHmac('md5', macS.slice(0, 16)); // TODO: net::ssh key_expander.rb
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
		var sha = crypto.createHash('SHA256');
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
							['diffie-hellman-group-exchange-sha256'],
							['ssh-rsa'],
							['aes256-ctr'],
							['aes256-ctr'],
							['hmac-md5'],
							['hmac-md5'],
							['none'],
							['none'],
							[],
							[],
							false,
							{ uint32: 0 }
						]
					)
				);
				hashIn.push(hostPub);
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

				var sha = crypto.createHash('sha256');
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
					'aes-256-ctr',
					keyize('C').digest(),
					keyize('A').digest().slice(0,16)
				);
				cipher = crypto.createCipheriv(
					'aes-256-ctr',
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
							"en-US",
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
					if(typeof handlers.authentication.publickey == "function") {
						handlers.authentication.publickey.call(
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

	this.disconnect = function() {
		sendPay(
			[	{ byte : sshdefs.SSH_MSG_DISCONNECT },
				{ byte : 0 },
				"",
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
	hostKey = fs.readFileSync(settings.privateKeyFile).toString();
	hostPub = new Buffer(
		fs.readFileSync(settings.publicKeyFile).toString().split(' ')[1],
		'base64'
	);
	net.createServer(
		function(conn) {
			console.log('New connection');
			var sess = new Session(conn);
		}
	).listen(3000);
}
