var Defs = {

	SSH_MSG_DISCONNECT : 1,
	SSH_MSG_IGNORE : 2,
	SSH_MSG_UNIMPLEMENTED : 3,
	SSH_MSG_DEBUG : 4,
	SSH_MSG_SERVICE_REQUEST : 5,
	SSH_MSG_SERVICE_ACCEPT : 6,
	SSH_MSG_KEXINIT : 20,
	SSH_MSG_NEWKEYS : 21,
	SSH_MSG_KEX_DH_GEX_REQUEST_OLD : 30,
	SSH_MSG_KEX_DH_GEX_GROUP : 31,
	SSH_MSG_KEX_DH_GEX_INIT : 32,
	SSH_MSG_KEX_DH_GEX_REPLY : 33,
	SSH_MSG_KEX_DH_GEX_REQUEST : 34,
	SSH_MSG_USERAUTH_REQUEST : 50,
	SSH_MSG_USERAUTH_FAILURE : 51,
	SSH_MSG_USERAUTH_SUCCESS : 52,
	SSH_MSG_USERAUTH_BANNER : 53,
	SSH_MSG_USERAUTH_PK_OK : 60,
	SSH_MSG_USERAUTH_PASSWD_CHANGEREQ : 60,
	SSH_MSG_USERAUTH_INFO_REQUEST : 60,
	SSH_MSG_USERAUTH_INFO_RESPONSE : 61,
	SSH_MSG_GLOBAL_REQUEST : 80,
	SSH_MSG_REQUEST_SUCCESS : 81,
	SSH_MSG_REQUEST_FAILURE : 82,
	SSH_MSG_CHANNEL_OPEN : 90,
	SSH_MSG_CHANNEL_OPEN_CONFIRMATION : 91,
	SSH_MSG_CHANNEL_OPEN_FAILURE : 92,
	SSH_MSG_CHANNEL_WINDOW_ADJUST : 93,
	SSH_MSG_CHANNEL_DATA : 94,
	SSH_MSG_CHANNEL_EXTENDED_DATA : 95,
	SSH_MSG_CHANNEL_EOF : 96,
	SSH_MSG_CHANNEL_CLOSE : 97,
	SSH_MSG_CHANNEL_REQUEST : 98,
	SSH_MSG_CHANNEL_SUCCESS : 99,
	SSH_MSG_CHANNEL_FAILURE : 100,

	SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT : 1,
	SSH_DISCONNECT_PROTOCOL_ERROR : 2,
	SSH_DISCONNECT_KEY_EXCHANGE_FAILED : 3,
	SSH_DISCONNECT_RESERVED : 4,
	SSH_DISCONNECT_MAC_ERROR : 5,
	SSH_DISCONNECT_COMPRESSION_ERROR : 6,
	SSH_DISCONNECT_SERVICE_NOT_AVAILABLE : 7,
	SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED : 8,
	SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE : 9,
	SSH_DISCONNECT_CONNECTION_LOST : 10,
	SSH_DISCONNECT_BY_APPLICATION : 11,
	SSH_DISCONNECT_TOO_MANY_CONNECTIONS : 12,
	SSH_DISCONNECT_AUTH_CANCELLED_BY_USER : 13,
	SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE : 14,
	SSH_DISCONNECT_ILLEGAL_USER_NAME : 15,

	SSH_OPEN_ADMINISTRATIVELY_PROHIBITED : 1,
	SSH_OPEN_CONNECT_FAILED : 2,
	SSH_OPEN_UNKNOWN_CHANNEL_TYPE : 3,
	SSH_OPEN_RESOURCE_SHORTAGE : 4,

	SSH_EXTENDED_DATA_STDERR : 1,

	TTY_OP_END : 0,
	VINTR : 1,
	VQUIT : 2,
	VERASE : 3,
	VKILL : 4,
	VEOF : 5,
	VEOL : 6,
	VEOL2 : 7,
	VSTART : 8,
	VSTOP : 9,
	VSUSP : 10,
	VDSUSP : 11,
	VREPRINT : 12,
	VWERASE : 13,
	VLNEXT : 14,
	VFLUSH : 15,
	VSWTCH : 16,
	VSTATUS : 17,
	VDISCARD : 18,
	IGNPAR : 30,
	PARMRK : 31,
	INPCK : 32,
	ISTRIP : 33,
	INLCR : 34,
	IGNCR : 35,
	ICRNL : 36,
	IUCLC : 37,
	IXON : 38,
	IXANY : 39,
	IXOFF : 40,
	IMAXBEL : 41,
	ISIG : 50,
	ICANON : 51,
	XCASE : 52,
	ECHO : 53,
	ECHOE : 54,
	ECHOK : 55,
	ECHONL : 56,
	NOFLSH : 57,
	TOSTOP : 58,
	IEXTEN : 59,
	ECHOCTL : 60,
	ECHOKE : 61,
	PENDIN : 62,
	OPOST : 70,
	OLCUC : 71,
	ONLCR : 72,
	OCRNL : 73,
	ONOCR : 74,
	ONLRET : 75,
	CS7 : 90,
	CS8 : 91,
	PARENB : 92,
	PARODD : 93,
	TTY_OP_ISPEED : 128,
	TTY_OP_OSPEED : 129
	
}

module.exports = Defs;