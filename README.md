node-sshd
=========

An SSH server module for node.js

Based on original code by Daniel Lamando: https://github.com/danopia/sshd.js

This is still a work in progress, and the API will likely see some changes.

###Usage

Instantiate with:

```js
var sshd = require('./sshd.js');
```

Your instance ('sshd', in this case) will have the following properties:

* **settings** (object)
* **handlers** (object)

And the following method:

* **start**

####Settings

The 'settings' property has the following sub-properties:

* **privateKeyFile** (string) The path to and name of your server's private key file. (Default: 'rsa_host_key')
* **publicKeyFile** (string) The path to and name of your server's public key file. (Default: 'rsa_host_key.pub')
* **authenticationMethods** (array) An array of strings describing authentication methods that your server will accept, in order of preference. (Default: ["publickey", "keyboard-interactive", "password"].)  You have the option of adding "none" to this array, in which case all clients will immediately be sent an SSH_MSG_USERAUTH_SUCCESS message.  Support for arbitrary authentication methods may be added in the future.

####Handlers

This part of the API will likely see some revision in the future, however the nature of the protocol and of the existing codebase made the current scheme quick and easy to implement.

The 'handlers' property has the following sub-properties:

* **authentication** (object) By default, this has three properties which are all set to 'false': publickey, keyboardInteractive, and password.
* **session** (object) By default, this has four properties which are all set to 'false': shell, exec, subsystem, and pty-req.

#####Authentication Handlers

The handlers.authentication object presently has three properties: publickey, keyboardInteractive, and password.  By default, all of these are set to 'false'.  You must define your own functions here to perform the verification of the user's supplied credentials.

When a client attempts to authenticate, the server checks to see if the authentication handler corresponding to their chosen authentication method has been defined as a function.  If so, that function is called with the appropriate arguments.  If not, the client receives an SSH_MSG_USERAUTH_FAILURE message along with a list of other methods that they can try.

The 'keyboardInteractive' and 'password' handlers will be passed as an argument an object with two properties: 'username' and 'password'.  It's up to your function to verify these credentials.  If the username and password are correct, your function should call 'this.auth.success()' in order to inform the client that authentication was successful.  If the username and password are incorrect, your function should call 'this.auth.failuire().'

There is a bit of work yet to be done on the 'publicKey' handler, so don't use it yet.

#####Session Handlers:

The handlers.session object presently has four properties: shell, exec, subsystem, and pty-req.  By default, all of these are set to 'false'.  You must define your own functions here to deal with sending data to and processing data from the client.

In the scope of your session handler, 'this' refers to a Session object, which has two methods that may be useful in this context:

```js
this.write(data, channel); // Send String or Buffer 'data' to channel 'channel' of this session
this.disconnect(); // Disconnect this session
```

Your session handler will be passed two arguments: 'channel' and 'eventName', where 'channel' is a channel number to be used with 'this.write()' (as above), and 'eventName' is the name of an event that will be emitted when there is new data from the client.

Yes, I know, this is all still a bit clunky. :D

###Example:

```js
var sshd = require('./sshd.js');

sshd.handlers.authentication.password = function(userDetails) {
    if(userDetails.username == "root" && userDetails.password == "toor")
        this.auth.success();
    else
        this.auth.failure();
}

sshd.handlers.authentication.keyboardInteractive = function(userDetails) {
    if(userDetails.username == "root" && userDetails.password == "toor")
        this.auth.success();
    else
        this.auth.failure();
}

sshd.handlers.session.shell = function(channel, eventName) {
    var self = this;
    this.write("Welcome to your crappy shell.\r\n", channel);
    this.on(
        eventName,
        function(data, channel) {
            self.write(data, channel);
        }
    );
}

sshd.start();
```