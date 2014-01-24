node-sshd
=========

An SSH server module for node.js

Based on original code by Daniel Lamando: https://github.com/danopia/sshd.js

This is still a work in progress, and the API will likely see some changes.

More documentation coming; my first attempt was pretty lousy.

###Example:

```js
var sshd = require('./sshd.js');

sshd.settings.privateDSAKeyFile = "/path/to/your/private/dsa_key";
sshd.settings.publicDSAKeyFile = "/path/to/your/public/dsa_key";
sshd.settings.privateRSAKeyFile = "/path/to/your/private/rsa_key";
sshd.settings.publicRSAKeyFile = "/path/to/your/public/rsa_key";
sshd.settings.port = 22;

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

sshd.handlers.session.exec = function(channel, command) {
    var self = this;
    this.write("Your command was " + command + ".\r\n", channel);
    this.sendExitStatus(0, channel);
}

sshd.start();
```