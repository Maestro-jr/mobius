// observe-crypto.js: watch the app actually use cryptography.
//
// Static analysis finds a Cipher.getInstance("DES") in the bytecode. This
// watches the app call it at runtime, which is the stronger claim: the code
// path is not just present, it runs. A finding built from this is "we saw it
// happen", which is the most confidence themob can express about a weakness.
//
// It observes and reports. It does not change what the app does: hooking crypto
// to alter it would make the app under test a different app, and the point is
// to describe this one. Every observation is one JSON line on stdout, tagged so
// the adapter can tell them apart from Frida's own chatter.

'use strict';

function emit(kind, data) {
    // One line of JSON per event, prefixed so the reader never has to guess
    // whether a line is ours.
    send('themob-observe ' + JSON.stringify(Object.assign({ kind: kind }, data)));
}

Java.perform(function () {
    try {
        var Cipher = Java.use('javax.crypto.Cipher');
        Cipher.getInstance.overload('java.lang.String').implementation = function (t) {
            emit('cipher', { transformation: t });
            return this.getInstance(t);
        };
    } catch (e) { emit('error', { at: 'Cipher', message: '' + e }); }

    try {
        var MD = Java.use('java.security.MessageDigest');
        MD.getInstance.overload('java.lang.String').implementation = function (a) {
            emit('digest', { algorithm: a });
            return this.getInstance(a);
        };
    } catch (e) { emit('error', { at: 'MessageDigest', message: '' + e }); }

    try {
        var KeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
        KeySpec.$init.overload('[B', 'java.lang.String').implementation =
            function (bytes, algo) {
                // The key bytes are never emitted, only their length and
                // algorithm: this is an assessment tool, not a key logger.
                emit('secret-key', { algorithm: algo, key_length: bytes.length });
                return this.$init(bytes, algo);
            };
    } catch (e) { emit('error', { at: 'SecretKeySpec', message: '' + e }); }

    emit('ready', { hooks: ['Cipher', 'MessageDigest', 'SecretKeySpec'] });
});
