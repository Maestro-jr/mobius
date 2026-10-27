// observe-tls.js: watch how the app sets up TLS, without weakening it.
//
// The question this answers is "does the app pin, and does it verify". It
// reports what it sees at the TrustManager and pinning boundaries; it does not
// disable anything. Bypassing pinning is a separate, named objection job, so
// that "we observed the app's TLS" and "we defeated the app's TLS" are never
// the same action recorded the same way.
//
// One tagged JSON line per event, keys only, never certificate bytes.

'use strict';

function emit(kind, data) {
    send('themob-observe ' + JSON.stringify(Object.assign({ kind: kind }, data)));
}

Java.perform(function () {
    try {
        var TMF = Java.use('javax.net.ssl.TrustManagerFactory');
        TMF.getTrustManagers.implementation = function () {
            var managers = this.getTrustManagers();
            emit('trust-managers', { count: managers.length });
            return managers;
        };
    } catch (e) { emit('error', { at: 'TrustManagerFactory', message: '' + e }); }

    try {
        // OkHttp's CertificatePinner is the common pinning path on Android.
        var Pinner = Java.use('okhttp3.CertificatePinner');
        Pinner.check.overload('java.lang.String', 'java.util.List')
            .implementation = function (host, certs) {
                emit('pin-check', { host: host });
                return this.check(host, certs);
            };
    } catch (e) {
        // Not an error worth reporting: most apps do not bundle OkHttp pinning,
        // and its absence is a finding the static side already makes.
    }

    emit('ready', { hooks: ['TrustManagerFactory', 'okhttp3.CertificatePinner'] });
});
