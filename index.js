
/*
 CAS strategy for Passport.js
 */

(function () {
    var  __hasProp = {}.hasOwnProperty,
        __extends = function (child, parent) {
            for (var key in parent) {
                if (__hasProp.call(parent, key)) child[key] = parent[key];
            }
            function ctor() {
                this.constructor = child;
            }

            ctor.prototype = parent.prototype;
            child.prototype = new ctor();
            child.__super__ = parent.prototype;
            return child;
        };

    var _ = require('lodash');
    var url = require('url');
    var path = require('path');
    var http = require('http');
    var https = require('https');
    var passport = require('passport');
    var xml2json = require('xml2json');

    var Strategy = (function (_super) {

        /*
         options = {
         casServiceUrl : 'https://cas-ip/cas'
         serviceBaseUrl: 'http://localhost:3000/'
         passRequetToCallback: yes/no
         validateUri: '/cas/proxyValidate'
         pgtUrl: 'https://ip/proxyGrantingTicketCallback'
         }
         */
        __extends(Strategy, _super);

        var _DEFAULTS = {
            name: 'cas',
            postRedirect: false,
            validateMethod: 'proxyValidate',
            casServiceUrl: '',
            serviceBaseUrl: 'http://localhost:3000/',
            passRequetToCallback: false,
            pgtUrl: void 0
        };

        var _RESULT = {
            success: false,
            user: null,
            description: '',
            code: '',
            data: {}
        };

        var _VALIDATE_URL = {
            'default': '/validate',
            'validate': '/validate',
            'proxyvalidate': '/proxyValidate',
            'servicevalidate': '/serviceValidate'
        };

        var _validateResponseHandler = function (body) {
            var result, success, user, _ref;
            result = {
                data: body
            };
            _ref = body.split('\n'), success = _ref[0], user = _ref[1];
            result.description = success;
            if (success.toLowerCase() === 'yes') {
                result.user = user;
            }
            return _.extend({}, _RESULT, result);
        };

        var _proxyValidateResponseHandler = function (body) {
            var data, error, result, success;
            result = {
                data: body
            };
            data = xml2json.toJson(body, {
                sanitize: false,
                object: true
            });
            if (data['cas:serviceResponse'] != null) {
                data = data['cas:serviceResponse'];
            }
            if (data['cas:authenticationFailure'] != null) {
                error = data['cas:authenticationFailure'];
                result.data = error;
                result.code = error.code;
                result.description = error['$t'];
            }
            if (data['cas:authenticationSuccess'] != null) {
                success = data['cas:authenticationSuccess'];
                result.data = success;
                result.success = true;
                result.code = 'OK';
                result.user = success['cas:user'];
            }
            return _.extend({}, _RESULT, result);
        };

        var _VALIDATE_RESPONSE_HANDLER = {
            'default': _validateResponseHandler,
            'validate': _validateResponseHandler,
            'proxyvalidate': _proxyValidateResponseHandler,
            'servicevalidate': _proxyValidateResponseHandler
        };

        function Strategy(options, verifyCallback) {
            var verify;
            if (typeof options === 'function') {
                verify = options;
                options = {};
            }
            this.options = _.extend({}, _DEFAULTS, options);
            if (!verifyCallback) {
                throw new Error('CAS authentication strategy requires a verify function');
            }
            this.verifyCallback = verifyCallback;
            this.name = this.options.name;
            this.parsed = url.parse(this.options.casServiceUrl);
            this.client = http;
            if (this.parsed.protocol === 'https:') {
                this.client = https;
            }
            return;
        }

        Strategy.prototype._getResponseHandler = function (validateMethodName) {
            if (validateMethodName == null) {
                validateMethodName = 'default';
            }
            validateMethodName = validateMethodName.toLowerCase();
            if (_VALIDATE_RESPONSE_HANDLER[validateMethodName] != null) {
                return _VALIDATE_RESPONSE_HANDLER[validateMethodName];
            }
            return _VALIDATE_RESPONSE_HANDLER['default'];
        };

        Strategy.prototype._getValidateUrl = function (validateMethodName) {
            if (validateMethodName == null) {
                validateMethodName = 'default';
            }
            validateMethodName = validateMethodName.toLowerCase();
            if (_VALIDATE_URL[validateMethodName] != null) {
                return _VALIDATE_URL[validateMethodName];
            }
            return _VALIDATE_URL['default'];
        };

        Strategy.prototype._onValidateCallback = function (err, user, info) {
            if (err) {
                return this.error(err);
            }
            if (!user) {
                return this.fail(info);
            }
            return this.success(user, info);
        };

        Strategy.prototype.authenticate = function (req, options) {
            var get, parsedURL, query, redirectURL, resolvedURL, service, ticket, validatePath, validateService, validateUrl;
            if (options == null) {
                options = {};
            }
            ticket = req.param('ticket');
            if (!ticket) {
                //redirectURL = url.parse("" + this.options.casServiceUrl + "/login", true);
                redirectURL = url.parse("" + this.options.casServiceUrl, true);
                service = "" + this.options.serviceBaseUrl + req.url;
                redirectURL.query.service = service;
                if (this.options.postRedirect) {
                    redirectURL.query.method = 'POST';
                }
                return this.redirect(url.format(redirectURL));
            }
            resolvedURL = url.resolve(this.options.serviceBaseUrl, req.url);
            parsedURL = url.parse(resolvedURL, true);
            delete parsedURL.query.ticket;
            delete parsedURL.search;
            validateUrl = this._getValidateUrl(this.options.validateMethod);
            validatePath = path.normalize("" + this.parsed.path + validateUrl);
            validateService = url.format(parsedURL);
            query = {
                ticket: ticket,
                service: validateService
            };
            if (this.options.pgtUrl) {
                query.pgtUrl = this.options.pgtUrl;
            }
            get = this.client.get({
                rejectUnauthorized: false,
                requestCert: false,
                agent: false,
                host: this.parsed.hostname,
                port: this.parsed.port,
                path: url.format({
                    query: query,
                    pathname: validatePath
                }),
                headers: {
                    accept: 'application/json'
                }
            }, (function (_this) {
                return function (response) {
                    var body;
                    body = '';
                    response.setEncoding('utf8');
                    response.on('data', function (chunk) {
                        return body += chunk;
                    });
                    return response.on('end', function () {
                        var error, responseHandler, validateResult;
                        validateResult = _RESULT;
                        //responseHandler = _this._getResponseHandler(_this.options.validateMethod);
                        try {
                            console.info("****** response body: " + body);
                            //validateResult = responseHandler(body);
                        } catch (_error) {
                            error = _error;
                            validateResult.code = 'HANDLER_ERROR';
                            validateResult.success = false;
                            validateResult.description = 'HANDLER_ERROR';
                            console.log(error);
                            response.error(new Error("Error during response hander work " + error));
                        }
                        if (_this.options.passReqToCallback) {
                            return _this.verifyCallback(req, validateResult, _this._onValidateCallback.bind(_this));
                        } else {
                            return _this.verifyCallback(validateResult, _this._onValidateCallback.bind(_this));
                        }
                    });
                };
            })(this));

            get.on('error', (function (_this) {
                return function (error) {
                    return _this.fail(new Error(error));
                };
            })(this));
        };

        return Strategy;

    })(passport.Strategy);

    exports.Strategy = Strategy;

}).call(this);
