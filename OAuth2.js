/*
Class:
    df.OAuth2
Extends:
    df.WebObject

This class handles the initial OAuth 2.0 (http://oauth.net - RFC: http://tools.ietf.org/html/rfc6749)
user login and initial consent grant. It opens a new browser window (users may need to turn off pop-up
blockers) with the vendor's OAuth 2.0 url, passing a number of parameters in the query string. It then
waits for the window to be redirected to the redirect url (generally an empty HTML page) and on detecting
that redirection (by examining the URL of the new windows in a timer loop) it parses the URL for data
embedded in the that. If no error is reported and an Authorisation code or access token is returned (and
also if the passed "state" - in this case just the VDF session cookie - is the same as the returned 
"state", to ensure against Cross Site Request Forgery attacks) it will trigger the "LoginDone"
server-side action (which in turn will fire the OnLogin event), otherwise it will trigger the "LoginFail"
server-side action (which in turn will fire the OnLoginFail event).

Most of the action is handled by the vendor's OAuth 2.0 mechanism - we just trigger it and deal with what
it sends us back.
    
Revision:
    2022/05/25  (MJP, UIG)
        Upgrade to do things properly with properties and used the dfcc (DataFlex
        Custom Components) namespace instead of the core df namespace.  Frankly, I've
        leaned a lot more about creating DF custom web controls since 2015! :-)
    2015/07/15  (MJP, UIG) 
        Initial version: 1.0
*/

if (!dfcc) {
    var dfcc = {};
}

dfcc.OAuthParams = [
    {
        sParam : df.tString,
        sValue : df.tString
    }
];

dfcc.OAuth2 = function OAuth2(sName, oParent){
    dfcc.OAuth2.base.constructor.call(this, sName, oParent);

    // The properties we need:
    this.prop(df.tBool,   "wpbLoggedIn",        false);
    this.prop(df.tString, "wpsOAuth2Url",       ""   );
    this.prop(df.tString, "wpsOAuth2LogoutUrl", ""   );
    this.prop(df.tString, "wpsClientIDName",    ""   );
    this.prop(df.tString, "wpsClientID",        ""   );
    this.prop(df.tString, "wpsRedirectUrlName", ""   );
    this.prop(df.tString, "wpsRedirectUrl",     ""   );
    this.prop(df.tString, "wpsLogoutRedirName", ""   );
    this.prop(df.tString, "wpsRespTypeName",    ""   );
    this.prop(df.tString, "wpsResponseType",    ""   );
    this.prop(df.tString, "wpsStateName",       ""   );
    this.prop(df.tInt,    "wpiPollInterval,     500" );
    this.prop(df.tString, "wpsErrorCode",       ""   );
    this.prop(df.tString, "wpsErrorDesc",       ""   );
    this.prop(df.tString, "wpsAuthCode",        ""   );
    this.prop(df.tInt,    "wpiExpiresIn",       0    );
    this.prop(df.tString, "wpsRedirectedTo",    ""   );
    this.prop(df.tString, "wpsRetStateName",    ""   );
    this.prop(df.tString, "wpsErrCodeName",     ""   );
    this.prop(df.tString, "wpsErrDescName",     ""   );
    this.prop(df.tAdv,    "wptGrant",           ""   );
    this.prop(df.tAdv,    "wpatParams",         ""   );

    this.prop(df.tString, "psTest", "");
};

df.defineClass("dfcc.OAuth2", "df.WebObject", {

    deserializeParams: df.sys.vt.generateDeserializer(dfcc.OAuthParams),

    login: function () {
        var state, url, win, open, pollTimer, error, errorDesc, code, retState,
            expires, i, params = "", obj = this, aParams = this.deserializeParams(this.wpatParams);
        
        this.psTest = "bar";
        state = df.sys.cookie.get("dfWebApp");
        
        for (i = 0; i < aParams.length; i++) {
            params += "&" + aParams[i].sParam + "=" + aParams[i].sValue;
        }
        
        open = this.wpsOAuth2Url + '?' + this.wpsClientIDName + '=' + this.wpsClientID + '&' + 
               this.wpsRedirUrlName + '=' + this.wpsRedirectUrl + '&' + 
               this.wpsRespTypeName + '=' + this.wpsResponseType + '&' + 
               this.wpsStateName + '=' + state + params;
                
        win =  window.open(open, "Login Window", 'width=800, height=800'); 
    
        var pollTimer = window.setInterval(function() {
            
            try {
            
                if (win.document.URL.indexOf(obj.wpsRedirectUrl) != -1) {
                    window.clearInterval(pollTimer);
                    url         = win.document.URL;
                    error       = obj.queryValue(url, obj.wpsErrCodeName);
                    errorDesc   = obj.queryValue(url, obj.wpsErrDescName);
                    code        = obj.queryValue(url, obj.wpsAuthCdName);
                    retState    = obj.queryValue(url, obj.wpsRetStateName);
                    expires     = obj.queryValue(url, obj.wpsExpiresName);
                    
                    win.close();
                    obj.set("wpsRedirectedTo", url, false);
                    
                    if (errorDesc !== "" || error !== "" || code === "") {
                        obj.set("wpsAuthCode", "", false);
                        obj.set("wpiExpiresIn", 0, false);
                        obj.set("wpbLoggedIn", false, false);
                        obj.set("wpsErrorCode", error, false);
                        obj.set("wpsErrorDesc", errorDesc, false);
                        obj.serverAction("LoginFail");
                    }
                    else {
                    
                        if (retState !== state) {  // Check that the "state" we passed is the same as we got back
                            obj.set("wpsAuthCode", "", false);
                            obj.set("wpiExpiresIn", 0, false);
                            obj.set("wpbLoggedIn", false, false);
                            obj.set("wpsErrorCode", "CSRF", false);
                            obj.set("wpsErrorDesc", "Returned state does not match passed state: possible attempted Cross Site Request Forgery attack", false);
                            obj.serverAction("LoginFail");
                        }
                        else {
                            obj.set("wpsAuthCode", code, false);
                            obj.set("wpiExpiresIn", expires, false);
                            obj.set("wpbLoggedIn", true, false);
                            obj.set("wpsErrorCode", "", false);
                            obj.set("wpsErrorDesc", "", false);
                            obj.serverAction("LoginDone");
                        }
                        
                    }
                    
                }
                
            } 
            catch(e) {
            }
            
        }, this.wpiPollInterval);
    
    },
    
    logout: function() {
        var open, win, obj = this;
        
        open = this.wpsOAuth2LogoutUrl + '?' + this.wpsLogoutRedirName + '=' + this.wpsRedirectUrl;
        win =  window.open(open, "Logout Window", 'width=800, height=800');

        var pollTimer = window.setInterval(function () {

            try {

                if (win.document.URL.indexOf(obj.wpsRedirectUrl) != -1) {
                    window.clearInterval(pollTimer);
                    url = win.document.URL;

                    win.close();
                    obj.set("wpsRedirectedTo", url, false);
                    obj.set("wpsAuthCode", "", false);
                    obj.set("wpbLoggedIn", false, false);
                    obj.serverAction("LogoutDone");
                }

            }
            catch (e) {
            }

        }, this.wpiPollInterval);

    },

    // Finds and returns the value for the passed "name" in the passed "url" 
    // (or any string, come to that).  I've seen this done with a RegExp, but
    // it didn't always work, so I am doing it the stupid way.
    queryValue: function (url, name) {
        var nameLoc, valLoc, ampLoc, hashloc, value;
        
        nameLoc = url.indexOf(name + "=");
        
        if (nameLoc === -1) {  // "{name}=" not found in the URL
            return "";
        }
        
        valLoc  = nameLoc + name.length + 1; // + 1 for the "=" sign
        ampLoc  = url.indexOf('&', nameLoc);
        hashLoc = url.indexOf('#', nameLoc); // Some services (i.e. Facebook) use this instead of "?" in places
        
        if ((ampLoc === -1) & (hashLoc === -1)) {  // no ampersand or hash found after name position - extract to end
            value = url.substr(valLoc);
        }
        else {                // else extract to ampersand or hash
        
            if (ampLoc !== -1) {
            
                if ((hashLoc !== -1) & (hashLoc < ampLoc)) {
                    value = url.substr(valLoc, (hashLoc - valLoc));
                }
                else {
                    value = url.substr(valLoc, (ampLoc - valLoc));
                }
            }
            else if (hashLoc !== -1) {
                value = url.substr(valLoc, (hashLoc - valLoc));
            }
            
        }
            
        return value;
    }
    
});
