from burp import IBurpExtender
from burp import IHttpListener
from burp import ITab
import urllib2, json, base64, time, datetime
from urllib import quote_plus
from collections import OrderedDict
from threading import Lock, Thread
from javax import swing
from javax.swing import (JSplitPane, JTabbedPane, JPanel, JLabel, JSeparator, JScrollPane, JTextArea, JTextField, JComboBox, JButton, JCheckBox, GroupLayout, LayoutStyle, SwingConstants)
from javax.swing.text import DefaultCaret
from java.lang import Short
from java.awt import Dimension
from java.lang import Exception

class BurpExtender(IBurpExtender, ITab, IHttpListener):

    #
    # Implement IBurpExtender
    #
    
    # Add 'global' variables
    logLock = Lock()
    tokenLock = Lock()
    requestLock = Lock()
    currentToken = ["", ""]
    expiresIn = [time.time()]
    activated = False
    debugMode = False
    scope = []
    tokenUrl = ""
    debugRequest = "\n------------------------------------------ DEBUG REQUEST ------------------------------------------\n%s\n----------------------------------------------------------------------------------------------------------"
    debugResponse = "\n------------------------------------------ DEBUG RESPONSE -----------------------------------------\n%s\n----------------------------------------------------------------------------------------------------------"
    
    ################################################
    # BURP EXTENDER FUNCTIONS
    ################################################
    
    #
    # Register Extender Callbacks
    #
    def	registerExtenderCallbacks(self, callbacks):
        
        # Obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        self.callbacks = callbacks
        
        # Set our extension name
        callbacks.setExtensionName("OAuth2 Token Grabber")
        
        # Register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)
        
        # Init UI
        self.initUI()
        
        # Add tab
        callbacks.addSuiteTab(self)
        
        print """-- OAuth2 Token Grabber v1.0 --
Grabs OAuth2 access tokens and adds them to requests as custom headers.

Currently supported auth flows:
    - Client Credentials
    - Password Credentials
    - Resource Owner Password Credentials (ROPC)"""

        return
     
    #
    # Return UI component
    #
    def getUiComponent(self):
        return self.tabbedPane
    
    #
    # Return caption
    #
    def getTabCaption(self):
        return "OAuth2 Token Grabber"
    
    #
    # Listen for and process requests
    #
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        
        # Only process requests
        if messageIsRequest:
            
            # Check if activated
            if not self.activated:
                return
            
            # Check in scope
            if toolFlag not in self.scope:
                return
            
            # Check if token request from self
            if str(self._helpers.analyzeRequest(messageInfo).getUrl()) == self.tokenUrl:
                return
            
            # Process requests sequentially to avoid concurrent token requests
            with self.requestLock:
                
                # Exit nicely if deactivated
                if self.activated == False:
                    return
                
                with self.tokenLock:
                    
                    # Add current token to request
                    messageInfo = self.setToken(messageInfo)
                
                # Analyse request
                requestInfo = self._helpers.analyzeRequest(messageInfo)
                
                # Get request headers
                headers = requestInfo.getHeaders()
                
                # Check if current token expired
                expired = self.checkExpired(headers)
                
                if self.debugMode:
                    self.writeLog(self.debugRequest % (self._helpers.bytesToString(messageInfo.getRequest())))
                
                if expired:
                    
                    self.writeLog("Token expired.")
                    
                    # Get request body
                    reqBody = messageInfo.getRequest()[requestInfo.getBodyOffset():]
                    
                    # Remove expired header
                    headerToDelete = ''
                    for header in headers:
                        if self.txtCustomHeader.text in header:
                            headerToDelete = header
                            break
                    try:
                        headers.remove(headerToDelete)
                    except:
                        pass
                    
                    # Make token request
                    try:
                        
                        # Check parameters
                        grantType = self.checkParameters(self.cmbGrantType.getSelectedItem())
                        
                        # If parameters ok
                        if grantType != False:
                            
                            while True:
                                
                                # Check if activated
                                if self.activated == False:
                                    return
                                
                                self.writeLog("Requesting new token...")
                                
                                # Init TokenRequest
                                tokenRequest = self.TokenRequest(self.debugMode, self.debugRequest, self.debugResponse, self.callbacks, self._helpers, self.txtLog, self.logLock, self.currentToken, self.tokenLock, self.expiresIn, grantType, self.cmbClientAuth.getSelectedItem(), self.txtTokenURL.text, self.txtPort.text, self.cmbProtocol.getSelectedItem().split(":")[0], self.cmbHttpVersion.getSelectedItem().split(":")[0], self.txtUsername.text, self.txtPassword.text, self.txtClientID.text, self.txtClientSecret.text, self.txtScope.text)
                                
                                # New thread
                                t = Thread(target=tokenRequest.go, args=[])
                                t.daemon = True
                                t.start()
                                t.join()
                            
                                # Check no request error
                                if self.currentToken[1] != "error":
                                    break
                                
                                # Otherwise retry indefinitely
                                self.writeLog("Waiting 5 seconds...")
                                time.sleep(5)
                        
                        else:
                            self.writeLog("Something went wrong!")
                            return
                        
                        # Add new token to headers
                        with self.tokenLock:
                            headers.add(self.txtCustomHeader.text + ' ' + self.currentToken[0])
                            
                        # Build message
                        message = self._helpers.buildHttpMessage(headers, reqBody)
                        messageInfo.setRequest(message)
                        
                        self.writeLog("Token updated!")
                        
                        if self.debugMode:
                            self.writeLog(self.debugRequest % (self._helpers.bytesToString(messageInfo.getRequest())))
                        
                    except Exception as e:
                        print str(e)
                        self.writeLog("Failed. See Extender output for details.")
                else:
                    return
    
    ################################################
    # CLASSES
    ################################################
    
    #
    # Token Request class
    #
    class TokenRequest:
        
        # Init
        def __init__(self, debugMode, debugRequest, debugResponse, callbacks, helpers, txtLog, logLock, currentToken, tokenLock, expireIn, grantType, clientAuth, tokenURL, port, protocol, httpVersion, username, password, clientID, clientSecret, scope):
            self.debugMode = debugMode
            self.debugRequest = debugRequest
            self.debugResponse = debugResponse
            self.callbacks = callbacks
            self._helpers = helpers
            self.txtLog = txtLog
            self.logLock = logLock
            self.currentToken = currentToken
            self.tokenLock = tokenLock
            self.expireIn = expireIn
            self.grantType = grantType
            self.clientAuth = clientAuth
            self.host = tokenURL.split("/")[0]
            self.path = tokenURL.replace(tokenURL.split("/")[0], "")
            self.port = port
            self.protocol = protocol
            self.httpVersion = httpVersion
            self.username = username
            self.password = password
            self.clientID = clientID
            self.clientSecret = clientSecret
            self.scope = scope
        
        # Thread safe write to log
        def writeLog(self, message):
            
            with self.logLock:
                
                # Get timestamp
                now = datetime.datetime.now()
                
                # Write to log
                self.txtLog.text += "[" + now.strftime("%H:%M:%S") + "] " + message + "\n"
                return
        
        #
        # Recursively search for and extract first token value from JSON
        #
        def findToken(self, v, k):
            for k1 in v:
                if k in k1.lower():
                    if type(v[k1]) != type(v):
                        return v[k1]
                    return self.findToken(v[k1], k)
                
        # Make request
        def go(self):
            
            # If Basic auth
            if self.clientAuth == "Basic Auth":
                
                # Create basic auth string
                auth = self.clientID + ":" + self.clientSecret
                auth = base64.b64encode(auth.encode())
                
                # Create headers
                headers = ["POST %s %s" % (self.path, self.httpVersion), "Host: %s" % (self.host), "Authorization: Basic %s" % (auth), "Content-Type: application/x-www-form-urlencoded", "Accept: */*", "Connection: close"]
                
                if self.grantType == "Client Credentials":
                    
                    # Create body
                    body = 'grant_type=client_credentials&scope=%s' % (quote_plus(self.scope))
                
                if self.grantType == "ROPC":
                    
                    # Create body
                    body = 'grant_type=password&username=%s&password=%s&scope=%s' % (quote_plus(self.username), quote_plus(self.password), quote_plus(self.scope))
            
            # If in body
            else:
                
                # Create headers
                headers = ["POST %s %s" % (self.path, self.httpVersion), "Host: %s" % (self.host), "Content-Type: application/x-www-form-urlencoded", "Accept: */*", "Connection: close"]
                
                if self.grantType == "Client Credentials":
                    
                    # Create body
                    body = 'grant_type=client_credentials&client_id=%s&client_secret=%s&scope=%s' % (quote_plus(self.clientID), quote_plus(self.clientSecret), quote_plus(self.scope))
                
                if self.grantType == "ROPC":
                    
                    # Create body
                    body = 'grant_type=password&client_id=%s&client_secret=%s&username=%s&password=%s&scope=%s' % (quote_plus(self.clientID), quote_plus(self.clientSecret), quote_plus(self.username), quote_plus(self.password), quote_plus(self.scope))
                
                if self.grantType == "Password Credentials":
                    
                    # Create body
                    body = 'grant_type=password&username=%s&password=%s&scope=%s' % (quote_plus(self.username), quote_plus(self.password), quote_plus(self.scope))
            
            # Build message
            message = self._helpers.buildHttpMessage(headers, self._helpers.stringToBytes(body))
            
            # Create HTTP service
            try:
                service = self._helpers.buildHttpService(self.host, int(self.port), self.protocol)
            
            except:
                self.writeLog("Invalid port?")
                self.currentToken[1] = "error"
                return
            
            if self.debugMode:
                self.writeLog(self.debugRequest % (self._helpers.bytesToString(message)))
            
            # Force HTTP version
            try:
                
                if self.httpVersion == "HTTP/1.1":
                    
                    # Make HTTP/1.1 request
                    request = self.callbacks.makeHttpRequest(service, message, True)
                
                else:
                    
                    # Make HTTP/2 request
                    request = self.callbacks.makeHttpRequest(service, message)
                
                # Get response
                response = request.getResponse()
                
                # Check for null response
                if response == None:
                    self.writeLog("No response! Try debug mode?")
                    self.currentToken[1] = "error"
                    return
            
            except Exception as e:
                
                self.writeLog("Ahhh! Invalid URL?? Consult Extender output for details.")
                self.currentToken[1] = "error"
                print str(e)
                return
            
            if self.debugMode:
                self.writeLog(self.debugResponse % (self._helpers.bytesToString(response)))
            
            # Analyse response
            info = self._helpers.analyzeResponse(response)
            
            # Get body offset
            offset = info.getBodyOffset()
            
            # Create json string
            try:
                
                # Parse json to OrderedDict to preserve order
                jsonString = json.loads(self._helpers.bytesToString(response)[offset:], object_pairs_hook=OrderedDict)
            
            except:
                
                self.writeLog("Something went wrong! Check token URL?")
                self.currentToken[1] = "error"
                return
            
            # Try get access_token
            try:
                token = self.findToken(jsonString, "token")
                if token == None:
                    raise Exception("Couldn't get token")
            
            # Failed
            except:
                    
                self.writeLog("Failed to retrieve token. Try debug mode?")
                self.currentToken[1] = "error"
                
                # Try get error
                try:
                    error = self.findToken(jsonString, "error")
                    if error != None:
                        self.writeLog("Error: " + error)
                
                # Failed again!
                except:
                    pass
                return
            
            # Try get 'expires_in' value, otherwise ingore
            try:
                
                exp = self.findToken(jsonString, "expires_in")
                
                # Set expire time
                if exp != None:
                    with self.tokenLock:
                        self.expireIn[0] = time.time() + exp
            
            except:
                pass
            
            # Update current token
            with self.tokenLock:
                self.currentToken[0] = token
            
            self.writeLog("Got token: " + token)
            self.currentToken[1] = ""
            return
    
    ################################################
    # CUSTOM FUNCTIONS
    ################################################
    
    #
    # Write to txtLog (threadsafe)
    #
    def writeLog(self, message):
        
        # Get timestamp
        now = datetime.datetime.now()
        
        # Write to log
        with self.logLock:
            self.txtLog.text += "[" + now.strftime("%H:%M:%S") + "] " + message + "\n"
        return
    
    #
    # Check parameters
    #
    def checkParameters(self, grantType):
        
        if self.cmbGrantType.getSelectedItem() == "Password Credentials" and self.cmbClientAuth.getSelectedItem() == "Basic Auth":
            
            self.writeLog("Password credentials incompatible with basic auth")
            
            return False
        
        # All grant types
        if len(self.txtCustomHeader.text) <= 0:
            
            self.writeLog("No custom header")
            
            return False
        
        if len(self.txtTokenURL.text) <= 0:
            
            self.writeLog("No token URL")
            
            return False
        
        if len(self.txtPort.text) <= 0:
            
            self.writeLog("No port")
            
            return False
        
        # Password credentials
        if grantType == "Password Credentials":
            
            if len(self.txtUsername.text) <= 0:
                
                self.writeLog("No Username")
                
                return False
            
            if len(self.txtPassword.text) <= 0:
                
                self.writeLog("No Password")
                
                return False
        
        # Client credentials
        if grantType == "Client Credentials" or grantType == "ROPC":
            
            if len(self.txtClientID.text) <= 0:
                
                self.writeLog("No Client ID")
                
                return False
            
            if len(self.txtClientSecret.text) <= 0:
                
                self.writeLog("No Client Secret")
                
                return False
        
        # All grant types
        if len(self.txtScope.text) <= 0:
            
            self.writeLog("No Scope")
            
            return False
        
        return grantType
    
    #
    # Update request with current token
    #
    def setToken(self, messageInfo):
        
        # Get request info
        requestInfo = self._helpers.analyzeRequest(messageInfo)
        
        # Get headers
        headers = requestInfo.getHeaders()
        
        # Get body
        reqBody = messageInfo.getRequest()[requestInfo.getBodyOffset():]
        
        # Header to delete
        headerToDelete = ''
        
        # Find authorization header
        for header in headers:
            
            if self.txtCustomHeader.text in header:
                
                # Set header to delete
                headerToDelete = header
                
                break
        
        # Delete header
        try:
            headers.remove(headerToDelete)
        except:
            pass
        
        # Add new header
        headers.add(self.txtCustomHeader.text + ' ' + self.currentToken[0])
        
        # Build message
        message = self._helpers.buildHttpMessage(headers, reqBody)
        
        # Replace request message
        messageInfo.setRequest(message)
        
        return messageInfo
    
    #
    # Check if current token expired
    #
    def checkExpired(self, headers):
        
        # Try parse JWT expiry
        try:
            
            # Find authorization or custom header
            for header in headers:
                if header.startswith(self.txtCustomHeader.text):
                    
                    # Get first part of token
                    token = header[22:].split('.')[1]
                    
                    # Pad as required
                    padded = token + "="*divmod(len(token),4)[1]
                    
                    # Decode to json string
                    jsondata = base64.urlsafe_b64decode(str(padded))
                    
                    # Get json
                    jwt = json.loads(jsondata)
                    
                    # Get exp from json
                    exp = int(jwt["exp"])
                    
                    # Get current time
                    now = int(time.time())
                    
                    # If time elapsed with 3 seconds remaining
                    if (now - exp) >= -3:
                        
                        return True
        
        # Fallback to 'expires_in' value
        except:
            
            # Use 'expires_in' value
            if (int(time.time()) - self.expiresIn[0]) >= -3:
                
                return True
        
        return False
    

    ################################################
    # UI STUFF
    ################################################
    
    #
    # Init UI
    #
    def initUI(self):
        
        #
        # Debug mode
        #
        def toggleDebug(event):
            
            if self.debugMode:
                self.debugMode = False
                self.writeLog("Debug mode disabled")
            
            else:
                self.debugMode = True
                self.writeLog("Debug mode enabled")
            
            return
        
        #
        # Activate
        #
        def activate(event):
            
            if self.activated:
                self.cmbProtocol.setEnabled(True)
                self.txtTokenURL.setEnabled(True)
                self.txtPort.setEnabled(True)
                self.cmbHttpVersion.setEnabled(True)
                self.cmbGrantType.setEnabled(True)
                self.txtUsername.setEnabled(True)
                self.txtPassword.setEnabled(True)
                self.txtClientID.setEnabled(True)
                self.txtClientSecret.setEnabled(True)
                self.txtScope.setEnabled(True)
                self.cmbClientAuth.setEnabled(True)
                self.chkRepeater.setEnabled(True)
                self.chkIntruder.setEnabled(True)
                self.chkScanner.setEnabled(True)
                self.chkExtender.setEnabled(True)
                self.chkSequencer.setEnabled(True)
                self.chkTarget.setEnabled(True)
                self.chkProxy.setEnabled(True)
                if self.chkCustomHeader.isSelected():
                    self.txtCustomHeader.setEnabled(True)
                self.chkCustomHeader.setEnabled(True)
                selectGrantType(event)
                self.activated = False
                self.btnActivate.setText("Activate")
                self.writeLog("Deactivated")
            
            else:
                if self.checkParameters(self.cmbGrantType.getSelectedItem()) == False:
                    return
                self.cmbProtocol.setEnabled(False)
                self.txtTokenURL.setEnabled(False)
                self.txtPort.setEnabled(False)
                self.cmbHttpVersion.setEnabled(False)
                self.cmbGrantType.setEnabled(False)
                self.txtUsername.setEnabled(False)
                self.txtPassword.setEnabled(False)
                self.txtClientID.setEnabled(False)
                self.txtClientSecret.setEnabled(False)
                self.txtScope.setEnabled(False)
                self.cmbClientAuth.setEnabled(False)
                self.chkCustomHeader.setEnabled(False)
                self.chkRepeater.setEnabled(False)
                self.chkIntruder.setEnabled(False)
                self.chkScanner.setEnabled(False)
                self.chkExtender.setEnabled(False)
                self.chkSequencer.setEnabled(False)
                self.chkTarget.setEnabled(False)
                self.chkProxy.setEnabled(False)
                if self.chkCustomHeader.isSelected():
                    self.txtCustomHeader.setEnabled(True)
                self.txtCustomHeader.setEnabled(False)
                self.activated = True
                self.btnActivate.setText("Deactivate")
                self.tokenUrl = self.cmbProtocol.getSelectedItem() + self.txtTokenURL.text.split("/")[0] + ":" + self.txtPort.text + self.txtTokenURL.text.replace(self.txtTokenURL.text.split("/")[0], "")
                self.writeLog("Activated - adding token to requests...")
            
            return
        
        #
        # Enable/disable text fields
        #
        def selectGrantType(event):
            
            if self.cmbGrantType.getSelectedItem() == "Client Credentials":
                self.txtUsername.setEnabled(False)
                self.txtPassword.setEnabled(False)
                self.txtClientID.setEnabled(True)
                self.txtClientSecret.setEnabled(True)
            
            if self.cmbGrantType.getSelectedItem() == "Password Credentials":
                self.txtUsername.setEnabled(True)
                self.txtPassword.setEnabled(True)
                self.txtClientID.setEnabled(False)
                self.txtClientSecret.setEnabled(False)
            
            if self.cmbGrantType.getSelectedItem() == "ROPC":
                self.txtUsername.setEnabled(True)
                self.txtPassword.setEnabled(True)
                self.txtClientID.setEnabled(True)
                self.txtClientSecret.setEnabled(True)
            
            return
        
        #
        # Custom header
        #
        def customHeader(event):
            if self.txtCustomHeader.enabled == True:
                self.txtCustomHeader.setEnabled(False)
            else:
                self.txtCustomHeader.setEnabled(True)
            return
        
        #
        # Test token retrieval
        #
        def test(event):
            
            # Check parameters
            grantType = self.checkParameters(self.cmbGrantType.getSelectedItem())
            
            # If parameters good
            if grantType != False:
                
                self.writeLog("Testing: " + self.cmbProtocol.getSelectedItem() + self.txtTokenURL.text)
                
                # Create TokenRequest
                tokenRequest = self.TokenRequest(self.debugMode, self.debugRequest, self.debugResponse, self.callbacks, self._helpers, self.txtLog, self.logLock, self.currentToken, self.tokenLock, self.expiresIn, grantType, self.cmbClientAuth.getSelectedItem(), self.txtTokenURL.text, self.txtPort.text, self.cmbProtocol.getSelectedItem().split(":")[0], self.cmbHttpVersion.getSelectedItem().split(":")[0], self.txtUsername.text, self.txtPassword.text, self.txtClientID.text, self.txtClientSecret.text, self.txtScope.text)
                
                # New thread
                t = Thread(target=tokenRequest.go, args=[])
                t.daemon = True
                t.start()
        
        #
        # Manage check boxes
        #
        def checkUncheck(event):
            
            # Get event
            scopeItem = event.getActionCommand()
            
            # Add/remove from scope
            if scopeItem == "Extender":
                if 1024 in self.scope:
                    self.scope.remove(1024)
                else:
                    self.scope.append(1024)
            elif scopeItem == "Intruder":
                if 32 in self.scope:
                    self.scope.remove(32)
                else:
                    self.scope.append(32)
            elif scopeItem == "Proxy":
                if 4 in self.scope:
                    self.scope.remove(4)
                else:
                    self.scope.append(4)
            elif scopeItem == "Repeater":
                if 64 in self.scope:
                    self.scope.remove(64)
                else:
                    self.scope.append(64)
            elif scopeItem == "Scanner":
                if 16 in self.scope:
                    self.scope.remove(16)
                else:
                    self.scope.append(16)
            elif scopeItem == "Target":
                if 2 in self.scope:
                    self.scope.remove(2)
                else:
                    self.scope.append(2)
            elif scopeItem == "Sequencer":
                if 128 in self.scope:
                    self.scope.remove(128)
                else:
                    self.scope.append(128)
            return
        
        # Tabs
        self.tabbedPane = JTabbedPane()
        
        # Main panel
        self._splitpane = JSplitPane()
        
        # Labels
        lblTokenURL = JLabel()
        lblTokenURL.setText("Token URL:")
        lblTokenURL.setHorizontalAlignment(SwingConstants.TRAILING)
        lblGrantType = JLabel()
        lblGrantType.setText("Grant Type:")
        lblGrantType.setHorizontalAlignment(SwingConstants.TRAILING)
        lblPort = JLabel()
        lblPort.setText("Port:")
        lblClientAuth = JLabel()
        lblClientAuth.setText("Client Auth:")
        lblUsername = JLabel()
        lblUsername.setHorizontalAlignment(SwingConstants.TRAILING)
        lblUsername.setText("Username:")
        lblPassword = JLabel()
        lblPassword.setHorizontalAlignment(SwingConstants.TRAILING)
        lblPassword.setText("Password:")
        lblClientID = JLabel()
        lblClientID.setHorizontalAlignment(SwingConstants.TRAILING)
        lblClientID.setText("Client ID:")
        lblClientSecret = JLabel()
        lblClientSecret.setHorizontalAlignment(SwingConstants.TRAILING)
        lblClientSecret.setText("Client Secret:")
        lblScope = JLabel()
        lblScope.setHorizontalAlignment(SwingConstants.TRAILING)
        lblScope.setText("Scope:")
        
        # Text fields
        self.txtTokenURL = JTextField()
        self.txtTokenURL.setText("example-token-endpoint.com/default/token")
        self.txtPort = JTextField()
        self.txtPort.setText("443")
        self.txtCustomHeader = JTextField()
        self.txtCustomHeader.setText("Authorization: Bearer")
        self.txtCustomHeader.setEnabled(False)
        self.txtUsername = JTextField()
        self.txtUsername.setEnabled(False)
        self.txtPassword = JTextField()
        self.txtPassword.setEnabled(False)
        self.txtClientID = JTextField()
        self.txtClientSecret = JTextField()
        self.txtScope = JTextField()
        self.txtScope.setText("read")
        
        # Buttons
        self.btnTest = JButton(actionPerformed=test)
        self.btnTest.setText("Test")
        self.btnActivate = JButton(actionPerformed=activate)
        self.btnActivate.setText("Activate")
        
        # Combo Boxes
        model = ('Client Credentials', 'Password Credentials', 'ROPC')
        self.cmbGrantType = JComboBox(model, actionListener=selectGrantType)
        model2 = ('http://', 'https://')
        self.cmbProtocol = JComboBox(model2)
        self.cmbProtocol.setSelectedIndex(1)
        model3 = ('HTTP/1.1', 'HTTP/2')
        self.cmbHttpVersion = JComboBox(model3)
        model4 = ('In Body', 'Basic Auth')
        self.cmbClientAuth = JComboBox(model4)
        
        # Check Boxes
        self.chkDebug = JCheckBox(actionPerformed=toggleDebug)
        self.chkDebug.setText("Debug")
        self.chkCustomHeader = JCheckBox(actionPerformed=customHeader)
        self.chkCustomHeader.setText("Custom Header")
        
        
        self.chkRepeater = JCheckBox(actionPerformed=checkUncheck)
        self.chkRepeater.setText("Repeater")
        self.chkIntruder = JCheckBox(actionPerformed=checkUncheck)
        self.chkIntruder.setText("Intruder")
        self.chkScanner = JCheckBox(actionPerformed=checkUncheck)
        self.chkScanner.setText("Scanner")
        self.chkExtender = JCheckBox(actionPerformed=checkUncheck)
        self.chkExtender.setText("Extender")
        self.chkSequencer = JCheckBox(actionPerformed=checkUncheck)
        self.chkSequencer.setText("Sequencer")
        self.chkTarget = JCheckBox(actionPerformed=checkUncheck)
        self.chkTarget.setText("Target")
        self.chkProxy = JCheckBox(actionPerformed=checkUncheck)
        self.chkProxy.setText("Proxy")
        
        # Other elements
        jPanel2 = JPanel()
        jPanel3 = JPanel()
        jScrollPane1 = JScrollPane()
        jScrollPane2 = JScrollPane()
        jScrollPane3 = JScrollPane()
        self.txtLog = JTextArea()
        self.txtLog.setEditable(False)
        self.txtLog.setLineWrap(True)
        self.txtLog.setColumns(20)
        self.txtLog.setRows(5)
        txtAbout = JTextArea()
        txtAbout.setText("""-- OAuth2 Token Grabber v1.0 --
Grabs OAuth2 access tokens and adds them to requests as custom headers.

Currently supported auth flows:
    - Client Credentials
    - Password Credentials
    - Resource Owner Password Credentials (ROPC)

Usage
    - Select desired grant type & client authentication method
    - (Optional) Set a custom header for access tokens to be added to
    - Input token URL
    - Input relevant credentials and scope
    - Hit 'Test'. You should recieve an access token (Otherwise, try debug mode)
    - Select desired tool scope
    - Hit 'Activate'. The access token will then be added to all in scope traffic
    - When the access token expires, a new one will be requested automatically
    
https://github.com/0kman/OAuth2-Token-Grabber""")
        txtAbout.setEditable(False)
        caret = self.txtLog.getCaret()
        caret.setUpdatePolicy(DefaultCaret.ALWAYS_UPDATE)
        jScrollPane1.setEnabled(False)
        jScrollPane1.setHorizontalScrollBar(None)
        jScrollPane1.setViewportView(self.txtLog)
        jScrollPane1.setMinimumSize(Dimension(0,0))
        jScrollPane1.setPreferredSize(Dimension(0,0))
        jSeparator2 = JSeparator()
        jSeparator3 = JSeparator()
        jSeparator4 = JSeparator()

        # Layout
        layout = GroupLayout(self._splitpane)
        self._splitpane.setLayout(layout)
        layout.setHorizontalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addComponent(jSeparator2)
            .addComponent(jSeparator3, GroupLayout.Alignment.TRAILING)
            .addComponent(jSeparator4)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                    .addGroup(GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING, False)
                                    .addComponent(lblClientID, GroupLayout.DEFAULT_SIZE, 74, Short.MAX_VALUE)
                                    .addComponent(lblPassword, GroupLayout.DEFAULT_SIZE, 74, Short.MAX_VALUE)
                                    .addComponent(lblUsername, GroupLayout.DEFAULT_SIZE, 74, Short.MAX_VALUE)
                                    .addComponent(lblClientSecret, GroupLayout.DEFAULT_SIZE, 74, Short.MAX_VALUE)
                                    .addComponent(lblScope, GroupLayout.PREFERRED_SIZE, 74, GroupLayout.PREFERRED_SIZE))
                                    .addGroup(layout.createSequentialGroup()
                                        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                            .addComponent(self.txtClientID, GroupLayout.PREFERRED_SIZE, 150, GroupLayout.PREFERRED_SIZE)
                                            .addComponent(self.txtUsername, GroupLayout.PREFERRED_SIZE, 150, GroupLayout.PREFERRED_SIZE)
                                            .addComponent(self.txtPassword, GroupLayout.PREFERRED_SIZE, 150, GroupLayout.PREFERRED_SIZE)
                                            .addComponent(self.txtClientSecret, GroupLayout.PREFERRED_SIZE, 150, GroupLayout.PREFERRED_SIZE)
                                            .addComponent(self.txtScope, GroupLayout.PREFERRED_SIZE, 150, GroupLayout.PREFERRED_SIZE))))
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(lblTokenURL, GroupLayout.PREFERRED_SIZE, 75, GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(self.cmbProtocol, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(self.txtTokenURL, GroupLayout.PREFERRED_SIZE, 350, GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(lblPort)
                                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(self.txtPort, GroupLayout.PREFERRED_SIZE, 60, GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(self.cmbHttpVersion, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(lblGrantType, GroupLayout.PREFERRED_SIZE, 75, GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(self.cmbGrantType, GroupLayout.PREFERRED_SIZE, 165, GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(lblClientAuth)
                                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(self.cmbClientAuth, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(self.chkCustomHeader, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(self.txtCustomHeader, GroupLayout.PREFERRED_SIZE, 150, GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(self.chkDebug)))
                        .addGap(0, 0, Short.MAX_VALUE))
                    .addGroup(GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addComponent(self.chkRepeater)
                        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(self.chkIntruder)
                        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(self.chkScanner)
                        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(self.chkExtender)
                        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(self.chkSequencer)
                        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(self.chkTarget)
                        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(self.chkProxy)
                        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(self.btnTest)
                        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(self.btnActivate))
                    .addComponent(jScrollPane1, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addContainerGap())
        )
        layout.setVerticalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(lblGrantType)
                    .addComponent(self.cmbGrantType, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                    .addComponent(lblClientAuth)
                    .addComponent(self.cmbClientAuth, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                    .addComponent(self.chkCustomHeader, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                    .addComponent(self.txtCustomHeader, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                    .addComponent(self.chkDebug))
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jSeparator2, GroupLayout.PREFERRED_SIZE, 2, GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(lblTokenURL)
                    .addComponent(self.txtTokenURL, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                    .addComponent(self.cmbProtocol, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                    .addComponent(self.cmbHttpVersion, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                    .addComponent(lblPort)
                    .addComponent(self.txtPort, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jSeparator3, GroupLayout.PREFERRED_SIZE, 2, GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(lblUsername)
                    .addComponent(self.txtUsername, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(lblPassword)
                    .addComponent(self.txtPassword, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(lblClientID)
                    .addComponent(self.txtClientID, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(lblClientSecret)
                    .addComponent(self.txtClientSecret, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(lblScope)
                    .addComponent(self.txtScope, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jSeparator4, GroupLayout.PREFERRED_SIZE, 2, GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self.btnTest)
                    .addComponent(self.btnActivate)
                    .addComponent(self.chkExtender)
                    .addComponent(self.chkIntruder)
                    .addComponent(self.chkRepeater)
                    .addComponent(self.chkScanner)
                    .addComponent(self.chkTarget)
                    .addComponent(self.chkSequencer)
                    .addComponent(self.chkProxy))
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane1, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addContainerGap())
        )

        jScrollPane3.setViewportView(jPanel3)
        
        jPanel3Layout = GroupLayout(jPanel3)
        jPanel3.setLayout(jPanel3Layout)
        jPanel3Layout.setHorizontalGroup(
            jPanel3Layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(jPanel3Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(self._splitpane, 770, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addContainerGap())
        )
        jPanel3Layout.setVerticalGroup(
            jPanel3Layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(jPanel3Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(self._splitpane, 300, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addContainerGap())
        )

        self.tabbedPane.addTab("Oauth2 Token Grabber", jScrollPane3)

        jPanel2Layout = GroupLayout(jPanel2)
        jPanel2.setLayout(jPanel2Layout)
        jPanel2Layout.setHorizontalGroup(
            jPanel2Layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addComponent(txtAbout, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE))
        )
        jPanel2Layout.setVerticalGroup(
            jPanel2Layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addComponent(txtAbout, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE))
        )

        jScrollPane2.setViewportView(jPanel2)

        self.tabbedPane.addTab("About", jScrollPane2)
        return
