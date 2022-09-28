__author__="Anil Yelken"

from burp import IBurpExtender
from burp import ISessionHandlingAction 

class BurpExtender(IBurpExtender, ISessionHandlingAction):
    def registerExtenderCallbacks(self, callbacks):
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Add Bugbounty Header by Anil Yelken")
        callbacks.registerSessionHandlingAction(self)

    
    def getActionName(self):
        return "Add \"Bugbounty\" header"
    
    def performAction(self, currentRequest, macroItems):
        request = currentRequest.getRequest()
        analyzeRequest = self._helpers.analyzeRequest(request)
        headers = analyzeRequest.getHeaders()
        headers.add("cyber:security")
        body = request[analyzeRequest.getBodyOffset():]
        newRequest = self._helpers.buildHttpMessage(headers, body)
        currentRequest.setRequest(newRequest)
        return
        
try:
    from exceptions_fix import FixBurpExceptions
except ImportError:
    pass
    
try:
    FixBurpExceptions()
except:
    pass
