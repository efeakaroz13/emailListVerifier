import socket
import smtplib
import os 
import dns.resolver


def verify(email):
    try:
        domain = email.split("@")[1]
        records = dns.resolver.resolve(domain, 'MX')
        mxRecord = records[0].exchange
        mxRecord = str(mxRecord)
        if len(mxRecord)<2:
            return False
    except:
        return False
    
    host = "kentel.dev"
   
    # SMTP lib setup (use debug level for full output)
    server = smtplib.SMTP()
    server.set_debuglevel(0)

    # SMTP Conversation
    server.connect(mxRecord)
    server.helo(host)
    server.mail('efeakaroz@kentel.dev')
    code, message = server.rcpt(str(email))
    server.quit()

    if code == 250:
        return True
    else:
        return False






elist = open("list.txt","r").readlines()

verified = []
unverified = []
for e in elist:
    e= e.replace("\n","")
    e= e.replace(" ","")
    if len(e)>3:
        out = verify(e)
        if out == True:
            verified.append(e)
        else:
            unverified.append(e)

print(verified)
print(unverified)
