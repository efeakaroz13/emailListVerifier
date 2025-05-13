import socket
import smtplib
import os 
import dns.resolver
import redis 
import uuid
red = redis.Redis()
import smtplib
import dns.resolver
import uuid
import socks
import socket

def verify(email):
    # Store original socket
    original_socket = socket.socket

    try:
        domain = email.split("@")[1]

        # Get MX record from cache or DNS
        try:
            mxRecord = red.get(domain).decode()
        except:
            records = dns.resolver.resolve(domain, 'MX')
            mxRecord = str(records[0].exchange).rstrip('.')
            if len(mxRecord) < 2:
                return False
            red.set(domain, mxRecord)

        # Configure SOCKS5 proxy
        socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 9050)
        socket.socket = socks.socksocket
        
        # Set up SMTP
        host = "gmail.com"
        server = smtplib.SMTP()
        server.set_debuglevel(0)
        server.connect(mxRecord)
        server.helo(host)
        server.mail('kasper@gmail.com')

        # First: check the real email
        code_real, message_real = server.rcpt(email)

        # Then: check a fake, random address at the same domain
        fake_email = f"{uuid.uuid4().hex[:12]}@{domain}"
        code_fake, message_fake = server.rcpt(fake_email)

        server.quit()

        # If fake also returns 250, likely catch-all -> treat as invalid
        if code_real == 250 and code_fake != 250:
            return True
        else:
            return False

    except Exception as e:
        return False
    finally:
        # Restore original socket
        socket.socket = original_socket






if __name__ == "__main__":

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
