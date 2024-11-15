import pandas as pd
from emailVerifier import verify


df = pd.read_csv("list1.csv")
df = df.to_numpy()
newdata = ["Business Name", "Email","Phone Number","Website","Email Verfication"]
for d in df:
    
    businessName = d[0]
    email =""
    phoneNumber = "N/A"
    website = "N/A"
    for _ in d:
        _ = str(_)
        if len(_)>6:
            num = _.replace("-","").replace(" ","").replace("(","").replace(")","").replace("+","")
            try:
                num = int(num)
                phoneNumber = _ 
            except:
                pass
        if "@gmail.com" in _:
            email = _
        elif (".com" in _ ) and ("gmail" not in _):
            website = _
        
    if email == "":
        continue
    email = email.lower()

    
    emailVerified = verify(email)
    if emailVerified == True:
        emailVerified = "Verified"
    else:
        emailVerified = "NOT VERIFIED"
    out = [businessName,email,phoneNumber,website,emailVerified]
    newdata.append(out)
    print(out)


newdf = pd.DataFrame(newdata)
newdf.to_csv("out.csv")  
            
