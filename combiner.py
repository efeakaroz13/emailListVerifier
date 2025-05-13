import json 
import pandas as pd

l1 = json.loads(open("lead_worker1.json","r").read())
l2 = json.loads(open("lead_worker2.json","r").read())
l3 = json.loads(open("lead_worker3.json","r").read())
l4 = json.loads(open("lead_worker4.json","r").read())
l5 = json.loads(open("lead_worker5.json","r").read())

newdata = [["businessName","city","state","phone","email","website","domain","claimed","reviewCount","stars"]]
wixdata = [["businessName","city","state","phone","email","website","domain","claimed","reviewCount","stars"]]

for w in l1["wix"]:
    wixdata.append(w)



for w in l2["wix"]:
    wixdata.append(w)

for w in l3["wix"]:
    wixdata.append(w)

for w in l4["wix"]:
    wixdata.append(w)

for w in l5["wix"]:
    wixdata.append(w)

wixdf = pd.DataFrame(wixdata)
wixdf.to_csv("wixleads2025.csv")
for l in l1["leads"]:
    newdata.append(l)

for l in l2["leads"]:
    newdata.append(l)
    
for l in l3["leads"]:
    newdata.append(l)
    
for l in l4["leads"]:
    newdata.append(l)
    
for l in l5["leads"]:
    newdata.append(l)


leads = pd.DataFrame(newdata)
leads.to_csv("allLeads2025.csv")