from emailVerifier import verify
import pandas as pd 
import numpy as np 
from multiprocessing import Process,Manager

def verifierProcess(inplist,column,return_array):
        verified = []
        for l in inplist:
            verifier = verify(l[column])
            if verifier == True:
                return_array.append(l)
                print(l[column]," Verified")
            else:
                print(l[column]," Not Verified")


if __name__ == "__main__":
    manager = Manager()

    return_array = manager.list()
    jobs = []
    df = pd.read_csv(input("Input CSV relative path:"))
    columns = list(df.columns.values)
    for c in columns:
        print(columns.index(c),f" - {c}")

    colToVerify = columns[int(input("Which column to verify(int):"))]
    outFile = input("Enter an output file(CSV):")



    l1 = []
    l2= []
    l3=[]
    l4= []
    l5 = []
    counter = 0 
    for i,r in df.iterrows():

        if type(r[colToVerify]) == float:

            continue
        else:
            pass


        counter +=1
        if counter == 1:
            l1.append(r)
        if counter == 2:
            l2.append(r)

        if counter == 3:
            l3.append(r)

        if counter == 4:
            l4.append(r)

        if counter == 5:
            l5.append(r)
            counter = 0
            


    
    p1 = Process(target=verifierProcess,args=(l1,colToVerify,return_array))

    p2 = Process(target=verifierProcess,args=(l2,colToVerify,return_array))
    p3 = Process(target=verifierProcess,args=(l3,colToVerify,return_array))
    p4 = Process(target=verifierProcess,args=(l4,colToVerify,return_array))
    p5 = Process(target=verifierProcess,args=(l5,colToVerify,return_array))

    p1.start()
    p2.start()
    p3.start()
    p4.start()
    p5.start()
    p1.join()
    p2.join()
    p3.join()
    p4.join()
    p5.join()
    dfout = pd.DataFrame([s.to_dict() for s in return_array])
    dfout.to_csv(outFile,index=False)

