from PyPDF2 import PdfFileReader
from PyPDF2.pdf import Destination
import json
import requests
import sys
endpoint="http://127.0.0.1:8080/addpage"
pdfFileObj=open("./temp_images/"+sys.argv[1],"rb")
pdfReader=PdfFileReader(pdfFileObj)
numerodePaginas=pdfReader.numPages
x=int(sys.argv[2])
while x<=int(sys.argv[2])+int(sys.argv[3]):
    x=x+1
    pageObj=pdfReader.getPage(x)
    str=pageObj.extractText()
    payload=[iduser=sys.argv[4],idbook=sys.argv[5],text=str]
    r=requests.put(endpoint,data=json.dumps(payload))
    print(r.status_code)


#marc=open("marcadores.txt","w")
#print(marcadores)






