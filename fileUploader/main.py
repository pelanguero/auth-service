from PyPDF2 import PdfFileReader
from PyPDF2.pdf import Destination

pdfFileObj=open("Building REST APIs with Flask.pdf","rb")
pdfReader=PdfFileReader(pdfFileObj)
numerodePaginas=pdfReader.numPages
pageObj=pdfReader.getPage(15)
outline= pdfReader.getOutlines(node=None,outlines=None)
#marc=open("marcadores.txt","w")
#print(marcadores)
archivo=open("prueba.txt","w")
archivo.write(pageObj.extractText())
archivo.close()




