import sys
import fitz
from PyPDF4 import PdfFileReader
from PyPDF4.pdf import Destination


def recorrer(oobj, profundidad):
    for pel in oobj:
        if type(pel) is list:
            recorrer(pel, profundidad+1)
        elif type(pel) is Destination:
            print(profundidad*"\t"+pel.title+"," +
                  str(pdf.getDestinationPageNumber(pel)))


doc = fitz.open(sys.argv[1])
page = doc.loadPage(0)  # number of page
pix = page.getPixmap()
output = sys.argv[2]+sys.argv[3] + ".png"
pix.writePNG(output)
pdf = PdfFileReader(open(sys.argv[1], "rb"))
prr = pdf.outlines
recorrer(prr, 0)
