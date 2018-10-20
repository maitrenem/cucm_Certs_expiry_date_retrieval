import regex
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import requests
import csv

filename = 'cucm.txt'

file = open(filename, "r")

o = file.read()

ip1 = regex.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", o)
hosts = ip1
for host in hosts:
    print("host: ", host)
    cucm_url = "https://" + host + "/axl/"

    print(cucm_url)

    # V11 CUCM Headers
    headers11query = {'Content-Type': 'text/xml', 'SOAPAction': 'CUCM:DB ver=11.0 executeSQLQuery'}


    msg = """<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" 
    xmlns:ns="http://www.cisco.com/AXL/API/11.0"> <soapenv:Header/> <soapenv:Body> <ns:executeSQLQuery> <sql> select 
    c.certificate as Cert, c.servername as Server_Name, c.serialnumber as Serial_Number, tcs.name as Cert_Type, 
    c.subjectname as Subject_Name, c.issuername as Issuer from certificate as c inner join 
    certificateservicecertificatemap as cscm on c.pkid = cscm.fkcertificate inner join typecertificateservice as tcs on 
    cscm.tkcertificateservice = tcs.enum</sql> </ns:executeSQLQuery> </soapenv:Body> </soapenv:Envelope> """


    # Create the Requests Connection
    post = requests.post(cucm_url, data=msg, headers=headers11query, verify=False, auth=('administrator', 'ciscopsdt'))

    # print(post) # the whole <Response 200>

    # Getting CERTS Successfully
    # print(post.text)    # class 'str'
    # print(post.content) # class 'bytes'


    certs_res = post.text

    def ParseXmlTagContents(source, tag, tagContentsRegex):
        openTagString = "<"+tag+">"
        closeTagString = "</"+tag+">"

        # print(openTagString)
        found = regex.findall(openTagString + tagContentsRegex + closeTagString, source)
        # print(found)
        return found



    server_name = ParseXmlTagContents(post.text, "server_name", "(?s)(?<=<server_name>)(.+?)(?=</server_name>)")
    cert_type = ParseXmlTagContents(post.text, "cert_type", "(?s)(?<=<cert_type>)(.+?)(?=</cert_type>)")
    subject_name = ParseXmlTagContents(post.text, "subject_name", "(?s)(?<=<subject_name>)(.+?)(?=</subject_name>)")
    issuer = ParseXmlTagContents(post.text, "issuer", "(?s)(?<=<issuer>)(.+?)(?=</issuer>)")
    cert = ParseXmlTagContents(post.text, "cert", "(?s)(?<=<cert>)(.+?)(?=</cert>)")



    # print("Server Name: ", server_name)
    # print("Cert Type: ", cert_type)
    # print("Subject Name: ", subject_name)
    # print("Issuer: ", issuer)
    # print("cert: ", cert)
    #     print(cert_issue_date)
    #     print(cert_expire_date)

    for x, y, z, i, c in zip(server_name, cert_type, subject_name, issuer, cert):
        so_bytes = c.encode()
        # print(so_bytes)
        cert = x509.load_pem_x509_certificate(so_bytes, default_backend())
        # print(cert.serial_number)
        cert_issue_date = str(cert.not_valid_before.strftime('%m/%d/%Y'))
        cert_expire_date = str(cert.not_valid_after.strftime('%m/%d/%Y'))
        print("Server Name: ", x, "\n", "Cert Type: ", y, "\n", "Subject Name: ", z, "\n", "Issuer: ", i, "\n" "Valid before: ", cert_issue_date, "\n", "Not Valid after: ", cert_expire_date)


        finalle = [[host, x, y, z, i, cert_issue_date, cert_expire_date]]

        out = open('out.csv', 'a')

        for row in finalle:
            for column in row:
                out.write('%s;' % column)
            out.write('\n')
        out.close()

        print("Writing complete")

