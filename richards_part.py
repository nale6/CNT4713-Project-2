# Help: https://www.eventhelix.com/networking/ftp/
# Help: https://www.eventhelix.com/networking/ftp/FTP_Port_21.pdf
# Help: https://realpython.com/python-sockets/
# Help: PASV mode may be easier in the long run. Active mode works 
# Reading: https://unix.stackexchange.com/questions/93566/ls-command-in-ftp-not-working
# Reading: https://stackoverflow.com/questions/14498331/what-should-be-the-ftp-response-to-pasv-command

#import socket module

from socket import *
import sys # In order to terminate the program

#Creating header and question sections of DNS query and forming query variable by adding them. Takes parameters of domain, ip address to send query and socket.
def sendQuery(domain, ipaddr, clientSocket):
    encodedDomain = encodeDomain(domain)
    header = dnsHeader()
    question = dnsQuestion(encodedDomain)
    query = header + question
    clientSocket.sendto(query, (ipaddr, 53))

#Receiving response, taking socket as parameter and returning the first part of a DNS reply. Second part is just the sender's address and port.
def receiveResponse(clientSocket):
    response = clientSocket.recvfrom(512)[0]
    return response

#Function to create a dns header section of query by setting variables with integer variables and converting them to bytes.
#Returns dns header as byte string
def dnsHeader():
    #ID can be any value for single query. Flag set to 0 because we are performing iterative process.
    id = 0x0000
    flags = 0x0000
    questionCount = 1
    answerCount = 0
    authorityCount = 0
    additionalCount = 0

    header = (id.to_bytes(2, "big") + flags.to_bytes(2, "big") + questionCount.to_bytes(2, "big") + answerCount.to_bytes(2, "big") + authorityCount.to_bytes(2, "big") + additionalCount.to_bytes(2, "big"))

    return header

#Function to create question section of query. Takes parameter of encoded domain and adds it to questiontype and questionclass fields that are converted from integer to bytes.
#Returns dns question section as byte string
def dnsQuestion(encodedDomain):
    questionName = encodedDomain
    questionType = 1
    questionClass = 1

    return (questionName + questionType.to_bytes(2, "big") + questionClass.to_bytes(2, "big"))

#Function to decode response from bytes to integer and return a key-value list with all fields
def decodeResponse(response):
    decodedHeader = {
        "id": int.from_bytes(response[0:2], "big"),
        "flags": int.from_bytes(response[2:4], "big"),
        "questionCount": int.from_bytes(response[4:6], "big"),
        "answerCount": int.from_bytes(response[6:8], "big"),
        "authorityCount": int.from_bytes(response[8:10], "big"),
        "additionalCount": int.from_bytes(response[10:12], "big")
    }

    return decodedHeader

#Function to encode domain we are searching for. Shouldn't be used more than once.
def encodeDomain(domain):
    #Need to split domain (each split occurs at the period) and add the number of characters per split and add a 0 at the end, as a byte string.
    encodeDomain = b''

    for section in domain.split('.'):
       encodeDomain += bytes([len(section)]) + section.encode()

    encodeDomain += b"\x00"

    return encodeDomain
    
def main():
    #If commandline did not receive 3 argument (filename, domain, ip) then notify user and exit program
    if len(sys.argv) != 3:
        print("Command to run file: python mydns.py <name of domain to search> <ip address>")
        sys.exit(1)

    #Socket so that recvfrom works
    clientSocket = socket(AF_INET, SOCK_DGRAM)

    #Second argument is domain
    domain = sys.argv[1]
    #Third argument is domain
    ipaddr = sys.argv[2]

    currentIP = ipaddr
    foundAnswer = False

    while not foundAnswer:

        # Send query to the current DNS server
        sendQuery(domain, currentIP, clientSocket)

        # Receive response from DNS server
        response = receiveResponse(clientSocket)

        # Decode the header of the response
        decodedResponse = decodeResponse(response)

        print("Query sent to:", currentIP)
        print("Answer count:", decodedResponse["answerCount"])

        # If answer found, stop looping
        if decodedResponse["answerCount"] > 0:
            foundAnswer = True
            print("Answer found!")

        else:
            # TEMPORARY placeholder until Sabrina writes the parser
            nextIP = extractNextDNSIP(response)

            print("Next DNS server:", nextIP)

            # Update server to query next
            currentIP = nextIP

    sys.exit()  # Terminate the program

main()
