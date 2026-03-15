from socket import *
import sys

#Creating header and question sections of DNS query and forming query variable by adding them. Takes parameters of domain, ip address to send query and socket
def sendQuery(domain, ipaddr, clientSocket):
    encodedDomain = encodeDomain(domain)
    header = dnsHeader()
    question = dnsQuestion(encodedDomain)
    query = header + question
    clientSocket.sendto(query, (ipaddr, 53))

#Receiving response, taking socket as parameter and returning the first part of a DNS reply. Second part is just the sender's address and port.
def receiveResponse(clientSocket):
    response = clientSocket.recvfrom(512)[0]
    # print("Received response. Content overview:")
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

#Function to create question section of query. Takes parameter of encoded domain and adds it to questiontype and questionclass fields that are converted from int to bytes.
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

    # print([f"ID: {decodedHeader["id"]}"])
    # print([f"Flags: {decodedHeader["flags"]}"])
    # print([f"Question Count: {decodedHeader["questionCount"]}"])
    # print([f"Answer Count: {decodedHeader["answerCount"]}"])
    # print([f"Authority Count: {decodedHeader["authorityCount"]}"])
    # print([f"Additional Count: {decodedHeader["additionalCount"]}"])


    return decodedHeader

#Function to encode domain we are searching for. Shouldn't be used more than once.
def encodeDomain(domain):
    #Need to split domain (each split occurs at the period) and add the number of characters per split and add a 0 at the end, as a byte string.
    encodeDomain = b''

    for section in domain.split('.'):
        encodeDomain += bytes([len(section)]) + section.encode()

    encodeDomain += b"\x00"

    return encodeDomain
# -----------------------------------------------------------------------

def extractNextDNSIP(response):
    decodedHeader = decodeResponse(response)
    authorityCount = decodedHeader["authorityCount"]
    additionalCount = decodedHeader["additionalCount"]
    
    domainList = []
    ipList = []
    nsList = []
    nameServerIPMap = {}

    # Parse a domain name at a given offset
    def parseName(offset):
        labels = []
        while True:
            length = response[offset]
            # Check for compression pointer
            if (length & 0xC0) == 0xC0:
                # Next two bytes give the actual offset
                pointer = ((length & 0x3F) << 8) | response[offset + 1]
                name_part, _ = parseName(pointer)
                labels.append(name_part)
                offset += 2
                break
            elif length == 0:
                offset += 1
                break
            else:
                offset += 1
                labels.append(response[offset:offset + length].decode())
                offset += length
        return '.'.join(labels), offset

    offset = 12


    questionCount = decodedHeader["questionCount"]
    for _ in range(questionCount):
        domain, offset = parseName(offset)
        offset += 4

    for _ in range(authorityCount):
        nsName, offset = parseName(offset)
        domainList.append(nsName)
        rtype = int.from_bytes(response[offset:offset + 2], "big")
        offset += 2
        offset += 2
        offset += 4
        rdlength = int.from_bytes(response[offset:offset + 2], "big")
        offset += 2

        if rtype == 2:
            nsName, ofst = parseName(offset)
            nsList.append(nsName)

        offset += rdlength
        # print(rdata)


    # Parse additional records to find the first A record (IPv4)
    for _ in range(additionalCount):
        addName, offset = parseName(offset)
        rtype = int.from_bytes(response[offset:offset + 2], "big")
        offset += 2 
        offset += 2 
        offset += 4
        rdlength = int.from_bytes(response[offset:offset + 2], "big")
        offset += 2
        rdata = response[offset:offset + rdlength]
        offset += rdlength

        # Type 1 = A record (IPv4 address)
        if rtype == 1 and rdlength == 4:
            ip = '.'.join(str(b) for b in rdata)
            ipList.append(ip)
            nameServerIPMap[addName] = ip
            # return ip

    # print(domainList)

    return domainList, ipList, nsList, nameServerIPMap

#Used for displaying final output
def displayResponse(ipList, nsList, domainList, header, currentIP, map, foundAnswer):
    #to help visualize creation of function --DELETE LATER
    #print(header)

    #create variables
    answerCount = header.get("answerCount")
    authorityCount = header.get("authorityCount")
    additionalCount = header.get("additionalCount")
    nsCount = len(nsList)
    
    #printing phase
    print("----------------------------------------------------------------")
    print("DNS server to query: " + currentIP)
    print("Reply received. Content overview: ")
    print("\t" + str(answerCount) + " Answers.")
    print("\t" + str(nsCount) + " Intermediate Name Servers.")
    print("\t" + str(additionalCount) + " Additional Information Records.")
    
    #iterate through each answer record and print them in a list
    print("Answers section:")
    #TODO fix answer section
    # for i in range(len(domainList)):
        # print("\tName: " + domainList[i] + "\tIP: " + ipList[i])
    if foundAnswer:
        print("\tName: " + domainList[0] + "\tIP: " + ipList[0])
    
    #iterate through each authority record and print them in a list
    print("Authority Section:")
    for i in range(len(domainList)):
        if i >= len(domainList) or i >= len(nsList):
            break
        print("\tName: " + domainList[i] + "\tName Server: " + nsList[i])

    #iterate through each additional information record and print them in a list
    #print("Additional Information Section:")
    print("Additional Information Section:")
    for nameServer, ip in map.items():
        print("\tName: " + nameServer + " \tIP: " + ip)
        
    return

# -----------------------------------------------------------------------

def main():
    #If commandline did not receive 3 argument (filename, domain, ip) then notify user and exit program
    if len(sys.argv) != 3:
        print("Command to run file: python mydns.py <name of domain to search> <ip address>")
        sys.exit(1)

    #Socket so that recvfrom works
    clientSocket = socket(AF_INET, SOCK_DGRAM)

    #Second argument is domain
    domain = sys.argv[1]
    #Third argument is ip address
    ipaddr = sys.argv[2]

    currentIP = ipaddr
    foundAnswer = False


    while not foundAnswer:
        domainList = []
        nsList = []
        ipList = []
        nameServerIPMap = {}
        # Send query to the current DNS server
        # print("Query sent to:", currentIP)
        sendQuery(domain, currentIP, clientSocket)

        # Receive response from DNS server
        response = receiveResponse(clientSocket)

        # Decode the header of the response
        decodedResponse = decodeResponse(response)

        # print("Answer count:", decodedResponse["answerCount"])
        
        domainList, ipList, nsList, nameServerIPMap = extractNextDNSIP(response)

        nextIP = ipList[0]

        # print("Next DNS server:", nextIP)

        if decodedResponse["answerCount"] > 0:
            foundAnswer = True
            # print("Answer found!")

        displayResponse(ipList, nsList, domainList, decodedResponse, currentIP, nameServerIPMap, foundAnswer)

        # Update server to query next
        currentIP = nextIP

        # for i in domainList:
        #     print(i)

        # for k in nsList:
        #     print(k)
        
        # for j in ipList:
        #     print(j)

        # print(domainList)

        # If answer found, stop looping


        #divider
        #final message display


    sys.exit()  # Terminate the program

main()
