import socket
import sys
import struct

DEFAULT_PORT = 53
DEFAULT_ID = 100
A_TYPECODE = b'\x00\x01'
NS_TYPECODE = b'\x00\x02'
CNAME_TYPECODE = b'\x00\x05'
MX_TYPECODE = b'\x00\x0f'

# TODO: Remove this, it's a bandaid covering up question not handling this case
USE_MX = False
USE_NS = False

def usage():
    print("Usage: python ./351dns @<server[:port]> <name>")

def header():
    # init header
    header = bytearray()

    # ID field
    header += struct.pack("!H", DEFAULT_ID)
    
    qr = '0'
    Opcode = '0000'
    AA = '0'
    TC = '0'
    RD = '1'
    RA = '0'
    Z  = '000'
    RCODE = '0000'
    header += bytearray([int(qr + Opcode + AA + TC + RD, 2), int(RA + Z + RCODE, 2)])

    QDCOUNT = 1
    header += struct.pack("!H", QDCOUNT)

    ANCOUNT = 0

    header += struct.pack("!H", ANCOUNT)

    NSCOUNT = 0
    header += struct.pack("!H", NSCOUNT)

    ARCOUNT = 0 
    header += struct.pack("!H", ARCOUNT)


    return header


def question(name):
    nArray = bytearray()
    nameArray = name.split(".")
    for name in nameArray:
        l = bytearray([len(name)])
        s = bytearray(name, 'utf-8')
        nArray += l + s

    if USE_MX:
        nArray += bytearray.fromhex("00000f0001")
    elif USE_NS:
        nArray += bytearray.fromhex("0000020001")
    else:
        nArray += bytearray.fromhex("0000010001")
    return nArray


def parseRecords(data, questionLength, headerInfo):
    """
    Parses the records in a DNS query response and prints out summaries
    according to project instructions.
    :param data: bytes object form of a DNS query response
    :param questionLength: length of the original question
    :return: None
    """
    pos = questionLength
    while pos < len(data):
        name = data[pos:pos+2]
        type = data[pos+2:pos+4]
        DNSClass = data[pos+4:pos+6]
        timeToLive = data[pos+6:pos+10]
        dataLength = data[pos+10:pos+12]
        nameSize = struct.unpack(">H", dataLength)[0]


        if type == A_TYPECODE:
            endName = pos + 12 + nameSize
            nameBytes = data[pos + 12:endName]
            IP = str(nameBytes[0]) + "." \
                 + str(nameBytes[1]) + "."\
                 + str(nameBytes[2]) + "."\
                 + str(nameBytes[3])
            print("\tIP\t", IP, "\t" + "PLACEHOLDER", sep="")
        elif type == CNAME_TYPECODE:
            name = parseName(data, pos+10)

            print("\tCNAME\t", name, "\t" + "PLACEHOLDER", sep="")
        elif type == NS_TYPECODE:
            print("Found NS")
        elif type == MX_TYPECODE:
            preference = data[pos+12] + data[pos+13]
            name = parseMailServer(data, pos+10)
            print("MX\t", name, "\t", preference, "\t", "PLACEHOLDER")

        pos += 12 + nameSize
        continue


def parseLabel(data, startPos):
    """
    Parses the label-reference part of a domain name, beginning at the label's
    destination (startPos) in data.
    :param data: bytes object form of a DNS query response
    :param startPos:
    :return:
    """
    strRep = ""
    wordSize = 1
    namePos = startPos
    while wordSize != 0:
        wordSize = data[namePos]
        namePos += 1
        wordBytes = data[namePos: namePos + wordSize]
        # situation to recursively call on another label; no new function needed
        if wordSize >= 192:
            offset = data[namePos] + data[namePos + 1] - 192
            namePos += 1
            word = parseLabel(data, offset)
            strRep += word

            # label always marks the end
            break

        if wordSize > 0:
            strRep += wordBytes.decode("ascii") + "."
        namePos += len(wordBytes)

    return strRep


def parseName(data, startPos):
    """
    Parses the domain name present in data beginning at startPos with its length

    Will probably throw an error if something is badly formatted.
    :param data: bytes object form of a DNS query response
    :param startPos: beginning of the name to parse
    :return:
    """
    nameSize = struct.unpack(">H", data[startPos:startPos+2])[0]
    startPos += 2
    endName = startPos + nameSize
    nameBytes = data[startPos:endName]
    strRep = ""

    namePos = 0
    while namePos < len(nameBytes):
        wordSize = nameBytes[namePos]

        # in compression, if label is used to save space it is guaranteed to
        # start with 11; this checks if the first byte of the name is a label
        if wordSize >= 192:
            offset = nameBytes[namePos] + nameBytes[namePos + 1] - 192
            namePos += 2
            word = parseLabel(data, offset)
            strRep += word

        else:
            namePos += 1
            wordBytes = nameBytes[namePos:namePos + wordSize]
            strRep += wordBytes.decode("ascii") + "."
            namePos += len(wordBytes)
    return strRep


def parseMailServer(data, startPos):
    """
    Slightly different variant of ParseName which accounts for the first 2 bytes
    being the preference field. Otherwise identical, but a call to parseName
    won't work for these packet types.
    :param data:
    :param startPos:
    :return:
    """
    cursor = startPos
    nameSize = struct.unpack(">H", data[cursor:cursor + 2])[0]
    cursor += 2

    # whole bunch of 2-shifts here because first 2 bytes of MX are preference
    # preference is not returned and instead calculated separately
    preference = struct.unpack(">H", data[cursor:cursor + 2])[0]
    endName = cursor + nameSize
    cursor += 2
    nameBytes = data[cursor:endName]
    strRep = ""

    while cursor < endName:
        wordSize = data[cursor]

        # in compression, if label is used to save space it is guaranteed to
        # start with 11; this checks if the first byte of the name is a label
        if wordSize >= 192:
            offset = data[cursor] + data[cursor + 1] - 192
            cursor += 2
            word = parseLabel(data, offset)
            strRep += word

        else:
            offset = cursor
            word = parseLabel(data, offset)
            cursor += len(word)
            strRep += word
    return strRep

def dump_packet(buffer, size):
    """
    prints a dump of the packet's contents in traditional hex-byte style
    :param buffer: buffer to dump
    :param size: size of the buffer
    :return:
    """
    byteCount = 0

    # line of ascii for the end is generated along with the main output, but
    # only appended at the end of the line
    lineAscii = ""
    output = ""
    for byte in buffer:
        if byteCount % 16 == 0:
            output += "\t" + lineAscii
            output += "\n|{:04x}|\t".format(byteCount)
            lineAscii = ""
        elif byteCount % 16 == 8:
            output += "\t"

        # appends 2-hex byte format to output
        # the [0] makes it work don't ask
        output += "{:02X}".format(byte) + " "

        # formats byte as ascii char and adds it to the line's ascii
        if 65 <= byte <= 122:
            lineAscii += "{:c}".format(byte)
        else:
            lineAscii += "."
        byteCount += 1

    if byteCount < 8:
        output += "\t"
    for i in range(0, 16 - (byteCount % 16)):
        output += "   "
    output += "\t" + lineAscii + "\n"

    # Filling out the last line with empty space and appending the ascii
    print(output)

def parseHeader(data):
    try:
        flagsB1 = struct.unpack("!B", data[2:3])[0]
    except Exception as e:
        raise Exception("Malformed Packet")

    QR = (int('10000000',2) & flagsB1) >> 7
    if QR != 1:
        raise Exception("Malformed Packet")
    
    Opcode = (int('01111000',2) & flagsB1) >> 3
    if Opcode != 0:
        raise Exception("Response not of expected type")

    AA = (int('00000100',2) & flagsB1) >> 2
    isAuthoritative = AA == 1

    TC = (int('00000010',2) & flagsB1) >> 1
    isTruncated = TC == 1

    RD = int('00000001',2) & flagsB1
    if RD != 1:
        raise Exception("Recursion desired value does not match")
    try:
        flagsB2 = struct.unpack("!B", data[3:4])[0]
    except Exception as e:
        raise Exception("Packet not long enough")

    RA = (int('10000000',2) & flagsB2) >> 7
    if RA != 1:
        raise Exception("Server does not support recursion")

    Z = (int('01110000',2) & flagsB2) >> 4

    RCODE = int('00001111',2) & flagsB2
    if RCODE > 0: 
        raise Exception("Error Response")
    
    try:
        QDCOUNT = struct.unpack("!H", data[4:6])[0]
        ANCOUNT = struct.unpack("!H", data[6:8])[0]
        NSCOUNT = struct.unpack("!H", data[8:10])[0]
        ARCOUNT = struct.unpack("!H", data[10:12])[0]
    except Exception as e:
        raise Exception("Malformed Packet")

    return {
        'isTrunc': isTruncated,
        'isAuthoritative': isAuthoritative,
        'QuestionCount': QDCOUNT,
        'AnswerCount': ANCOUNT,
        'NameServerCount': NSCOUNT,
        'AdditionalRecordsCount': ARCOUNT
    }

def main():
    if len(sys.argv) < 3:
        usage()
        return
    
    serverport = sys.argv[1].strip("@").split(":")
    if len(serverport) == 1:
        server = serverport[0]
        port = DEFAULT_PORT
    elif len(serverport) == 2:
        server = serverport[0]
        port = int(serverport[1])
    else: 
        usage()
        return

    type = A_TYPECODE
    
    domainName = sys.argv[2]
    
    requestPacket = header() + question(domainName)
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (server, port)

    print("Sending packet of size: ", len(requestPacket), "\nContents:")
    dump_packet(requestPacket, len(requestPacket))

    sent = sock.sendto(requestPacket, server_address)

    while True:
        print("Waiting for DNS response...")
        data, server = sock.recvfrom(4096)
        if len(data) > 2:
            respID = struct.unpack("!H", data[0:2])[0]
            if respID == DEFAULT_ID:
                parseHeader(data)
                print("Received packet of size: ", len(data), "\nContents:")
                dump_packet(data, len(data))
                try:
                    res = parseHeader(data)
                except Exception as e:
                    print("ERROR    {}".format(e))

                print("With DNS records:")
                parseRecords(data, sent, res)
                
                break


    

if __name__ == "__main__":
    main()    
