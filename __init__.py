import base64
import hashlib

def euclide(b, m):
    a1,a2,a3 = 1, 0, m
    b1, b2, b3 = 0, 1, b
    q=0
    
    while( (b3 > 1)):
        # print(q,a1,a2,a3,b1,b2,b3)
        q = a3//b3
        t = b3
        b3 = a3%b3
        o1,o2 = a1, a2
        a1, a2, a3 = b1, b2, t
        b1 = o1 - q*b1
        b2 = o2 - q*b2
        if b3 == 0:
            gdc = a3
        elif b3 == 1:
            gdc = b2
    return (gdc)

def encrypt(m_raw, e, n, phi, d):
    c_list = []
    crypt=''
    for x in m_raw:
        c_list.append(pow(ord(x), e, n))
    for r in c_list:
        crypt += '' + chr(r)
    #encode
    encodedBytes = base64.b64encode(crypt.encode("utf-8"))
    mysign = str(encodedBytes, "utf-8")
    return mysign

def decrypt (c, d, n):
    m_list = []
    messages = ''
    decodedBytes = base64.b64decode(c.encode("utf-8"))
    mysign_raw = str(decodedBytes,"utf-8")
    mysign = list(mysign_raw)
    for m in mysign:
        m_list.append(pow(ord(m), d, n))
    for r in m_list:
        messages += '' + chr(r)
    return messages

def hash_file (path):
    file = path # Location of the file (can be set a different way)
    #BLOCK_SIZE = 65536 # The size of each read from the file
    file_hash = hashlib.sha1() # Create the hash object, can use something other than `.sha256()` if you wish
    with open(file, 'rb') as f: # Open the file to read it's bytes
        fb = f.read() # Read from the file. Take in the amount declared above
        while len(fb) > 0: # While there is still data being read from the file
            file_hash.update(fb) # Update the hash
            fb = f.read() # Read the next block from the file
    return file_hash.hexdigest()

def main():
    p, q = 79, 53 
    e = 71
    path = "E:\WindowsISO\Windows.Server.2003.iso"

    #counter
    n = p*q
    phi = (p-1)*(q-1)
    d = euclide(e, phi)
    if d < 0 : d = phi + d
    print("d: ", d)

    #Hash file
    hash_raw = hash_file(path)
    print("Hash file: ",hash_raw)
    m_raw = list(hash_raw)
    
    #Result
    c = encrypt(m_raw, e, n, phi, d)
    print("signature: ",c)
    print("---------------------------------")
    m = decrypt(c, d, n)
    print("verify: ",m)
if __name__ == "__main__":
    main()