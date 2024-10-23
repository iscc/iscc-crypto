# import rfc3161ng
#
# timestamper = rfc3161ng.RemoteTimestamper('https://rfc3161.ai.moda', hashname='sha256')
# tsr = timestamper(data=b'Example Data 2', return_tsr=True)
# print('{}'.format(tsr))
# print(len(str(tsr)))
import rfc3161ng
import base64
import gzip

# Configure timestamper to exclude certificates and use SHA-224
timestamper = rfc3161ng.RemoteTimestamper('https://rfc3161.ai.moda', hashname='sha256')
tsr = timestamper(data=b'Example Data 2', return_tsr=True)

# Get binary data of TSR
tsr_binary = tsr.dump()

# Compress the TSR binary data
compressed_tsr = gzip.compress(tsr_binary)

# Encode compressed data to Base64 for JSON
tsr_base64 = base64.b64encode(compressed_tsr).decode('ascii')

print(f"Compressed TSR size: {len(tsr_base64)} characters")

