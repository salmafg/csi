import binascii
import cmath
import json
import math
import struct
import subprocess as sub

import numpy as np
import pcapkit

# configuration
CHIP = '43455c0'
BW = 80
FILE = './out.pcap'
FOUT = 'out.json'
NPKTS_MAX = 20

# read file
HOFFSET = 16           # header offset
NFFT = BW*3.2          # fft size

extraction = pcapkit.extract(
    fin=FILE, fout=FOUT, layer='Link', extension=False)
n = min(NPKTS_MAX, len(extraction.frame))
# print('n:', n)


def fread(fid, nelements, dtype):
    if dtype is np.str:
        dt = np.uint8  # WARNING: assuming 8-bit ASCII for np.str!
    else:
        dt = dtype

    data_array = np.fromfile(fid, dt, nelements)
    # print(data_array)
    data_array.shape = (nelements, 1)

    return data_array

obj = {
        'fid': FILE,
        'global_header': {}
    }

fid = open(obj['fid'], 'rb')

# should be 0xA1B2C3D4
obj['global_header']['magic_number'] = fread(fid, 1, np.uint32)

# major version number
obj['global_header']['version_major'] = fread(fid, 1, np.uint16)

# minor version number
obj['global_header']['version_minor'] = fread(fid, 1, np.uint16)

# GMT to local correction
obj['global_header']['thiszone'] = fread(fid, 1, np.int32)

# accuracy of timestamps
obj['global_header']['sigfigs'] = fread(fid, 1, np.uint32)

# max length of captured packets, in octets
obj['global_header']['snaplen'] = fread(fid, 1, np.uint32)

# data link type
obj['global_header']['network'] = fread(fid, 1, np.uint32)

# print(obj['global_header'])

fid.seek(24, 0)

csi_buff = np.zeros([n, int(NFFT)], dtype=complex)

frames = json.loads(open(FOUT).read())

k = 0
while k < n:
    f = frames['Frame ' + str(k+1)]
    if f is None:
        print('no more frames')
        break

    if f['frame_info']['orig_len'] - (HOFFSET-1)*4 != NFFT*4:
        print('skipped frame with incorrect size')
        continue

    # packet data
    fread(fid, 4, np.uint32)
    if f['frame_info']['incl_len'] % 4 == 0:
        payload = fread(fid, int(f['frame_info']['incl_len']/4), np.uint32)
        # print(payload)
    else:
        payload = fread(fid, f['frame_info']['incl_len'], np.uint8)

    H = payload[HOFFSET-1:HOFFSET+int(NFFT)-1]
    if CHIP in ['4339', '43455c0']:
        Hout = H.view(np.int16)
    else:
        print('invalid CHIP')
        break

    cmplx = (Hout[0:int(NFFT), 0]).astype('double') + \
        1j * (Hout[0:int(NFFT), 1]).astype('double')
    # print(cmplx)
    csi_buff[k] = cmplx.T
    k += 1

print(csi_buff)
