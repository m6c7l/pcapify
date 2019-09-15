#!/bin/sh
'''which' python3 > /dev/null && exec python3 "$0" "$@" || exec python "$0" "$@"
'''

#
# Copyright (c) 2017, Manfred Constapel
# This file is licensed under the terms of the MIT license.
#

import os, datetime, time, argparse


def time_to_txt(value=None, millis=False):
    """ millis=False: 1500564304.533 -> 20170720-172504 """
    if value is not None:
        v = epoch_to_time(value)
    else:
        v = datetime.datetime.now()
    s = '%Y%m%d-%H%M%S'
    if millis: s += '-%f'
    return v.strftime(s)


def hex_to_dec(value):
    """ 'ff' -> 255 ; 'af fe' -> [175, 254] ; ('af', 'fe) -> [175, 254] """
    if type(value) in (list, tuple):
        return [hex_to_dec(item) for item in value]
    else:
        value = value.split(' ')
        if len(value) == 1:
            return int(str(value[0]), 16)
        else:
            return hex_to_dec(value)


def dec_to_hex(value, size=0):
    """ size=0: 12648430 -> ['c0', 'ff', 'ee'] ; (255, 255) -> ['ff', 'ff'] ; (256 * 256 - 1, 10) -> ['ff', 'ff', '0a'] """
    if type(value) in (list, tuple):
        return [item for sub in [dec_to_hex(item) for item in value] for item in sub]  # flatten
    else:
        s = '{:02x}'.format(value)
        s = '0' * (len(s) % 2) + s
        if size > 0:
            s = s.zfill(size * 2)[:size * 2]
        return chunk(s)


def dec_to_bit(value, bits=8):
    """ bits=8: 42 -> [False, True, False, True, False, True, False, False] """
    v = value % 2**bits
    seq = list(reversed(bin(v)[2:].zfill(bits)))
    seq = [True if c == '1' else False for c in seq]
    if value - v > 0:
        seq = seq + dec_to_bit(value // 2**bits)
    return seq


def val_to_dec(value, base=2):
    """ base=2: [False, False, False, False, False, False, False, True] -> 128 """
    res = 0
    for idx, val in enumerate(value):
        res += int(val) * base ** idx
    return res


def epoch_to_time(value):
    """ 1500564304.533 -> datetime(2017-07-20 17:25:04.533000) """
    return datetime.datetime.fromtimestamp(value)


def epoch(value=None):
    """ 2017-07-20 17:25:04.533000 -> 1500564304.533 ; 20170720172504533000 -> 1500564304.533 """
    if value is None:
        value = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    ofs = 1  # be compatible to windows
    strip = value.replace('-', '').replace(' ', '').replace(':', '')
    strip = strip.replace(',', '.').replace('.', '')
    form = '197001010' + str(ofs) + '0000' + '000000'
    strip = strip.ljust(len(form), '0')
    t = datetime.datetime.strptime(strip, '%Y%m%d%H%M%S%f')
    epoch = datetime.datetime.strptime(form, '%Y%m%d%H%M%S%f')
    return float((t - epoch).total_seconds()) - (60 * 60) * ofs


def swap(array, size=0):
    """ size=0: [2, 3, 5, 7, 11] -> [11, 7, 5, 3, 2] ; size=2: [2, 3, 5, 7, 11] -> [3, 2, 7, 5, 11] """
    if size == 0: size = len(array)
    a = [array[i:i + size] for i in range(0, len(array), size)]
    a = [item[::-1] for item in a]
    return [item for sublist in a for item in sublist]


def chunk(value, size=2):
    """ size=2: 'abcdefg' -> ['ab', 'cd', 'ef', 'gh'] """
    return [value[0 + i:size + i] for i in range(0, len(value), size)]


def pcap_version(value=(2, 4)):
    """ (2, 4) -> ['02', '00', '04', '00'] """
    major, minor = value
    return swap(dec_to_hex(major, 2) + dec_to_hex(minor, 2), 2)


def pcap_time_offset(value=0):
    """ 0 -> ['00', '00', '00', '00', '00', '00', '00', '00'] """
    return swap(dec_to_hex(value, 4)) + dec_to_hex(0, 4)


def pcap_frame_length(value=65535):
    """ 65535 -> ['ff', 'ff', '00', '00'] """
    return swap(dec_to_hex(value, 4))


def pcap_link_type(value):
    """ 230 -> ['e6', '00', '00', '00'] """
    return swap(dec_to_hex(value, 2)) + dec_to_hex(0, 2)


def pcap_timestamp(value):
    """ 1500564304.533 -> ['50', 'cb', '70', '59', '08', '22', '08', '00'] """
    pre = int(value)
    suf = int(round((value - pre) * 1000**2))
    return swap(dec_to_hex(pre, 4)) + swap(dec_to_hex(suf, 4))


def pcap_header(link_layer_id):
    magic_number = (212, 195, 178, 161)
    magic = [dec_to_hex(item)[0] for item in magic_number]
    res = bytes(hex_to_dec(magic))
    res += bytes(hex_to_dec(pcap_version()))
    res += bytes(hex_to_dec(pcap_time_offset()))
    res += bytes(hex_to_dec(pcap_frame_length()))
    res += bytes(hex_to_dec(pcap_link_type(link_layer_id)))
    return res


def pcap_data(line):
    t, data = extract_data(line)
    if t is None:
        return None, bytes([])
    ts, fr = pcap_timestamp(t), chunk(data, 2)
    tl = len(fr)
    fr = bytes(hex_to_dec(fr))
    fl = pcap_frame_length(len(fr))
    rec = bytes(hex_to_dec(ts))
    rec += bytes(hex_to_dec(fl))
    rec += bytes(hex_to_dec(fl))
    rec += fr
    return t, rec


def daintree_to_plain(line):
    elem = line.split(' ')
    if len(elem) != 12: return ''
    return '{} {}'.format(time_to_txt(float(elem[1]), True), elem[3][:-4])  # last two fields are ffff


def extract_data(line):
    if len(line) < 18 or line.count('\x00') > 0:
        return None, None
    line = line.replace('\r', '').replace('\n', '').replace(' *', '')
    if '[' in line and ']' in line:  # timestamp is human-readable datetime within brackets
        ts = line[line.index('[') + 1:line.index(']')]
        dat = line[line.index(']') + 1:]
        ts = epoch(ts)
    else:  # timestamp has to be epoch if brackets not found
        token = line.split(' ')
        if len(token) > 1: # delimiter found, try to find timestamp
            for tok in token:
                if len(tok) == 13 or (len(tok) == 14 and -1 < tok.find('.') < 13):
                    ts = tok.replace('.', '')
                    ts = ts[:10] + '.' + ts[10:]
                    break
            if len(token) > 2: # line has additional fields         
                idx = len(token)
                width = len(token[-1]) # length of last token
                for tok in token[::-1]:
                    if token[idx - 1] == '': # check for blank spaces in advance
                        idx += 1
                        break
                    if not (len(tok) == width): # 2 chars for byte or 4 chars for hex
                        break                        
                    idx -= 1
                if -1 < idx < len(token):       
                    dat = ''.join(token[idx:])
                else: # assume joined payload
                    dat = token[-1]                
            else:  # only two tokens, thus timestamp and payload
                dat = token[1]
        else: # no delimter found, timestamp to be at the beginning of line
            if -1 < line.find('.') < 13: 
                ts = line[:14]
                dat = line[14:]
            else:
                ts = line[:13]
                ts = ts[:10] + '.' + ts[10:]
                dat = line[13:]
    dat = dat.replace('0x', '').replace(' ', '').lower()
    return float(ts), dat


def convert(fn):
    if fn.lower().endswith('.dcf'): return lambda s : daintree_to_plain(s)
    if fn.lower().endswith('.isd'): raise NotImplementedError()
    if fn.lower().endswith('.psd'): raise NotImplementedError()
    return lambda s : s
    

def process(src, dst, period, link):

    def check(t, data):
        return data is not None and t is not None

    stamp = None
    if type(dst) == str:  # destination is file
        if period is None:  # no chunking
            out = open(os.path.join(os.path.dirname(dst), os.path.basename(dst)), 'wb', 0)
            out.write(pcap_header(link))
            for item in src:
                conv = convert(item)
                with open(item, 'r') as f:
                    for line in f:
                        t, data = pcap_data(conv(line))
                        res = check(t, data)
                        if res: out.write(data)
            out.close()
        else:  # chunk it
            out = None
            for item in src:
                conv = convert(item)
                with open(item, 'r') as f:
                    for line in f:
                        t, data = pcap_data(conv(line))
                        res = check(t, data)
                        if res:
                            if out is None:
                                stamp = t
                                out = open(os.path.join(os.path.dirname(dst), time_to_txt(t) + '_' + os.path.basename(dst)), 'wb', 0)
                                out.write(pcap_header(link))
                            if out is not None:
                                out.write(data)
                            if t > stamp + period:
                                out.close()
                                out = None
            if out is not None:
                out.close()
    elif type(dst) == list:  # destination is directory
        dst = dst[0]
        if period is None:  # no chunking
            for item in src:
                conv = convert(item)
                out = open(os.path.join(dst, '_' + os.path.basename(item) + '_' + '.pcap'), 'wb', 0)
                out.write(pcap_header(link))
                with open(item, 'r') as f:
                    for line in f:
                        t, data = pcap_data(conv(line))
                        res = check(t, data)
                        if res: out.write(data)
                out.close()
        else:  # chunk it
            out = None
            for item in src:
                conv = convert(item)
                with open(item, 'r') as f:
                    for line in f:
                        t, data = pcap_data(conv(line))
                        res = check(t, data)
                        if res:
                            if out is None:
                                stamp = t
                                out = open(os.path.join(dst, time_to_txt(t) + '_' + os.path.basename(item) + '_' + '.pcap'), 'wb', 0)
                                out.write(pcap_header(link))
                            if out is not None:
                                out.write(data)
                            if t > stamp + period:
                                out.close()
                                out = None
            if out is not None:
                out.close()


def main(src, dst, period, link):
    files = {}
    for item in src:
        conv = convert(item)
        found = 2  # max two attempts to find timestamp
        f = open(item, 'r')
        while found > 0:
            found -= 1
            s = f.readline()
            ts, _ = extract_data(conv(s))
            if ts is not None:
                files[ts] = item
                found = 0
        f.close()
    if len(files) == 0: return False
    process([files[file] for file in sorted(files)], dst, period, link)
    return True


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='pcapify converts IEEE 802.15.4 packet logs to PCAP files', epilog='', add_help=True,
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    gin = parser.add_mutually_exclusive_group(required=True)
    gin.add_argument('-id', '--input-directory', help='directory containing log files')
    gin.add_argument('-if', '--input-file', help='log file')

    gout = parser.add_mutually_exclusive_group(required=True)
    gout.add_argument('-od', '--output-directory', help='directory for storing PCAP files')
    gout.add_argument('-of', '--output-file', help='PCAP file')

    parser.add_argument('-fc', '--frame-check', action='store_true', help='frame check sequence captured (y/n)', default=None)    
    parser.add_argument('-cp', '--chunk-period', help='split PCAP files into chunks of seconds')

    args = parser.parse_args()

    # input
    inp = []
    if not args.input_directory is None and os.path.exists(args.input_directory) and not os.path.isfile(args.input_directory):
        for f in os.listdir(args.input_directory):
            if not os.path.isfile(os.path.join(args.input_directory, f)) or f == os.path.basename(__file__): continue
            inp.append(os.path.join(args.input_directory, f))
    elif not args.input_file is None and os.path.exists(args.input_file) and (os.path.isfile(args.input_file) or os.path.islink(args.input_file)):
        inp.append(args.input_file)

    if len(inp) == 0:
        print('no source specified', file=sys.stderr)
        exit(1)

    # output
    outp = None
    if not args.output_directory is None and os.path.exists(args.output_directory) and not os.path.isfile(args.output_directory):
        outp = [args.output_directory,]
    elif not args.output_file is None: # and (not os.path.exists(args.target_file) or os.path.islink(args.target_file)):
        outp = args.output_file

    if outp is None:
        print('no destination specified or destination is existent', file=sys.stderr)
        exit(1)

    # period
    period = None
    if args.chunk_period is not None:
        try:
            period = int(args.chunk_period)
        except ValueError as e:
            print(e, file=sys.stderr)
            exit(1)

    # link layer
    link = None    
    try:
        if args.frame_check is not None:
            link = 195  # 802.15.4 with FCS (c3)
        else:
            link = 230  # 802.15.4 without FCS (e6)
    except ValueError as e:
        print(e, file=sys.stderr)
        exit(1)

    if not main(inp, outp, period, link):
        print('no data found', file=sys.stderr)
        exit(1)
