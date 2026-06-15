#!/usr/bin/env python3
"""
生成 EtherCAT 抓包样本文件（原始二进制格式）
用于测试 ethercat-parser CLI 工具
运行: python samples/generate_sample.py samples/sample_capture.bin
"""
import struct
import sys
import os

ETHERCAT_ETHERTYPE = 0x88A4
AL_ERROR_CODE_REG = 0x0134

def build_ethercat_frame(slave_count: int, frame_index: int, inject_fault: bool) -> bytes:
    data = bytearray()
    eth_dest = bytes([0x01, 0x01, 0x05, 0x04, 0x00, 0x00])
    eth_src = bytes([0x08, 0x06, 0x07, 0x08, 0x09, 0x0a])
    data.extend(eth_dest)
    data.extend(eth_src)
    data.extend(struct.pack('>H', ETHERCAT_ETHERTYPE))
    datagrams = []
    for i in range(slave_count):
        sid = i + 1
        is_last = (i + 1 == slave_count)
        dg = bytearray()
        dg.append(0x0C)
        dg.append(i & 0xFF)
        dg.extend(struct.pack('<H', sid))
        inject = inject_fault and (frame_index % 37 == 23) and (sid == (frame_index % slave_count + 1))
        reg = AL_ERROR_CODE_REG if inject else 0x0010
        dg.extend(struct.pack('<H', reg))
        plen = 4 if inject else 12
        nflag = 0 if is_last else (1 << 15)
        lf = plen | nflag
        dg.extend(struct.pack('<H', lf))
        irq = 0x0001 if is_last else 0x0000
        dg.extend(struct.pack('<H', irq))
        if inject:
            fault_codes = [0x0011, 0x001A, 0x0027, 0x0030, 0x0017]
            code = fault_codes[frame_index % len(fault_codes)]
            dg.extend(struct.pack('<I', code))
        else:
            pos = (frame_index * 100 + sid * 50) & 0xFFFFFFFF
            dg.extend(struct.pack('<i', pos - 0x80000000 if pos >= 0x80000000 else pos))
            vel = ((frame_index % 1000) + sid * 10) & 0xFFFF
            dg.extend(struct.pack('<h', vel - 0x8000 if vel >= 0x8000 else vel))
            io_val = 0xFF00 | sid
            dg.extend(struct.pack('<H', io_val))
        wc = 1 + (frame_index + i) % 8
        dg.extend(struct.pack('<H', wc))
        datagrams.append(bytes(dg))
    total_len = sum(len(d) for d in datagrams)
    ec = bytearray(4)
    ec_len = total_len & 0x07FF
    ec[0] = ec_len & 0xFF
    ec[1] = (ec_len >> 8) & 0x07
    ec[2] = 0
    ec[3] = slave_count & 0x7F
    data.extend(ec)
    for d in datagrams:
        data.extend(d)
    return bytes(data)

def main():
    output_path = sys.argv[1] if len(sys.argv) > 1 else 'samples/sample_capture.bin'
    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
    num_frames = 200
    num_slaves = 5
    include_faults = True
    base_ts = 1_700_000_000_000_000_000
    with open(output_path, 'wb') as f:
        for idx in range(num_frames):
            inject = include_faults
            frame = build_ethercat_frame(num_slaves, idx, inject)
            f.write(struct.pack('<I', len(frame)))
            f.write(struct.pack('<Q', base_ts + idx * 1_000_000))
            f.write(frame)
    print(f'Generated {num_frames} frames for {num_slaves} slaves -> {output_path}')
    print(f'File size: {os.path.getsize(output_path)} bytes')

if __name__ == '__main__':
    main()
