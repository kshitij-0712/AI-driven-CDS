import json
import os
import gzip
import binascii

from utils.paths import ensure_dir


def _smart_open(path):
    if path.endswith('.gz'):
        return gzip.open(path, 'rt', encoding='utf-8', errors='ignore')
    return open(path, 'r', encoding='utf-8', errors='ignore')


def ingest_cowrie(input_dir, output_path):
    ensure_dir(os.path.dirname(output_path))
    count = 0
    for filename in os.listdir(input_dir):
        if not filename.startswith("cowrie.json"):
            continue
        full_path = os.path.join(input_dir, filename)
        try:
            with open(full_path, 'r', encoding='utf-8') as infile:
                for line in infile:
                    try:
                        data = json.loads(line)
                        data['sensor_source'] = 'cowrie'
                        with open(output_path, 'a') as outfile:
                            outfile.write(json.dumps(data) + "\n")
                        count += 1
                    except Exception:
                        continue
        except Exception:
            continue
    return count


def ingest_zeek(input_dirs, output_path, target_logs):
    ensure_dir(os.path.dirname(output_path))
    count = 0
    with open(output_path, 'w') as outfile:
        for input_dir in input_dirs:
            if not os.path.exists(input_dir):
                continue
            for root, _, files in os.walk(input_dir):
                for filename in files:
                    log_type = None
                    for t in target_logs:
                        if filename.startswith(t + ".") or filename == f"{t}.log":
                            log_type = t
                            break
                    if not log_type:
                        continue
                    full_path = os.path.join(root, filename)
                    try:
                        headers = []
                        with _smart_open(full_path) as infile:
                            for line in infile:
                                if line.startswith('#fields'):
                                    headers = line.strip().split('\t')[1:]
                                    continue
                                if line.startswith('#'):
                                    continue
                                fields = line.strip().split('\t')
                                if len(fields) == len(headers):
                                    entry = dict(zip(headers, fields))
                                    entry['sensor_source'] = 'zeek'
                                    entry['log_type'] = log_type
                                    entry['is_live_spool'] = "spool" in input_dir
                                    entry['original_file'] = filename
                                    outfile.write(json.dumps(entry) + "\n")
                                    count += 1
                    except Exception:
                        continue
    return count


def ingest_dionaea_bistreams(input_dir, output_path):
    ensure_dir(os.path.dirname(output_path))
    count = 0
    with open(output_path, 'w') as outfile:
        for root, _, files in os.walk(input_dir):
            for filename in files:
                full_path = os.path.join(root, filename)
                try:
                    with open(full_path, 'rb') as infile:
                        raw_bytes = infile.read()
                        hex_payload = binascii.hexlify(raw_bytes).decode('utf-8')
                        try:
                            ascii_preview = raw_bytes.decode('utf-8', errors='ignore')
                        except Exception:
                            ascii_preview = "BINARY_DATA"
                        entry = {
                            "filename": filename,
                            "original_path": full_path,
                            "size_bytes": len(raw_bytes),
                            "hex_payload": hex_payload,
                            "ascii_preview": ascii_preview,
                            "sensor_source": "dionaea_bistream"
                        }
                        outfile.write(json.dumps(entry) + "\n")
                        count += 1
                except Exception:
                    continue
    return count
