import numpy as np

def encode_session_changes(changes: list) -> np.ndarray:
    """Encode a list of system changes into a 20-dim feature vector.
    changes: list of dicts, e.g., [{'type': 'file_write', 'path': '...', 'size': 123}]
    """
    vec = np.zeros(20, dtype=np.float32)
    if not changes:
        return vec
        
    # File writes (0-5)
    file_writes = [c for c in changes if c.get('type') == 'file_write']
    vec[0] = len(file_writes)
    vec[1] = max([c.get('size', 0) for c in file_writes], default=0) / 1e6
    vec[2] = max([c.get('entropy', 0) for c in file_writes], default=0)
    vec[3] = sum(1 for c in file_writes if 'executable' in c.get('path', ''))
    vec[4] = sum(1 for c in file_writes if any(x in c.get('path', '') for x in ['/etc/', '/root/', '/home/']))
    vec[5] = sum(1 for c in file_writes if c.get('entropy', 0) > 7.0)
    
    # Process execution (6-9)
    proc_execs = [c for c in changes if c.get('type') == 'process_exec']
    vec[6] = len(proc_execs)
    vec[7] = sum(1 for c in proc_execs if any(x in c.get('cmdline', '') for x in ['wget','curl','bash','sh','python']))
    vec[8] = sum(1 for c in proc_execs if 'sudo' in c.get('cmdline', '') or 'su ' in c.get('cmdline', ''))
    vec[9] = sum(1 for c in proc_execs if '/tmp/' in c.get('cmdline', '') or '/var/tmp/' in c.get('cmdline', ''))
    
    # Network connections (10-13)
    net_conns = [c for c in changes if c.get('type') == 'network_conn']
    vec[10] = len(net_conns)
    vec[11] = len(set(c.get('dst_ip', '') for c in net_conns))
    vec[12] = sum(1 for c in net_conns if c.get('dst_port') in [22, 80, 443, 4444, 8080, 6667])
    
    def is_external_ip(ip):
        return not (ip.startswith('10.') or ip.startswith('192.168.') or ip.startswith('172.'))
    
    vec[13] = sum(1 for c in net_conns if is_external_ip(c.get('dst_ip', '')))
    
    # User/account changes (14-16)
    user_changes = [c for c in changes if c.get('type') in ['user_add', 'ssh_key_add', 'passwd_change']]
    vec[14] = len(user_changes)
    vec[15] = sum(1 for c in user_changes if c.get('type') == 'ssh_key_add')
    vec[16] = sum(1 for c in user_changes if 'root' in c.get('username', '') or 'admin' in c.get('username', ''))
    
    # Scheduled tasks (17-19)
    cron_changes = [c for c in changes if c.get('type') in ['cron_add', 'systemd_add']]
    vec[17] = len(cron_changes)
    vec[18] = sum(1 for c in cron_changes if '@reboot' in c.get('schedule', ''))
    vec[19] = sum(1 for c in cron_changes if any(x in c.get('command', '') for x in ['wget','curl','bash','sh']))
    
    return vec
