"""Canonical NSL-KDD schema and attack taxonomy (including test-only attacks)."""
FEATURES = '''duration protocol_type service flag src_bytes dst_bytes land wrong_fragment urgent hot num_failed_logins logged_in num_compromised root_shell su_attempted num_root num_file_creations num_shells num_access_files num_outbound_cmds is_host_login is_guest_login count srv_count serror_rate srv_serror_rate rerror_rate srv_rerror_rate same_srv_rate diff_srv_rate srv_diff_host_rate dst_host_count dst_host_srv_count dst_host_same_srv_rate dst_host_diff_srv_rate dst_host_same_src_port_rate dst_host_srv_diff_host_rate dst_host_serror_rate dst_host_srv_serror_rate dst_host_rerror_rate dst_host_srv_rerror_rate'''.split()
CATEGORICAL = ['protocol_type', 'service', 'flag']
NUMERIC = [x for x in FEATURES if x not in CATEGORICAL]
RATES = [x for x in NUMERIC if x.endswith('_rate')]
BINARY_FLAGS = ['land', 'logged_in', 'root_shell', 'is_host_login', 'is_guest_login']
GROUPS = {
    'DoS': 'back land neptune pod smurf teardrop apache2 mailbomb processtable udpstorm',
    'Probe': 'ipsweep nmap portsweep satan mscan saint',
    'R2L': 'ftp_write guess_passwd imap multihop phf spy warezclient warezmaster sendmail named snmpgetattack snmpguess xlock xsnoop worm',
    'U2R': 'buffer_overflow loadmodule perl rootkit httptunnel ps sqlattack xterm',
}
ATTACK_MAP = {a: group for group, attacks in GROUPS.items() for a in attacks.split()}
ATTACK_MAP['normal'] = 'Normal'
CLASSES = ['Normal', 'DoS', 'Probe', 'R2L', 'U2R']
METADATA = ['source_ip', 'destination_ip', 'source_port', 'destination_port', 'protocol', 'timestamp']
SCHEMA_VERSION = 1
ADVICE = {
    'Normal': 'No anomaly predicted. Continue monitoring; a normal prediction does not guarantee safety.',
    'DoS': 'Inspect connection volume and service availability. Review rate limits with the administrator.',
    'Probe': 'Review repeated connection attempts and exposed services; investigate possible scanning.',
    'R2L': 'Review authentication logs, suspicious remote access, and account permissions.',
    'U2R': 'Investigate privilege escalation indicators and review affected host audit logs.',
}
