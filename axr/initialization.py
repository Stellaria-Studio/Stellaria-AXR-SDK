# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
"""Recognize an interrupted EMPTY first setup, never an old permission store.

This preliminary filesystem/SQLite check cannot authorize recovery. The trusted
initializer additionally verifies the native protected audit anchor and the
Root-MAC receipt of the original hardware owner approval. An unchanged approved
transaction can continue without asking the owner to authenticate again.
"""
from pathlib import Path
import sqlite3
from .aet import AXRError

def empty_initialization(directory):
    root=Path(directory)
    if not root.exists() or not any(root.iterdir()):return True
    allowed={name+suffix for name in ('guard.sqlite3','journal.sqlite3') for suffix in ('','-wal','-shm')}
    allowed.add('policy.sealed.json') # A MAC-protected setup receipt, not execution authority.
    if root.is_symlink() or any(p.is_symlink() or p.name not in allowed for p in root.iterdir()):return False
    try:
        for filename,expected in [('guard.sqlite3',{'policy':1,'grants':0,'security_meta':1}),
                ('journal.sqlite3',{k:0 for k in ('jobs','contexts','events','telemetry','audit_records','results','disclosed_scopes','execution_claims')})]:
            connection=sqlite3.connect((root/filename).resolve().as_uri()+'?mode=ro',uri=True)
            try:
                tables={r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if tables!=set(expected):return False
                for name,count in expected.items():
                    if connection.execute('SELECT count(*) FROM '+name).fetchone()[0]!=count:return False
            finally:connection.close()
        return True
    except (OSError,sqlite3.Error):return False
