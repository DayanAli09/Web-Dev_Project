"""
This file turns 'views' from a single file into a package (folder).
It re-exports each tool's view function, so urls.py can keep saying
`views.home`, `views.phishing_detector`, etc. without any changes —
even though the code now lives in separate files.
"""
from .home import home
from .phishing import phishing_detector
from .encryptor import file_encryptor
from .scanner import port_scanner, start_scan, scan_status
