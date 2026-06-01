import os
import shutil
from typing import Dict

import pyclamd

from .config import Settings


class ClamNotReadyError(Exception):
    pass


async def scan_file_and_maybe_quarantine(settings: Settings, stored_path: str, stored_filename: str) -> Dict[str, str]:
    if not settings.clamav_enabled():
        return {"infected": False, "skipped": True}

    try:
        cd = pyclamd.ClamdNetworkSocket(host=settings.CLAMD_HOST, port=settings.CLAMD_PORT, timeout=30)
        # ping to ensure it's ready
        if not cd.ping():
            raise ClamNotReadyError("clamd not responding")
    except Exception as e:
        raise ClamNotReadyError(str(e))

    result = cd.scan_file(stored_path)
    if result is None:
        # clean
        return {"infected": False}
    else:
        # Infected - move to quarantine
        qdir = "data/quarantine"
        os.makedirs(qdir, exist_ok=True)
        qpath = os.path.join(qdir, stored_filename)
        try:
            shutil.move(stored_path, qpath)
        except Exception:
            # If move fails, attempt copy+remove
            shutil.copy2(stored_path, qpath)
            os.remove(stored_path)
        return {"infected": True, "quarantine_path": qpath, "details": str(result)}


