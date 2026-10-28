# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
"""Independent local owner control. Never registered as an MCP tool."""
import argparse
from contextlib import closing,contextmanager
import getpass
import json
import sys
import time
from dataclasses import asdict,replace
from pathlib import Path
from .aet import AXRError,Resource,Action,canonical
from .policy import OwnerStore
from .host import Supervisor,Lease

def authenticate(helper):
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise AXRError("owner_interactive_terminal_required")
    result=Supervisor(timeout=65).invoke([str(Path(helper).resolve(strict=True))],{"op":"owner_auth"})["result"]
    if not isinstance(result,dict) or result.get("verified") is not True or "error" in result:
        # Keep cancellation/unavailability distinct from expiry. Never forward
        # arbitrary helper descriptions, usernames or OS userInfo in an error.
        reason=result.get('error') if isinstance(result,dict) else None
        suffix=':'+reason if isinstance(reason,str) and reason in {'owner_auth_denied','owner_auth_unavailable','owner_auth_timed_out'} else ''
        code=result.get('os_error_code') if isinstance(result,dict) else None
        if suffix and type(code) is int and -100000<=code<=100000:suffix+=':os_error_'+str(code)
        raise AXRError('owner_os_authentication_failed'+suffix)

def review(store,jid,principal):
    action=store.journal.action(store.journal.get(jid,principal))
    result={"intent":asdict(action),"seal":action.seal}
    if action.operation=="disclosure.send" and "context_id" in action.payload:
        context=store.journal.context(action.payload["context_id"],principal,action.resource,store.guard.version)
        from .aet import digest
        if digest(context)!=action.payload.get("context_digest"):raise AXRError("context_intent_digest_changed")
        result["exact_disclosure"]=context
    return result

def approve(store,jid,principal):
    row=store.journal.get(jid,principal)
    if row["state"] not in {"AwaitingApproval","Ready"} or row["expires"]<=time.time():
        raise AXRError("job_not_approvable")
    action=store.journal.action(row)
    common=dict(principal=principal,purpose=action.purpose,expires_at=min(row["expires"],time.time()+240),
        max_uses=1,workflow=action.workflow)
    # Separate grants for disclosure of every source. Access grants remain independently required.
    for p in action.sources:
        if action.destination!="local":
            disclosure=replace(action,resource=p.resource,operation="disclosure.send",
                payload={"output_seal":action.seal},sources=(p,))
            store.guard._issue_owner(**common,resource=p.resource,operations=["disclosure.send"],
                destinations=[action.destination],classes=[p.data_class],intent=disclosure.seal)
    return store.guard._issue_owner(**common,resource=action.resource,operations=[action.operation],
        destinations=[action.destination],classes=sorted({p.data_class for p in action.sources}) or ["workspace-normal"],
        intent=action.seal)

@contextmanager
def upgrade_store(state):
    # Migration/recovery cannot run while an executor owns the same journal.
    # Acquire before opening or altering a legacy Guard database.
    directory=Path(state).resolve()
    with Lease(Path.home()/'.stellaria-axr'/'leases',['journal',str(directory)]):
        with closing(OwnerStore(directory,migrate_legacy=True,protected_audit=True)) as store:
            yield store

def main():
    parser=argparse.ArgumentParser(description="Local AXR owner control (never invoke through an agent tool)")
    parser.add_argument("--state",required=True);parser.add_argument("--helper",required=True)
    commands=parser.add_subparsers(dest="command",required=True)
    p=commands.add_parser("init");p.add_argument("--policy",required=True)
    p=commands.add_parser("configure");p.add_argument("--policy",required=True)
    p=commands.add_parser("grant");p.add_argument("--principal",required=True);p.add_argument("--platform",required=True)
    p.add_argument("--account",required=True);p.add_argument("--conversation",required=True)
    p.add_argument("--purpose",required=True);p.add_argument("--operation",action="append",required=True)
    p.add_argument("--workflow",default="manual");p.add_argument("--ttl",type=int,default=3600);p.add_argument("--uses",type=int,default=100)
    p.add_argument("--class",dest="classes",action="append",choices=["workspace-normal","personal"],
                   help="Explicit local data classes; sensitive classes require exact job approval")
    p=commands.add_parser("approve");p.add_argument("job");p.add_argument("--principal",required=True)
    p=commands.add_parser("revoke");p.add_argument("grant")
    p=commands.add_parser("secret");p.add_argument("reference")
    commands.add_parser("dashboard")
    commands.add_parser("upgrade-security",help="Authenticate, revoke legacy authority and initialize protected audit")
    args=parser.parse_args()
    try:
        if args.command=="dashboard":
            store=OwnerStore(args.state)
            try:print(json.dumps({"metrics":store.journal.metrics(),"audit_valid":store.journal.verify_audit(),"policy_version":store.guard.version},indent=2))
            finally:store.close()
            return
        if not sys.stdin.isatty() or not sys.stdout.isatty():raise AXRError("owner_interactive_terminal_required")
        policy=None
        if args.command in {"init","configure"}:
            policy=json.loads(Path(args.policy).read_bytes());print(json.dumps(policy,ensure_ascii=True,indent=2))
        elif args.command=="grant":
            print(json.dumps(vars(args),ensure_ascii=True,indent=2))
        elif args.command=="approve":
            # Read exact encrypted intent before invoking trusted OS authentication.
            store=OwnerStore(args.state)
            try:print(json.dumps(review(store,args.job,args.principal),ensure_ascii=True,indent=2))
            finally:store.close()
        print("Review the operation above. Owner authentication will authorize precisely this operation.")
        authenticate(args.helper)
        scope=upgrade_store(args.state) if args.command=="upgrade-security" else closing(OwnerStore(args.state,provision=args.command=="init"))
        with scope as store:
            if args.command=='upgrade-security':
                if not store.journal.verify_audit(check_checkpoint=False):raise AXRError('journal_audit_integrity_failed')
                if store.journal.checkpoint.read() is not None and not store.journal.verify_audit():raise AXRError('journal_audit_integrity_failed')
                store.guard.revoke_owner('security-upgrade')
                store.journal.recover();store.journal.purge()
                store.journal.security_event('owner-security-upgrade',{'policy_version':store.guard.version,'authority_restored':False})
                store.journal.checkpoint.anchor(store.journal.db,initialize=True)
                result={'upgraded':True,'authority_restored':False,'release_qualified':False}
            elif args.command in {"init","configure"}:
                # Changing controls revokes all prior capabilities and cached contexts.
                if args.command=="configure":store.guard.revoke_owner("policy-change")
                store.seal_config(policy);result={"configured":True}
            elif args.command=="grant":
                result={"grant_id":store.guard._issue_owner(principal=args.principal,
                    resource=Resource(args.platform,args.account,args.conversation),operations=args.operation,
                    purpose=args.purpose,expires_at=time.time()+args.ttl,max_uses=args.uses,workflow=args.workflow,
                    classes=args.classes or ["workspace-normal"])}
            elif args.command=="approve":result={"grant_id":approve(store,args.job,args.principal)}
            elif args.command=="revoke":store.guard.revoke_owner(args.grant);result={"revoked":True}
            else:
                value=getpass.getpass("Local secret (not echoed): ")
                # SQLCipher keys: validate locally, never echo or accept through argv.
                if len(value)!=64 or any(c not in "0123456789abcdefABCDEF" for c in value):raise AXRError("expected_32_byte_hex_key")
                store.secrets.provision(args.reference,bytes.fromhex(value));result={"stored":True}
            print(json.dumps(result))
    except AXRError as exc:parser.exit(1,str(exc)+"\n")
if __name__=="__main__":main()
