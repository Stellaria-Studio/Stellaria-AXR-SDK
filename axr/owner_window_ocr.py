# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
"""Local owner-only window qualification; never register this command in MCP.

The native picker captures only the exact window sealed in this action. Window
selection qualifies local inspection, not platform account identity or a send.
Only counts leave this command; OCR text is an encrypted, short-lived result.
"""
import argparse
import json
import os
import stat
import sys
import time
from dataclasses import asdict
from pathlib import Path

from .aet import Action, AXRError, Provenance, Resource, digest
from .host import Lease, Supervisor
from .owner import authenticate
from .policy import OwnerStore
from .runtime import Runtime


def validate_request(value):
    if not isinstance(value, dict) or set(value) != {'resource', 'visual_binding'}:
        raise AXRError('owner_window_request_invalid')
    resource = Resource(**value['resource'])
    binding = value['visual_binding']
    if not isinstance(binding, dict) or set(binding) != {'bundle', 'pid', 'window_id', 'title', 'bounds'}:
        raise AXRError('owner_window_binding_invalid')
    if any(type(binding[k]) is not int or binding[k] <= 0 for k in ('pid', 'window_id')):
        raise AXRError('owner_window_epoch_required')
    if binding['window_id'] > 2**32-1:
        raise AXRError('owner_window_epoch_required')
    from .aet import canonical, identifier
    identifier(binding['bundle']); identifier(binding['title'])
    bounds = binding['bounds']
    if not isinstance(bounds, list) or len(bounds) != 4 or any(type(v) not in (int, float) for v in bounds):
        raise AXRError('owner_window_bounds_invalid')
    canonical(binding)  # Reject non-finite JSON and oversized/invalid strings.
    if not 100 <= bounds[2] <= 4096 or not 100 <= bounds[3] <= 4096:
        raise AXRError('owner_window_bounds_invalid')
    return resource, binding


def read_private_request(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > 16384
                or before.st_mode & 0o077 or before.st_uid != os.getuid()):
            raise AXRError('owner_private_request_required')
        data = os.read(descriptor, 16385)
        after = os.fstat(descriptor)
        if (len(data) != before.st_size or before.st_size != after.st_size
                or before.st_mtime_ns != after.st_mtime_ns or before.st_ctime_ns != after.st_ctime_ns):
            raise AXRError('owner_private_request_changed')
        return validate_request(json.loads(data))
    finally:
        os.close(descriptor)


def capture(store, picker, resource, binding, *, synthetic_control=False):
    if synthetic_control and (resource != Resource('fixture', 'fixture-account', 'fixture-chat')
            or binding['bundle'] != 'dev.axr.input-fixture'
            or binding['title'] != 'AXR synthetic input fixture'):
        raise AXRError('synthetic_fixture_scope_required')
    lifetime = 299 if synthetic_control else 240
    principal = 'owner:window-ocr-qualification'
    action = Action(principal, resource, 'messages.read', 'owner-window-ocr-qualification',
                    {'visual_binding': binding}, (Provenance(resource, digest(binding), 'personal'),))
    supervisor = Supervisor(timeout=280 if synthetic_control else 200)
    stats = {}

    def handler(current, check, epoch):
        check()
        try:
            result = supervisor.invoke([picker, '--read-ocr-fixture' if synthetic_control else '--read-ocr'],
                {'resource': asdict(current.resource), 'visual_binding': current.payload['visual_binding'],
                 'guard_context': check.commit_proof()})['result']
        except AXRError as exc:
            stats.update(error=str(exc))
            raise
        check()
        if result.get('verified') is not True:
            stats.update(error=result.get('reason', 'owner_capture_unverified'))
            if type(result.get('system_error_code')) is int:
                stats['system_error_code'] = result['system_error_code']
            return {'epoch': epoch, 'verified': False}
        if result.get('images_persisted') is not False or result.get('network_used') is not False:
            raise AXRError('owner_capture_privacy_unverified')
        lines = result.get('lines')
        if not isinstance(lines, list) or len(lines) > 100:
            raise AXRError('owner_capture_result_invalid')
        stats.update(frame_received=result.get('frame_received') is True,
                     ocr_lines=len(lines), ocr_bytes=sum(len(x['text'].encode('utf-8')) for x in lines),
                     foreground=result.get('foreground'), width=result.get('width'), height=result.get('height'),
                     frame_has_variation=result.get('frame_has_variation'),
                     frame_luma_min=result.get('frame_luma_min'), frame_luma_max=result.get('frame_luma_max'),
                     opaque_samples=result.get('opaque_samples'),
                     identity_assurance=result.get('identity_assurance'))
        if stats['frame_received'] is not True or stats['frame_has_variation'] is not True:
            stats.update(error='frame_content_unavailable')
            return {'epoch': epoch, 'verified': False}
        return {'epoch': epoch, 'verified': True, 'output': result, 'evidence_digest': digest(stats)}

    runtime = Runtime(store.guard, store.journal, store.directory/'window-qualification-leases',
                      {'messages.read': handler})
    grant = store.guard._issue_owner(principal=principal, resource=resource, operations=['messages.read'],
        purpose=action.purpose, expires_at=time.time()+lifetime, max_uses=1, workflow=action.workflow,
        classes=['personal'], intent=action.seal)
    try:
        receipt = runtime.propose(action, ttl=lifetime)
        result = runtime.execute(receipt['id'], principal)
        return {'state': result['state'], **stats, 'audit_valid': store.journal.verify_audit(),
                'images_persisted': False, 'body_disclosed': False, 'send_available': False}
    finally:
        try:
            supervisor.cancel()
        finally:
            try:
                store.guard.revoke_owner(grant)
            finally:
                # Remove bodies even if revocation storage fails. Such an error
                # propagates; do not report a successful cleanup or read.
                store.journal.db.execute('UPDATE results SET payload=NULL,expires=0 WHERE principal=?', (principal,))
                store.journal.purge()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', required=True)
    parser.add_argument('--helper', required=True)
    parser.add_argument('--picker', required=True)
    parser.add_argument('--request', required=True)
    args = parser.parse_args()
    try:
        if sys.platform != 'darwin' or not sys.stdin.isatty() or not sys.stdout.isatty():
            raise AXRError('owner_interactive_mac_terminal_required')
        resource, binding = read_private_request(args.request)
        picker = str(Path(args.picker).resolve(strict=True))
        print('Review locally: one exact owner-selected window, one frame, local OCR only; '
              'no image files, model disclosure, send or listener permission.', flush=True)
        # Display the exact scope only in the trusted owner's terminal, never
        # print the account ID or OCR text to an agent-facing result.
        print('window_id=' + str(binding['window_id']) + '; pid=' + str(binding['pid']), flush=True)
        authenticate(args.helper)
        store = OwnerStore(args.state)
        try:
            with Lease(store.directory/'window-owner-leases', 'owner-window-qualification'):
                result = capture(store, picker, resource, binding)
                print(json.dumps(result), flush=True)
                if result['state'] != 'Completed' or result['audit_valid'] is not True:
                    raise SystemExit(1)
        finally:
            store.close()
    except (AXRError, ValueError, OSError, TypeError, KeyError):
        parser.exit(1, 'owner_window_qualification_failed\n')


if __name__ == '__main__':
    main()
