# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
"""Typed model output is data. ActionProposal/DataRequest never grant authority."""
from .aet import AXRError,canonical

KINDS={'Summary','ReplyDraft','ActionProposal','DataRequest','SafeContent'}
def validate_output(value,contract,*,maximum=24000):
    if type(value) is not dict or set(value)!={'kind','content','sources'}:raise AXRError('typed_output_required')
    if value['kind'] not in KINDS or value['kind'] not in contract['outputs']:raise AXRError('output_kind_outside_task_contract')
    if type(value['content']) is not str or len(value['content'].encode())>maximum:raise AXRError('output_content_budget')
    if type(value['sources']) is not list or len(value['sources'])>64 or any(type(s) is not str or s not in contract['sources'] for s in value['sources']):raise AXRError('output_provenance_outside_task_contract')
    # An actor cannot inject tool calls, owner approvals or executable callbacks.
    canonical(value)
    return value
