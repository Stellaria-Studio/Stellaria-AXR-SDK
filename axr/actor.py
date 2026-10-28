# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
"""Source-bound incoming inference. A visible parent chat is metadata routing only.

The provider is a fixed trusted registration whose completion API accepts no
executable tool definitions or caller-selected endpoints. Its credential and OS
isolation belong to the host. Unsupported provider isolation denies invocation.
"""
import json,time,uuid
from dataclasses import asdict
from .aet import AXRError,Action,Provenance,canonical,digest
from .outputs import validate_output
class IncomingActor:
    def __init__(self,authority,capability,principal,provider,*,verify_provider,clock=time.time):
        self.authority=authority;self.capability=capability;self.principal=principal;self.provider=provider
        self.verify_provider=verify_provider;self.clock=clock;self.context=None;self.used=False
    def infer(self,resource,records,*,contract,check,style=''):
        if self.used:raise AXRError('incoming_actor_context_already_consumed')
        body=contract.body()
        if body['mode']!='incoming' or body['trigger'] not in ('external-message','document') or body['agent']!=self.principal:raise AXRError('incoming_actor_contract_required')
        if resource.key not in body['resources'] or resource.key not in body['sources']:raise AXRError('incoming_actor_source_outside_contract')
        if self.clock()>=body['expires']:raise AXRError('incoming_actor_expired')
        if type(records) is not list or len(records)>6 or len(canonical(records))>24000:raise AXRError('incoming_actor_context_budget')
        sources=[]
        for row in records:
            if type(row) is not dict or set(row)-{'reference','text','data_class'} or not isinstance(row.get('text'),str):raise AXRError('incoming_actor_record_invalid')
            source=Provenance(resource,row['reference'],row.get('data_class','personal'))
            if source.data_class not in body['classes']:raise AXRError('incoming_actor_class_outside_contract')
            sources.append(source)
        if not isinstance(style,str) or len(style.encode())>4000:raise AXRError('incoming_actor_style_budget')
        if self.verify_provider(self.provider) is not True:raise AXRError('incoming_actor_provider_isolation_unqualified')
        destination=self.provider.destination
        if destination not in body['destinations']:raise AXRError('incoming_actor_destination_outside_contract')
        self.context=uuid.uuid4().hex
        request={'version':2,'context_id':self.context,'contract':body['id'],'records':records,'style':style,
                 'allowed_outputs':body['outputs'],'source_keys':[resource.key],'tools':[],'history':[],'parent_context':None}
        # The sealed action covers the exact snapshot, provider and fresh context.
        action=Action(self.principal,resource,'disclosure.send','incoming-inference',
                      {'request_digest':digest(request),'context_id':self.context},sources=tuple(sources),destination=destination)
        self.authority.request('Access',capability=self.capability,action=asdict(action))
        check();self.used=True
        proof=self.authority.request('Commit',capability=self.capability,action=asdict(action))
        # A fixed provider consumes a native claimed disclosure action before
        # transmission. The returned value is data; no tool execution loop exists.
        result=self.provider.complete(action,request,proof,check)
        check()
        value=validate_output(result,body)
        if any(source not in [resource.key] for source in value['sources']):raise AXRError('incoming_actor_cross_source_output')
        return {'context_id':self.context,'output':value,'source':resource.key,'parent_history_inherited':False,'tool_execution':False}
