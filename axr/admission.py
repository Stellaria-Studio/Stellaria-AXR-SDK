# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
"""AXR persistent admission budgets with fixed-window accounting.
"""
import hashlib
import time
from .aet import AXRError, digest


class Budget:
    def __init__(self, journal):
        self.journal=journal
        self.db=journal.db
        self.db.execute("CREATE TABLE IF NOT EXISTS throttle(key TEXT,window INTEGER,count INTEGER,PRIMARY KEY(key,window))")

    def reserve(self, identity, maximum, *, amount=1, seconds=86400):
        if any(type(v) is not int for v in (maximum,amount,seconds)) or maximum<0 or amount<1 or not 1<=seconds<=86400:
            raise AXRError("invalid_budget_reservation")
        now=int(self.journal.clock());window=now//seconds*seconds
        key=hashlib.sha256(identity.encode()).hexdigest()
        # Reject without incrementing when the reservation exceeds its ceiling.
        self.db.execute("BEGIN IMMEDIATE")
        try:
            self.db.execute("DELETE FROM throttle WHERE window<?",(now-86400*2,))
            row=self.db.execute("SELECT count FROM throttle WHERE key=? AND window=?",(key,window)).fetchone()
            if (row[0] if row else 0)+amount>maximum:
                raise AXRError("cost_or_call_budget_exhausted")
            self.db.execute("INSERT INTO throttle VALUES(?,?,?) ON CONFLICT(key,window) DO UPDATE SET count=count+excluded.count",
                            (key,window,amount))
            self.db.execute("COMMIT")
        except BaseException:
            self.db.execute("ROLLBACK")
            raise


class Admission:
    """Three independent switches; local filters never call a model."""
    def __init__(self, guard, journal, budget):
        self.guard,self.journal,self.budget=guard,journal,budget
        self.pending={}

    def evaluate(self, resource, events, policy, authorize, *, replay=False):
        if type(policy.get('all_incoming',False)) is not bool:
            raise AXRError('all_incoming_control_requires_boolean')
        decisions=[]
        if not policy.get("listen",False):
            return {"decisions":[],"model_calls":0,"state":"listener_off"}
        now=self.journal.clock()
        for event in events:
            reference=event["reference"]
            reason="workflow_match"
            if event.get("outgoing") is not False or not event.get("text") or not isinstance(event.get("created"),(int,float)):
                reason="not_incoming_text"
            elif not now-policy.get("event_ttl",900)<=event.get("created",0)<=now+10:
                reason="expired_or_future"
            elif policy.get("senders") and event.get("sender") not in policy["senders"]:
                reason="sender_not_in_workflow"
            elif not policy.get('all_incoming',False) and not any(k in event["text"] for k in policy.get("keywords",[])):
                reason="no_local_rule_match"
            elif not replay and self.journal.seen(resource,reference):
                reason="duplicate"
            if reason=="workflow_match":
                try:
                    authorize()
                except AXRError:
                    reason="authority_denied"
            wake=reason=="workflow_match" and policy.get("wake_agent",False)
            decision={"reference":reference,"reason":reason,"wake":wake,
                      "automatic_execution":bool(wake and policy.get("auto_execute",False)),
                      "workflow":policy.get("workflow","manual")}
            if not replay:
                self.journal.meter("events_seen")
                self.journal.meter("events_admitted" if wake else "events_filtered")
                if wake:
                    bucket=self.pending.setdefault(resource.key,[])
                    bounded={**event,"text":event["text"][:4000]}
                    if len(event["text"])>4000:bounded["text_truncated"]=True
                    bucket.append((now,bounded,decision))
                    del bucket[:-50]
            decisions.append(decision)
        return {"decisions":decisions,"model_calls":0,"simulation":replay}

    def drain(self, resource, policy, *, force=False):
        events=self.pending.get(resource.key,[])
        if not events or not policy.get("listen") or not policy.get("wake_agent"):
            self.pending.pop(resource.key,None)
            return []
        if not force and self.journal.clock()-events[-1][0]<policy.get("aggregate_seconds",3):
            return []
        # Bound aggregation memory and event age. A stopped/restarted listener never auto-replays.
        self.pending.pop(resource.key,None)
        return [e for at,e,d in events[-50:] if self.journal.clock()-at<policy.get("event_ttl",900)]

    def clear(self):
        self.pending.clear()
