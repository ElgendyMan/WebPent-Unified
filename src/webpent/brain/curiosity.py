"""webpent.brain.curiosity — U-13 S-3 The Curiosity Engine."""
from __future__ import annotations
import re, json, logging
from pathlib import Path
from typing import Any
from dataclasses import dataclass
from urllib.parse import parse_qs, urlsplit
_logger=logging.getLogger(__name__)
_CONFIG_PATH=Path(__file__).resolve().parents[2]/"config"/"curiosity_params.yaml"
# U-1/GAP-5 (restored TC-4 C1a): the in-tree defaults ARE the designed
# fallback when the optional config surface is absent — the engine must
# function without the config file or PyYAML.  Single SSOT for the fallback
# payload; both narrowed handlers below return it verbatim.
_CONFIG_DEFAULTS={"odd_params":["debug","admin","test","internal","secret","token","key","config","env","cmd","exec","file","path","url","redirect"],"shape_divergence_exclusions":["token","session","csrf","nonce","timestamp","request_id"]}
def _load_config():
    # U-1/GAP-5 (restored TC-4 C1a): the bare `except:` here returned in the
    # v14.1->v15 lineage (the minified re-emission predates the fix).  Narrowed
    # again with the justification: ONLY the three designed fallback conditions
    # may fall through to _CONFIG_DEFAULTS — PyYAML absent (ImportError), the
    # optional config file missing/unreadable (OSError), or malformed YAML
    # (yaml.YAMLError).  A bare except also swallows KeyboardInterrupt and
    # SystemExit — never acceptable in a brain module; anything outside the
    # three designed conditions must propagate to the caller.
    try:
        import yaml
    except ImportError:
        _logger.debug("curiosity: PyYAML unavailable — using in-tree defaults")
        return dict(_CONFIG_DEFAULTS)
    try:
        with open(_CONFIG_PATH) as f: return yaml.safe_load(f) or dict(_CONFIG_DEFAULTS)
    except (OSError, yaml.YAMLError) as _cfg_exc:
        # OSError: missing/unreadable optional config; yaml.YAMLError: malformed
        # optional config.  Both are the designed fallback, not error conditions.
        _logger.debug("curiosity: optional config unusable (%s) — using in-tree defaults", _cfg_exc)
        return dict(_CONFIG_DEFAULTS)
_CONFIG=_load_config()
ODD_PARAMS_SET=frozenset(_CONFIG.get("odd_params",[]))
SHAPE_EXCLUSIONS=frozenset(_CONFIG.get("shape_divergence_exclusions",[]))
@dataclass
class CuriositySignal:
    type:str; source:str; evidence:str; confidence:float; signal_id:str=""
    def to_dict(self): return {"type":self.type,"source":self.source,"evidence":self.evidence,"confidence":self.confidence,"signal_id":self.signal_id}
def extract_odd_params(request_url, body=None):
    signals=[]; parsed=urlsplit(request_url)
    for param_name in parse_qs(parsed.query):
        if param_name.lower() in ODD_PARAMS_SET:
            signals.append(CuriositySignal("odd_param",param_name,f"param={param_name}",0.3,f"odd_{param_name}_{len(signals)}"))
    if body and isinstance(body,dict):
        for key in body:
            if isinstance(key,str) and key.lower() in ODD_PARAMS_SET:
                signals.append(CuriositySignal("odd_param",key,f"param={key} in body",0.3,f"odd_{key}_{len(signals)}"))
    return signals
_STACK_PATTERNS=[("python",re.compile(r"Traceback|File \"[^\"]+\", line \d+|SyntaxError:|TypeError:|AttributeError:")),("java",re.compile(r"java\.lang\.|NullPointerException|SQLException")),("php",re.compile(r"Fatal error:|Warning:|Notice:|Deprecated:"))]
def extract_stack_traces(response_body):
    signals=[]
    for lang,pat in _STACK_PATTERNS:
        m=pat.search(response_body)
        if m: signals.append(CuriositySignal("stack_trace",lang,response_body[max(0,m.start()-100):m.end()+200][:500],0.7,f"stack_{lang}_{len(signals)}"))
    return signals
_DATA_IND=re.compile(r'"(id|name|email|token|user|role|permission|internal|private|password|secret|key)"\s*:',re.I)
def extract_data_behind_4xx(status_code,response_body):
    if status_code not in (403,404,405): return []
    signals=[]
    try:
        p=json.loads(response_body)
        if isinstance(p,dict) and len(p)>2: signals.append(CuriositySignal("data_behind_4xx",str(status_code),response_body[:500],0.6,f"data_{status_code}_{len(signals)}")); return signals
    except (TypeError, ValueError):
        # U-1/GAP-5 (restored TC-4 C1a): narrowed from bare `except:`.  A
        # non-JSON body is the EXPECTED input on this heuristic path — the
        # contract is "try JSON first, fall through to the body heuristics".
        # json.JSONDecodeError subclasses ValueError; TypeError covers non-
        # str/bytes payloads.  Parse failures are not error conditions;
        # anything else (KeyboardInterrupt, MemoryError, …) must propagate.
        pass
    if len(response_body)>200: signals.append(CuriositySignal("data_behind_4xx",str(status_code),response_body[:500],0.5,f"data_{status_code}_{len(signals)}"))
    if _DATA_IND.search(response_body): signals.append(CuriositySignal("data_behind_4xx",str(status_code),response_body[:500],0.6,f"data_{status_code}_{len(signals)}"))
    return signals
def _extract_json_fields(body):
    try:
        p=json.loads(body)
        if isinstance(p,dict): return {k for k in p if k.lower() not in SHAPE_EXCLUSIONS}
    except (TypeError, ValueError):
        # U-1/GAP-5 (restored TC-4 C1a): narrowed from bare `except:`.  The
        # shape-divergence contract treats a non-JSON body as an empty field
        # set — divergence is then computed against the other side.  Only
        # parse failures (TypeError/ValueError; JSONDecodeError is a ValueError
        # subclass) may take that path; everything else propagates.
        pass
    return set()
def extract_shape_divergence(endpoint,response_a,response_b):
    fa=_extract_json_fields(response_a); fb=_extract_json_fields(response_b)
    if not fa and not fb: return []
    if fa!=fb: return [CuriositySignal("shape_divergence",endpoint,f"diff={sorted(fa.symmetric_difference(fb))[:5]}",0.5,f"shape_{endpoint[:30]}")]
    return []
_VER_HEADERS=re.compile(r"^(Server|X-Powered-By|X-AspNet-Version|X-Runtime|X-Version|X-Build|X-Environment|X-Debug)$",re.I)
_IP=re.compile(r"\b(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d+\.\d+\b")
_COMMENT=re.compile(r"<!--.*?(?:TODO|FIXME|HACK|XXX|password=|secret=|key=).*?-->",re.I|re.DOTALL)
_JS_INT=re.compile(r"/api/(?:internal|admin|debug)/")
_KEYS=re.compile(r"(?:AKIA|AIza|sk-|ghp_)[A-Za-z0-9]{10,}")
def extract_header_comment_js(headers,body):
    signals=[]
    for k,v in headers.items():
        if _VER_HEADERS.match(k) and v.strip(): signals.append(CuriositySignal("header_comment_js",f"header:{k}",f"{k}: {v[:200]}",0.5,f"hdr_{k}_{len(signals)}"))
    for m in _COMMENT.finditer(body): signals.append(CuriositySignal("header_comment_js","html_comment",m.group()[:500],0.7,f"comment_{len(signals)}"))
    if _IP.search(body): signals.append(CuriositySignal("header_comment_js","internal_ip",_IP.search(body).group()[:200],0.8,f"ip_{len(signals)}"))
    if _JS_INT.search(body): signals.append(CuriositySignal("header_comment_js","js_internal",_JS_INT.search(body).group()[:200],0.6,f"js_{len(signals)}"))
    if _KEYS.search(body): signals.append(CuriositySignal("header_comment_js","hardcoded_key","key detected (redacted)",0.8,f"key_{len(signals)}"))
    return signals
class CuriosityEngine:
    def __init__(self): self._signals=[]
    def extract_all(self,*,request_url="",body=None,response_body="",status_code=200,headers=None,endpoint="",response_a="",response_b=""):
        all_s=[]
        if request_url: all_s.extend(extract_odd_params(request_url,body))
        if response_body: all_s.extend(extract_stack_traces(response_body))
        all_s.extend(extract_data_behind_4xx(status_code,response_body))
        if endpoint and response_a and response_b: all_s.extend(extract_shape_divergence(endpoint,response_a,response_b))
        if headers: all_s.extend(extract_header_comment_js(headers,response_body))
        self._signals.extend(all_s); return all_s
    def get_signals(self): return list(self._signals)
    def clear(self): self._signals.clear()
VALID_PROVENANCE=frozenset({"signal","family_prior","lesson","planner_initiative"})
def provenance_gate(h):
    p=h.get("provenance") or h.get("_provenance")
    if not p: return False
    if isinstance(p,str): return p in VALID_PROVENANCE
    if isinstance(p,dict): return (p.get("source") or p.get("type")) in VALID_PROVENANCE
    return False
def is_code_detected(s): return bool(s.signal_id) and s.type in ("odd_param","stack_trace","data_behind_4xx","shape_divergence","header_comment_js")
