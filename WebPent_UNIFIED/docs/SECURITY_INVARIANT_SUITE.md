# Security Invariant Suite

## الغرض

هذه المجموعة تختبر خصائص السلامة غير القابلة للتفاوض في WebPent. نجاحها لا يعني اكتشاف ثغرة، ولا يرفع candidate إلى confirmed، ولا يساوي qualification كـVIP. الهدف هو التأكد من أن النظام يفشل مغلقًا عندما تكون السلطة أو النطاق أو الحالة أو الأدلة ناقصة أو متلاعبًا بها.

## النطاق المغطى

| المجال | invariant | الاختبار |
|---|---|---|
| Scope | تُرفض dot-segments وpercent-decoded traversal وcontrol characters كحالة ambiguous بدل التطبيع الصامت | `tests/security_invariants/test_scope_invariants.py` |
| Action authority | policy denial لا يستدعي handler، ولا تتجاوز البوابات package/identity/capability/idempotency/destructive | `tests/security_invariants/test_authority_invariants.py` |
| Action ledger | الحالات terminal المسموحة فقط `executed` و`failed`؛ status غير معروف لا يغيّر reservation | `tests/security_invariants/test_ledger_state.py` |
| ProofBundle | أي tamper بعد seal يفشل integrity وreplay، وغياب provenance أو استقلال negative control يمنع promotion | `tests/security_invariants/test_proof_invariants.py` |

## قواعد التفسير

> **Observed** و**candidate** و**Needs Human Review** ليست confirmations.

لا تُعد النتيجة confirmed إلا عبر مسار verifier القائم الذي يجمع causal signal target-backed، وnegative control مستقل، وProofBundle sealed قابلًا لإعادة التشغيل، مع validator identity/version وscope/identity provenance. اختبارات هذه المجموعة لا تنفّذ traffic على أهداف خارجية؛ كل الاختبارات محلية ومحدودة.

## بوابة التشغيل

يجب تشغيل المجموعة مع اختبارات package/proof وG-02 قبل أي commit أمني:

```bash
PYTHONPATH=src:/tmp/webpent-release-run/bbscout/src \
  .venv/bin/pytest -q tests/security_invariants \
  tests/test_target_package_v2_hardening.py \
  tests/test_vip_action_authority_contract.py \
  tests/test_proof_bundle.py \
  tests/test_vip_proof_bundle_contract.py
```

بعد تغيير أي direct-I/O path يجب إعادة توليد `docs/direct_io_inventory.json` و`docs/DIRECT_IO_INVENTORY.md` وتشغيل اختبارات G-02. أي فشل في هذه البوابة يُسجّل كفشل release ولا يُتجاوز بتعديل thresholds.
