# enhanced-test-step1.py
# Shows whether detection came from transformer-hybrid or rule-only logic

import sys
import time
from datetime import datetime

def test_detection_methods():
    print("🔍 TESTING DETECTION METHODS")
    print("=" * 60)

    from step1_transformer_model import WebAttackTransformer

    print("📥 Initializing model ...")
    model = WebAttackTransformer()          # loads DistilBERT + rule fallback
    print("✅ Model initialized\n")

    test_requests = [
        "GET /api/users/123",                              # Benign
        "GET /users?id=1' OR 1=1--",                       # SQLi
        "GET /search?q=<script>alert('xss')</script>",     # XSS
        "GET /../../../etc/passwd"                         # Path-traversal
    ]

    print("🧪 COMPARING DETECTION METHODS")
    print("-" * 60)

    for i, req in enumerate(test_requests, 1):
        print(f"\n{i}. Testing: {req}")
        print("   " + "-" * 50)

        # Transformer (hybrid) mode
        print("   🤖 TRANSFORMER MODE:")
        res_t = model.predict_attack(req, use_transformer=True)
        status_t = "🚫 BLOCKED" if res_t['is_malicious'] else "✅ ALLOWED"
        print(f"      Result: {status_t}")
        print(f"      Confidence: {res_t['confidence']*100:.1f}%")
        print(f"      Method Used: {res_t.get('model_used')}")
        if 'rule_based_detection' in res_t:
            rule = res_t['rule_based_detection']
            rule_flag = '✅ YES' if rule['detected'] else '❌ NO'
            print(f"      Rule Engine: {rule_flag}")
            if rule['detected']:
                print(f"      Rule Attack Type: {rule['attack_type']}")

        # Pure rule-based mode
        print("   📋 RULE-BASED MODE:")
        res_r = model.predict_attack(req, use_transformer=False)
        status_r = "🚫 BLOCKED" if res_r['is_malicious'] else "✅ ALLOWED"
        print(f"      Result: {status_r}")
        print(f"      Confidence: {res_r['confidence']*100:.1f}%")
        print(f"      Method Used: {res_r.get('model_used')}")

        # Agreement check
        if res_t['is_malicious'] == res_r['is_malicious']:
            print("   ✅ Methods agree")
        else:
            print("   ⚠️  Methods disagree")

def test_raw_transformer():
    print("\n" + "="*60)
    print("🧠 PURE TRANSFORMER OUTPUT")
    print("="*60)

    from step1_transformer_model import WebAttackTransformer
    import torch

    model = WebAttackTransformer()
    text = "METHOD GET PATH /users PARAMS id=1' OR 1=1--"
    toks = model.tokenizer(text, return_tensors='pt')
    with torch.no_grad():
        cls = model.base_model(**toks).last_hidden_state[:,0,:]
        probs = torch.softmax(model.classifier(cls), dim=-1)[0]
    print(f"Probabilities → benign={probs[0]:.3f}  malicious={probs[1]:.3f}")

if __name__ == "__main__":
    print("🔬 ENHANCED STEP-1 ANALYSIS")
    print("="*60)
    test_detection_methods()
    test_raw_transformer()
    print("\n🎉 Analysis complete! Ready for Step 2.")
