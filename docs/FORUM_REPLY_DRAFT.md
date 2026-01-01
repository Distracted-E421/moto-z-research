# Forum Reply Draft - Response to Motorola Support

**In reply to**: Jess (Motorola Support)  
**Re**: Case ID 251216-000447

---

## Reply

Hi Jess,

Thank you for the detailed response. I appreciate knowing the actual reason for rejection - the "4 year database retention policy" - which is much more informative than the generic portal error message.

However, this raises several important questions I'd like addressed:

### 1. Regarding the Error Message

Why does the portal display "Your device does not qualify for bootloader unlocking" instead of "Unlock keys for this device model are no longer available due to age"? 

The current message implies device ineligibility, which led me to spend significant time troubleshooting a problem that was actually a server-side policy decision. Accurate error messaging would save both users and support staff considerable time.

### 2. Regarding the Database Policy

- **Where is this 4-year policy documented?** I've reviewed Motorola's bootloader unlock terms and developer documentation and cannot find any mention of key expiration or retention periods. Was this disclosed at time of purchase or when the unlock program was established for this device?

- **Is this policy applied retroactively?** The Moto Z4 was sold with the advertised feature of bootloader unlockability. If the keys have been deleted, this effectively removes a feature that was part of the product at sale.

### 3. Regarding Your Suggestion

You mentioned that "community members sometimes find and share alternative methods for older devices, although these are not officially supported."

I want to be clear about what you're suggesting here: **Is Motorola's official position that users of devices past the 4-year window should seek unofficial/unsupported unlock methods?** 

If so, would Motorola consider:
- **Releasing the expired unlock keys publicly** for devices past the retention window, since they're no longer being maintained anyway?
- **Open-sourcing the unlock verification mechanism** for EOL devices to allow community-maintained unlocking?
- **Providing documentation** that would allow developers to implement their own unlock solutions for unsupported devices?

These options would align with environmental sustainability goals (extending device lifespan, reducing e-waste) while removing any ongoing support burden from Motorola.

### 4. Regarding Alternative Paths

- **Is there a Motorola Developer Relations or Engineering contact** who handles edge cases or developer program members?
- **Does Motorola have a developer program** that might provide access to unlock capabilities for legitimate development purposes?
- **Are there any enterprise or bulk unlock options** that might apply to individual developers?

### 5. Technical Clarification Request

My understanding is that bootloader unlock tokens are **generated on-demand using a signing key**, not pre-generated and stored per-device. If this is correct, the unlock capability would depend on Motorola retaining the signing key, not individual device tokens.

Could you clarify whether:
- Individual per-device keys were actually stored and deleted, OR
- The signing/generation capability for this device family was retired?

This distinction matters because it determines whether this is a data retention issue or a deliberate capability removal.

### Summary

I'm not asking for unofficial workarounds. I'm asking Motorola to either:

1. **Honor the unlockability** that was part of the device's advertised features, OR
2. **Officially enable alternatives** for devices past the arbitrary retention window (key release, documentation, etc.), OR  
3. **Provide escalation** to someone with authority to make exceptions for legitimate developer use cases

I understand support staff work within policy constraints. If this requires escalation to developer relations, product management, or engineering, I'm happy to be transferred to the appropriate team.

Thank you for your time.

---

**Case Reference**: 251216-000447  
**Device Serial**: ZY22726N55

---

## Notes for Self (DO NOT POST)

**Strategic goals of this response:**

1. **Document the contradiction** - They suggest unofficial methods but won't help officially. Get this on record.

2. **Challenge the policy premise** - Ask where it's documented. If it's not public, that's a problem.

3. **Probe the technical reality** - Are keys really "deleted" or is this just policy-speak for "we won't"?

4. **Offer face-saving alternatives** - Releasing old keys or docs lets them help without "supporting" anything.

5. **Request escalation** - Get past front-line support to someone with actual authority.

6. **Environmental angle** - Frame device longevity as sustainability, which corporations love to claim they care about.

**Possible follow-ups depending on response:**

- If they confirm keys are generated not stored: Ask why generation was disabled
- If they won't release keys: Ask about GPL obligations for bootloader code
- If they won't escalate: Ask for written confirmation of this policy for consumer protection filing
- If they go silent: Consider formal complaint to consumer protection agency about feature removal

**What we're fishing for:**

- Any admission that they COULD unlock but WON'T (policy vs capability)
- Any documentation of this policy we can challenge
- Any escalation path to someone who might actually help
- Any official statement we can use to justify alternative approaches

