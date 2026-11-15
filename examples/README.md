# Example manifests

Four ready-made `tutela.resources.toml` files for different kinds of business. Copy the one closest to yours, rename the types and fields, and change the roles. Each one compiles, and tests prove that its data hiding works.

| Example | Tree (root first) | What it hides, and from whom |
|---|---|---|
| [tracker](tracker/tutela.resources.toml) | org → team → project → issue → task | The owner's access-blueprint. A project owner hides the budget from members. Contract terms start hidden. Guests see only client-visible issues. AI agents write only their own tasks and never see the budget. |
| [hr](hr/tutela.resources.toml) | org → company → department → employee | Pay, reviews and private data. Colleagues see the directory only. You see your own pay. A manager writes reviews but never sees pay. Payroll changes pay but never sees reviews. |
| [crm](crm/tutela.resources.toml) | org → region → account → deal | Deal money and margins. A rep edits only their own deals. Finance reads all the money and changes nothing. A partner sees only the deals shared with it, without the money. |
| [procurement](procurement/tutela.resources.toml) | org → company → plant → purchase_order → po_line | Prices and bank details. The warehouse records received goods but never sees prices. Approvers see submitted orders only. Only accounts payable and auditors see the supplier's bank account. |

The format is in [docs/MANIFEST.md](../docs/MANIFEST.md). The rules behind it are in [docs/PERMISSION-MODEL.md](../docs/PERMISSION-MODEL.md).

## Use one

```sh
cp examples/hr/tutela.resources.toml ./tutela.resources.toml
tutela check                                    # compiles it and lists every problem
tutela codegen --rust src/perms.rs --ts web/src/perms.ts   # constants, the UI map, the route table
tutela apply --dry-run                          # shows the diff against the applied manifest
tutela apply                                    # library mode: a widening diff needs an approval token
```

`tutela apply` in library mode writes to the database in `TUTELA_DATABASE_URL` (run `tutela migrate` once first). With `tutelad` running, `tutela apply --server <url> --token <token>` publishes it to your tenant with an impact report instead.

## What is in the manifest, and what is data

The manifest holds the **model**: types, fields, roles, conditions, and field rules for the whole org. These things are **data** in `tutela-store`, written by your product or by the tenant's admins in the Tutela Console:

- who holds which role, and where (role assignments);
- groups;
- which scopes are private;
- a field rule at one scope, for example "in project Payments, members do not see the budget".

The tests in [`crates/tutela-pdp/src/tests_examples.rs`](../crates/tutela-pdp/src/tests_examples.rs) write this data for each example, so you can see the whole picture there. Run them with:

```sh
cargo test -p tutela-pdp tests_examples
```

## Patterns the examples use

1. **Confidential and secret fields start hidden.** Every role sees None until a field rule opens the field for one role. See `salary` in [hr](hr/tutela.resources.toml).
2. **The closest assignment wins.** Put a role on the record itself when it is about that one record. In [hr](hr/tutela.resources.toml), `self_service` sits on your own employee record and `line_manager` on each direct report's record. So on your own record you are never your own manager, and you cannot approve your own leave.
3. **A condition reads only the item's own fields.** Conditions do not look at the parent. In [procurement](procurement/tutela.resources.toml), each order line carries a copy of its order's `buyer` and `status`, so the line's conditions can read them. Your product keeps the copies up to date.
4. **A field that decides access needs `manage_access` to change.** A field with `grants_access = true` (like `assignee`, `owner` or `labels`) works like a permission. So only a role with `manage_access` (for example `owner`) may change it, and a member may not. If your members must reassign work, give that job to a role that holds `<type>:manage_access`.
5. **Conditions only narrow.** When a condition is false, the level drops to its `else` level. A condition never opens anything.
6. **An AI agent never sees more than the person behind it.** An agent acting for a person gets the overlap of both. See the tracker tests.
7. **Hiding in the UI is not security.** Every server route checks again, and lists are filtered inside SQL with `list_filter` ([docs/PERMISSION-MODEL.md §12](../docs/PERMISSION-MODEL.md#12-list-filtering-in-sql)).

## Limits of manifest v1

- Every resource has exactly one parent. A record that belongs to two departments does not fit.
- Conditions come from a fixed list: `eq`, `in`, `contains`, `is_principal`, `in_group`, `and`, `or`, `not` ([docs/MANIFEST.md §8](../docs/MANIFEST.md#8-conditions)). There is no "greater than".
- A condition may not read a confidential or secret field: people could learn its value from what they may do. So "hide orders over 10,000" cannot read `total_amount`. Instead, store a band that is not confidential (for example `size = "large"`, set by your product) and use `in` on it.

These are starting points, not a product. No product uses them as they are.
