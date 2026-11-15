import type { PermissionMapAnswer } from "@f8fvwgzc/tutela-js";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { Can, Field, Protect, TutelaProvider, useField, useUi } from "../src/index.js";
import { Fake, json, problem, violations } from "./fake.js";

afterEach(cleanup);

const INVOICE = {
  type: "invoice",
  id: "inv-1",
  path: [
    { type: "project", id: "p-1" },
    { type: "org", id: "org_1" },
  ],
};

const MAP: PermissionMapAnswer = {
  rev: 10,
  ui: {
    "invoices.approve_button": { mode: "show" },
    "invoices.delete_button": { mode: "disable", reason: "level_too_low" },
    "invoices.export_button": { mode: "hide" },
    "invoices.amount_cell": { mode: "readonly" },
  },
  actions: { "invoice:read": true, "invoice:approve": true, "invoice:delete": false },
  fields: { "invoice.number": "write", "invoice.status": "read", "invoice.amount": "none" },
};

/** A fake whose permission map is `answer`, or whatever `answer` returns. */
function fakeWith(answer: PermissionMapAnswer | (() => Response)): Fake {
  const fake = new Fake();
  fake.overrides.push((req) => {
    if (req.path !== "/v1/authz/permissions") return undefined;
    return typeof answer === "function" ? answer() : json(200, answer);
  });
  return fake;
}

function mount(fake: Fake, ui: React.ReactNode) {
  return render(<TutelaProvider client={fake.client()}>{ui}</TutelaProvider>);
}

function page(more?: { fields?: string[]; uiKeys?: string[] }) {
  return (
    <Protect
      resource={INVOICE}
      action="invoice:read"
      uiKeys={more?.uiKeys ?? Object.keys(MAP.ui)}
      fields={more?.fields ?? ["number", "status", "amount"]}
      loading={<p>Loading</p>}
      fallback={<p>No access</p>}
    >
      <p>Invoice page</p>
      <Can uiKey="invoices.approve_button" resource={INVOICE}>
        <button type="button">Approve</button>
      </Can>
      <Can uiKey="invoices.delete_button" resource={INVOICE} reasonText="Only owners delete.">
        <button type="button">Delete</button>
      </Can>
      <Can uiKey="invoices.export_button" resource={INVOICE} fallback={<span>No export</span>}>
        <button type="button">Export</button>
      </Can>
      <Can uiKey="invoices.amount_cell" resource={INVOICE}>
        {({ mode }) => <span>amount cell: {mode}</span>}
      </Can>
      <Can action="invoice:approve" resource={INVOICE}>
        <span>may approve</span>
      </Can>
      <Can action="invoice:delete" resource={INVOICE} fallback={<span>may not delete</span>}>
        <span>may delete</span>
      </Can>
      <dl>
        <dt>Number</dt>
        <dd>
          <Field resource={INVOICE} name="number">
            {(level) =>
              level === "write" ? <input aria-label="Number" defaultValue="881" /> : "881"
            }
          </Field>
        </dd>
        <dt>Status</dt>
        <dd>
          <Field resource={INVOICE} name="status">
            {(level) => `paid (${level})`}
          </Field>
        </dd>
        <dt>Amount</dt>
        <dd data-testid="amount">
          <Field resource={INVOICE} name="amount">
            $15,000
          </Field>
        </dd>
        <dt>Amount, removed</dt>
        <dd data-testid="amount-removed">
          <Field resource={INVOICE} name="amount" whenHidden="remove">
            $15,000
          </Field>
        </dd>
      </dl>
    </Protect>
  );
}

describe("Protect", () => {
  it("loads one map with the action, the UI keys and the field keys, then shows the page", async () => {
    const fake = fakeWith(MAP);
    mount(fake, page());
    expect(screen.getByText("Loading")).toBeTruthy();
    await screen.findByText("Invoice page");
    const asked = fake.last("POST", "/v1/authz/permissions")?.json as Record<string, unknown>;
    expect(asked.actions).toEqual(["invoice:read"]);
    expect(asked.ui_keys).toEqual(Object.keys(MAP.ui));
    expect(asked.fields).toEqual(["invoice.number", "invoice.status", "invoice.amount"]);
    expect(asked.resource).toEqual(INVOICE);
  });

  it("shows the fallback when the action is denied", async () => {
    const fake = fakeWith({ ...MAP, actions: { "invoice:read": false } });
    mount(fake, page());
    await screen.findByText("No access");
    expect(screen.queryByText("Invoice page")).toBeNull();
  });

  it("shows the fallback when the map cannot be loaded", async () => {
    const fake = fakeWith(() => problem(403, "forbidden"));
    mount(fake, page());
    await screen.findByText("No access");
    expect(screen.queryByText("Invoice page")).toBeNull();
  });
});

describe("Can", () => {
  it("shows, disables, hides and hands the mode to a function", async () => {
    mount(fakeWith(MAP), page());
    await screen.findByText("Invoice page");

    const approve = screen.getByRole("button", { name: "Approve" }) as HTMLButtonElement;
    expect(approve.matches(":disabled")).toBe(false);

    const del = screen.getByRole("button", { name: "Delete" }) as HTMLButtonElement;
    expect(del.matches(":disabled")).toBe(true);
    const box = del.closest("fieldset");
    expect(box?.getAttribute("title")).toBe("Only owners delete.");
    expect(box?.getAttribute("data-tutela-mode")).toBe("disable");

    expect(screen.queryByRole("button", { name: "Export" })).toBeNull();
    expect(screen.getByText("No export")).toBeTruthy();
    expect(screen.getByText("amount cell: readonly")).toBeTruthy();
  });

  it("answers one action: shown when allowed, the fallback when not", async () => {
    mount(fakeWith(MAP), page());
    await screen.findByText("Invoice page");
    expect(screen.getByText("may approve")).toBeTruthy();
    expect(screen.getByText("may not delete")).toBeTruthy();
    expect(screen.queryByText("may delete")).toBeNull();
  });

  it("hides what no map has loaded", () => {
    mount(
      fakeWith(MAP),
      <Can
        uiKey="invoices.approve_button"
        resource={INVOICE}
        fallback={<span>nothing loaded</span>}
      >
        <button type="button">Approve</button>
      </Can>,
    );
    expect(screen.queryByRole("button", { name: "Approve" })).toBeNull();
    expect(screen.getByText("nothing loaded")).toBeTruthy();
  });
});

describe("Field", () => {
  it("draws a field by its level, and Restricted or nothing when it is hidden", async () => {
    mount(fakeWith(MAP), page());
    await screen.findByText("Invoice page");
    expect((screen.getByLabelText("Number") as HTMLInputElement).value).toBe("881");
    expect(screen.getByText("paid (read)")).toBeTruthy();
    expect(screen.getByTestId("amount").textContent).toBe("Restricted");
    expect(screen.queryByText("$15,000")).toBeNull();
    expect(screen.getByTestId("amount-removed").textContent).toBe("");
  });

  it("is Restricted when the field was not asked for", async () => {
    mount(fakeWith({ ...MAP, fields: {} }), page({ fields: [] }));
    await screen.findByText("Invoice page");
    expect(screen.getByText("Restricted", { selector: "[data-testid=amount] *" })).toBeTruthy();
    expect(screen.queryByLabelText("Number")).toBeNull();
  });

  it("has no accessibility violations", async () => {
    const { container } = mount(fakeWith(MAP), page());
    await screen.findByText("Invoice page");
    expect(await violations(container)).toEqual([]);
  });
});

/** Shows what the hooks answer for the delete button and two fields. */
function Probe() {
  const ui = useUi("invoices.delete_button", INVOICE);
  const amount = useField("amount", INVOICE);
  const status = useField("status", INVOICE);
  return (
    <p>
      {ui.mode} {ui.reason ?? "-"} {amount} {status}
    </p>
  );
}

describe("useUi and useField", () => {
  it("read the loaded map, and update when it loads", async () => {
    mount(
      fakeWith(MAP),
      <>
        <Probe />
        <Protect
          resource={INVOICE}
          action="invoice:read"
          uiKeys={["invoices.delete_button"]}
          fields={["status"]}
        />
      </>,
    );
    expect(screen.getByText("hide - none none")).toBeTruthy();
    await waitFor(() => expect(screen.getByText("disable level_too_low none read")).toBeTruthy());
  });
});
