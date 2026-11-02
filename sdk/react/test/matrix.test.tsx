import {
  MoveRefusedError,
  NetworkError,
  type RoleDraft,
  StepUpRequiredError,
  UnauthorizedError,
} from "@f8fvwgzc/tutela-js";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import { userEvent } from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";

import { ErrorNotice, PermissionMatrix, RoleEditor, TutelaProvider } from "../src/index.js";
import { Fake, problem, violations } from "./fake.js";

afterEach(cleanup);

function mount(fake: Fake, ui: React.ReactNode) {
  return render(<TutelaProvider client={fake.client()}>{ui}</TutelaProvider>);
}

const cellOf = (row: string, col: number) => {
  const header = screen.getByRole("rowheader", { name: new RegExp(`^${row}( |$)`) });
  const tr = header.closest("tr");
  if (tr === null) throw new Error(row);
  return within(tr).getAllByRole("cell")[col] as HTMLElement;
};

describe("ErrorNotice", () => {
  it("shows which scopes wait for an owner on move_refused", () => {
    render(
      <ErrorNotice
        error={
          new MoveRefusedError({
            status: 403,
            code: "move_refused",
            title: "the move is not allowed",
            detail: "needs_approval: looser target; an owner must agree at project:p-2, org:org_1",
          })
        }
      />,
    );
    const alert = screen.getByRole("alert");
    expect(within(alert).getByText("This move waits for an owner.")).toBeTruthy();
    expect(within(alert).getByText("project p-2")).toBeTruthy();
    expect(within(alert).getByText("org org_1")).toBeTruthy();
  });

  it("offers MFA on a step-up refusal, and says sign in again on 401", async () => {
    let stepped = 0;
    const { rerender } = render(
      <ErrorNotice
        error={new StepUpRequiredError(400, "invalid_grant", "step-up authentication is required")}
        onStepUp={() => stepped++}
      />,
    );
    await userEvent.setup().click(screen.getByRole("button", { name: "Sign in with MFA" }));
    expect(stepped).toBe(1);
    rerender(
      <ErrorNotice
        error={new UnauthorizedError({ status: 401, code: "invalid_token", title: "" })}
      />,
    );
    expect(screen.getByText("Your sign-in ended.")).toBeTruthy();
    rerender(<ErrorNotice error={new NetworkError("down")} />);
    expect(screen.getByText("Tutela could not be reached.")).toBeTruthy();
  });
});

describe("PermissionMatrix", () => {
  it("shows roles × types, with field rows under their type and never above the item level", async () => {
    const fake = new Fake();
    mount(fake, <PermissionMatrix />);
    const table = await screen.findByRole("table", { name: "Permission matrix" });
    const heads = within(table)
      .getAllByRole("columnheader")
      .map((h) => h.textContent);
    expect(heads[0]).toBe("Permission");
    expect(heads.slice(1).map((h) => h?.replace(/seeded|Edit.*/g, "").trim())).toEqual([
      "owner",
      "reader",
      "Approver",
    ]);
    const rows = within(table)
      .getAllByRole("rowheader")
      .map((h) => h.textContent);
    expect(rows.indexOf("invoice")).toBeLessThan(rows.findIndex((r) => r?.startsWith("amount")));
    // reader: invoice read, invoice.amount write in the model -> read, never above the item.
    expect(cellOf("invoice", 1).textContent).toContain("read");
    expect(cellOf("amount", 1).textContent).toContain("read");
    expect(cellOf("amount", 1).textContent).not.toContain("write");
    // approver: a custom action and no admin key.
    expect(cellOf("approve", 2).textContent).toContain("Granted");
    expect(cellOf("approve", 1).textContent).toContain("Not granted");
    // An admin key, under each type: the owner holds project:manage_access.
    const keys = screen.getAllByRole("rowheader", { name: /^manage_access( |$)/ });
    expect(keys).toHaveLength(2);
    const projectKey = within(keys[0]?.closest("tr") as HTMLElement).getAllByRole("cell");
    expect(projectKey[0]?.textContent).toContain("Granted");
    expect(projectKey[1]?.textContent).toContain("Not granted");
  });

  it("hands an edited role to the RoleEditor in editable mode, never the owner", async () => {
    const fake = new Fake();
    const reviewed: RoleDraft[] = [];
    mount(fake, <PermissionMatrix editable onReview={(d) => reviewed.push(d)} />);
    await screen.findByRole("table", { name: "Permission matrix" });
    expect(screen.queryByRole("button", { name: "Edit owner" })).toBeNull();
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "Edit reader" }));
    await user.selectOptions(screen.getByLabelText("Level of invoice for reader"), "write");
    await user.click(screen.getByLabelText("invoice:approve for reader"));
    // A field is offered only up to its item level.
    await user.selectOptions(screen.getByLabelText("Level of invoice for reader"), "none");
    const field = screen.getByLabelText("Level of invoice.amount for reader") as HTMLSelectElement;
    expect([...field.options].map((o) => o.value)).toEqual(["none"]);
    await user.selectOptions(screen.getByLabelText("Level of invoice for reader"), "write");
    await user.click(screen.getByRole("button", { name: "Review change" }));
    expect(reviewed).toHaveLength(1);
    expect(reviewed[0]).toMatchObject({
      key: "reader",
      levels: { project: "read", invoice: "write" },
      field_levels: { "invoice.amount": "none" },
      grants: ["invoice:approve"],
    });
  });

  it("has no accessibility violations (axe)", async () => {
    const fake = new Fake();
    const { container } = mount(fake, <PermissionMatrix editable onReview={() => undefined} />);
    await screen.findByRole("table", { name: "Permission matrix" });
    expect(await violations(container)).toEqual([]);
  });
});

describe("RoleEditor", () => {
  async function checkImpact(user: ReturnType<typeof userEvent.setup>) {
    await user.selectOptions(await screen.findByLabelText("Level of invoice for reader"), "write");
    await user.click(screen.getByRole("button", { name: "Check impact" }));
  }

  it("shows the impact as sentences, asks for an approval token when it widens, and publishes with expected_version", async () => {
    const fake = new Fake();
    const done: unknown[] = [];
    mount(fake, <RoleEditor roleKey="reader" onDone={(r) => done.push(r)} />);
    const user = userEvent.setup();
    await checkImpact(user);
    expect(await screen.findByText("12 users gain read on contract")).toBeTruthy();
    expect(screen.getByText("This change widens access.")).toBeTruthy();
    const impact = fake.last("POST", "/v1/models/impact")?.json as {
      source: string;
      expected_version: number;
    };
    expect(impact.expected_version).toBe(3);
    expect(impact.source).toContain(
      '[roles.reader]\ngrants = { invoice = "write", project = "read", "invoice.amount" = "write" }',
    );
    expect(impact.source).toContain("[roles.approver]");

    const publish = screen.getByRole("button", { name: "Publish change" });
    expect((publish as HTMLButtonElement).disabled).toBe(true);
    await user.type(screen.getByLabelText("Approval token"), "tutela-approval-v1.abc");
    await user.click(publish);
    await waitFor(() => expect(fake.count("POST", "/v1/models/publish")).toBe(1));
    expect(fake.last("POST", "/v1/models/publish")?.json).toEqual({
      source: impact.source,
      expected_version: 3,
      approval: "tutela-approval-v1.abc",
    });
    await waitFor(() => expect(done).toHaveLength(1));
    expect(done[0]).toMatchObject({ kind: "published", result: { version: 4 } });
  });

  it("proposes when the tenant needs two people", async () => {
    const fake = new Fake();
    fake.twoPerson = true;
    fake.impactClass = "narrowing";
    mount(fake, <RoleEditor roleKey="reader" />);
    const user = userEvent.setup();
    await user.selectOptions(await screen.findByLabelText("Level of invoice for reader"), "none");
    await user.click(screen.getByRole("button", { name: "Check impact" }));
    await user.click(await screen.findByRole("button", { name: "Propose change" }));
    await waitFor(() => expect(fake.count("POST", "/v1/models/proposals")).toBe(1));
    expect(fake.count("POST", "/v1/models/publish")).toBe(0);
    expect(
      await screen.findByText(/Proposed\. Another admin approves it/, {
        selector: ".tutela-footer *",
      }),
    ).toBeTruthy();
  });

  it("loads the model again on 409 version_conflict", async () => {
    const fake = new Fake();
    fake.impactClass = "narrowing";
    fake.once(
      (r) => r.path === "/v1/models/publish",
      () => problem(409, "version_conflict"),
    );
    mount(fake, <RoleEditor roleKey="reader" />);
    const user = userEvent.setup();
    await checkImpact(user);
    const loads = fake.count("GET", "/v1/models/active");
    await user.click(await screen.findByRole("button", { name: "Publish change" }));
    expect(await screen.findByText("The model changed since you opened it.")).toBeTruthy();
    await waitFor(() => expect(fake.count("GET", "/v1/models/active")).toBe(loads + 1));
    expect(screen.getByRole("button", { name: "Check impact" })).toBeTruthy();
  });

  it("says why a publish needs an approval token (403 approval_required)", async () => {
    const fake = new Fake();
    fake.impactClass = "widening";
    fake.once(
      (r) => r.path === "/v1/models/publish",
      () => problem(403, "approval_required"),
    );
    mount(fake, <RoleEditor roleKey="reader" />);
    const user = userEvent.setup();
    await checkImpact(user);
    await user.type(await screen.findByLabelText("Approval token"), "tutela-approval-v1.old");
    await user.click(screen.getByRole("button", { name: "Publish change" }));
    expect(
      await screen.findByText("This change widens access.", { selector: ".tutela-notice-title" }),
    ).toBeTruthy();
  });

  it("does not change the owner role", async () => {
    const fake = new Fake();
    mount(fake, <RoleEditor roleKey="owner" />);
    expect(await screen.findByText(/The owner role holds everything/)).toBeTruthy();
    expect(screen.queryByRole("combobox")).toBeNull();
  });

  it("starts from a draft the matrix gave it, and has no accessibility violations (axe)", async () => {
    const fake = new Fake();
    const draft: RoleDraft = {
      key: "reader",
      levels: { project: "write" },
      field_levels: {},
      grants: [],
    };
    const { container } = mount(fake, <RoleEditor roleKey="reader" draft={draft} />);
    const project = (await screen.findByLabelText(
      "Level of project for reader",
    )) as HTMLSelectElement;
    expect(project.value).toBe("write");
    expect(await violations(container)).toEqual([]);
  });
});
