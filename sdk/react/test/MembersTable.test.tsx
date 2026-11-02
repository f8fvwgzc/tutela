import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import { userEvent } from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { type AccessRequest, MembersTable, TutelaProvider } from "../src/index.js";
import { Fake, ORG, PROJECT, problem, violations } from "./fake.js";

afterEach(cleanup);

function mount(fake: Fake, extra: Partial<Parameters<typeof MembersTable>[0]> = {}) {
  const client = fake.client();
  const r = render(
    <TutelaProvider client={client}>
      <MembersTable scope={PROJECT} path={[ORG]} {...extra} />
    </TutelaProvider>,
  );
  return { client, ...r };
}

const table = () => screen.getByRole("table", { name: "Members of project p-1" });

describe("MembersTable", () => {
  it("lists the members and lets a person who may manage access give a role with an end", async () => {
    const fake = new Fake();
    const { client } = mount(fake);
    expect(await screen.findByText("user:usr_alice")).toBeTruthy();
    expect(screen.getByText("group:legal")).toBeTruthy();
    expect(within(table()).getByText("2027-01-01")).toBeTruthy();
    expect(within(table()).getByText("No end")).toBeTruthy();

    const user = userEvent.setup();
    await user.type(await screen.findByLabelText("Member"), "user:usr_bob");
    await user.selectOptions(screen.getByLabelText("Role"), "approver");
    await user.type(screen.getByLabelText("Ends (UTC, optional)"), "2030-06-01");
    await user.click(screen.getByRole("button", { name: "Give role" }));

    await waitFor(() => expect(fake.count("POST", "/v1/admin/assignments")).toBe(1));
    expect(fake.last("POST", "/v1/admin/assignments")?.json).toEqual({
      subject: "user:usr_bob",
      role: "approver",
      scope: PROJECT,
      expires_at: "2030-06-01T00:00:00.000Z",
    });
    expect(await screen.findByText("user:usr_bob")).toBeTruthy();
    expect(screen.getByRole("status").textContent).toBe("Role given.");
    // The page shows its own write: the next map is at least that new.
    expect(client.revision).toBe(11);
    await waitFor(() =>
      expect(fake.last("POST", "/v1/authz/permissions")?.json).toMatchObject({
        at_least_revision: 11,
      }),
    );
  });

  it("hides what the permission map does not allow", async () => {
    const fake = new Fake();
    fake.manage = false;
    mount(fake);
    expect(await screen.findByText("user:usr_alice")).toBeTruthy();
    await waitFor(() => expect(fake.count("POST", "/v1/authz/permissions")).toBe(1));
    expect(screen.queryByRole("form", { name: "Give a role" })).toBeNull();
    expect(screen.queryByRole("button", { name: /Remove/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /Change end/ })).toBeNull();
    expect(within(table()).getAllByRole("columnheader")).toHaveLength(4);
  });

  it("says so when the person may not see the members (403 forbidden)", async () => {
    const fake = new Fake();
    fake.once(
      (r) => r.path === "/v1/admin/assignments/list",
      () => problem(403, "forbidden"),
    );
    mount(fake);
    expect(await screen.findByText("You can't see who has access here.")).toBeTruthy();
    expect(screen.queryByRole("table")).toBeNull();
  });

  it("hides the controls when a change is refused with 403 forbidden", async () => {
    const fake = new Fake();
    fake.once(
      (r) => r.method === "DELETE",
      () => problem(403, "forbidden"),
    );
    mount(fake);
    const user = userEvent.setup();
    await user.click(
      await screen.findByRole("button", { name: "Remove reader from user:usr_alice" }),
    );
    await user.click(screen.getByRole("button", { name: "Remove" }));
    expect(await screen.findByText("You don't have access to do this here.")).toBeTruthy();
    expect(screen.queryByRole("form", { name: "Give a role" })).toBeNull();
    expect(screen.queryByRole("button", { name: /Change end/ })).toBeNull();
  });

  it("shows the counts-only detail of not_held and offers to ask an admin who holds more", async () => {
    const fake = new Fake();
    fake.once(
      (r) => r.method === "POST" && r.path === "/v1/admin/assignments",
      () =>
        problem(
          403,
          "not_held",
          "1 user gains write on invoice in 1 scope; 1 user gains read on invoice.amount in 1 scope",
        ),
    );
    const asked: AccessRequest[] = [];
    mount(fake, { onAskAdmin: (r) => asked.push(r) });
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText("Member"), "user:usr_bob");
    await user.selectOptions(screen.getByLabelText("Role"), "approver");
    await user.click(screen.getByRole("button", { name: "Give role" }));

    const alert = await screen.findByRole("alert");
    expect(within(alert).getByText("You can't give this much access.")).toBeTruthy();
    expect(within(alert).getByText("1 user gains write on invoice in 1 scope")).toBeTruthy();
    expect(within(alert).getByText("1 user gains read on invoice.amount in 1 scope")).toBeTruthy();
    await user.click(within(alert).getByRole("button", { name: "Ask an admin who holds more" }));
    expect(asked).toEqual([
      {
        subject: "user:usr_bob",
        role: "approver",
        scope: PROJECT,
        gains: [
          "1 user gains write on invoice in 1 scope",
          "1 user gains read on invoice.amount in 1 scope",
        ],
      },
    ]);
    // The controls stay: the person may still give what it holds.
    expect(screen.getByRole("form", { name: "Give a role" })).toBeTruthy();
  });

  it("reloads the list on 409", async () => {
    const fake = new Fake();
    fake.once(
      (r) => r.method === "DELETE",
      () => problem(409, "busy"),
    );
    mount(fake);
    const user = userEvent.setup();
    await user.click(
      await screen.findByRole("button", { name: "Remove reader from user:usr_alice" }),
    );
    const lists = fake.count("POST", "/v1/admin/assignments/list");
    await user.click(screen.getByRole("button", { name: "Remove" }));
    expect(await screen.findByText("This changed while you were looking.")).toBeTruthy();
    await waitFor(() => expect(fake.count("POST", "/v1/admin/assignments/list")).toBe(lists + 1));
  });

  it("asks again after Retry-After when the list answers 503", async () => {
    const fake = new Fake();
    fake.once(
      (r) => r.path === "/v1/admin/assignments/list",
      () => problem(503, "unavailable", undefined, { "retry-after": "1" }),
    );
    mount(fake);
    expect(await screen.findByText("Tutela is busy.")).toBeTruthy();
    expect(await screen.findByText("user:usr_alice", undefined, { timeout: 3000 })).toBeTruthy();
    expect(fake.count("POST", "/v1/admin/assignments/list")).toBe(2);
    await waitFor(() => expect(screen.queryByText("Tutela is busy.")).toBeNull());
  });

  it("offers to try a refused change again on 503, and sends it again", async () => {
    const fake = new Fake();
    fake.once(
      (r) => r.method === "PATCH",
      () => problem(503, "unavailable", undefined, { "retry-after": "20" }),
    );
    mount(fake);
    const user = userEvent.setup();
    await user.click(
      await screen.findByRole("button", { name: "Change end of approver for group:legal" }),
    );
    await user.click(screen.getByRole("button", { name: "No end" }));
    const alert = await screen.findByRole("alert");
    expect(within(alert).getByText("Tutela is busy.")).toBeTruthy();
    expect(within(alert).getByText(/Trying again in \d+ s\./)).toBeTruthy();
    await user.click(within(alert).getByRole("button", { name: "Try again now" }));
    await waitFor(() => expect(fake.count("PATCH", "/v1/admin/assignments/ra_2")).toBe(2));
    expect(fake.last("PATCH", "/v1/admin/assignments/ra_2")?.json).toEqual({ expires_at: null });
    await waitFor(() => expect(screen.getByRole("status").textContent).toBe("End changed."));
  });

  it("changes an end, and removes a role after a confirmation", async () => {
    const fake = new Fake();
    mount(fake);
    const user = userEvent.setup();
    await user.click(
      await screen.findByRole("button", { name: "Change end of reader for user:usr_alice" }),
    );
    await user.type(screen.getByLabelText("New end for user:usr_alice"), "2031-02-03");
    await user.click(screen.getByRole("button", { name: "Save end" }));
    await waitFor(() =>
      expect(fake.last("PATCH", "/v1/admin/assignments/ra_1")?.json).toEqual({
        expires_at: "2031-02-03T00:00:00.000Z",
      }),
    );
    await user.click(
      await screen.findByRole("button", { name: "Remove approver from group:legal" }),
    );
    expect(screen.getByText("Remove approver?")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Remove" }));
    await waitFor(() => expect(fake.count("DELETE", "/v1/admin/assignments/ra_2")).toBe(1));
    await waitFor(() => expect(screen.queryByText("group:legal")).toBeNull());
  });

  it("pages with Load more", async () => {
    const fake = new Fake();
    for (let i = 3; i <= 5; i++) {
      fake.assignments.push({
        id: `ra_${i}`,
        subject: `user:usr_${i}`,
        role: "reader",
        scope: PROJECT,
      });
    }
    mount(fake, { pageSize: 2 });
    expect(await screen.findByText("user:usr_alice")).toBeTruthy();
    expect(screen.queryByText("user:usr_3")).toBeNull();
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "Load more" }));
    expect(await screen.findByText("user:usr_3")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Load more" }));
    expect(await screen.findByText("user:usr_5")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Load more" })).toBeNull();
    const afters = fake.seen
      .filter((s) => s.path === "/v1/admin/assignments/list")
      .map((s) => (s.json as { after?: string }).after);
    expect(afters).toEqual([undefined, "ra_2", "ra_4"]);
  });

  it("never offers the owner role by default", async () => {
    const fake = new Fake();
    mount(fake);
    const role = (await screen.findByLabelText("Role")) as HTMLSelectElement;
    await waitFor(() => expect(role.options.length).toBe(3));
    expect(role.value).toBe("reader");
    expect(role.options[role.options.length - 1]?.value).toBe("owner");
  });

  it("checks the member before it sends anything", async () => {
    const fake = new Fake();
    mount(fake);
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText("Member"), "bob@example.test");
    await user.click(screen.getByRole("button", { name: "Give role" }));
    expect(screen.getByText(/A member is a principal/)).toBeTruthy();
    expect(screen.getByLabelText("Member").getAttribute("aria-invalid")).toBe("true");
    expect(fake.count("POST", "/v1/admin/assignments")).toBe(0);
  });

  it("shows names the product gives, and works with the keyboard", async () => {
    const fake = new Fake();
    const names: Record<string, string> = {
      "user:usr_alice": "Alice",
      "group:legal": "Legal team",
    };
    mount(fake, { renderSubject: (s) => names[s] ?? s });
    expect(await screen.findByText("Alice")).toBeTruthy();
    const user = userEvent.setup();
    await user.tab();
    expect(document.activeElement).toBe(screen.getByLabelText("Member"));
    await user.keyboard("user:usr_kim");
    await user.tab();
    await user.tab();
    await user.tab();
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "Give role" }));
    await user.keyboard("{Enter}");
    await waitFor(() => expect(fake.count("POST", "/v1/admin/assignments")).toBe(1));
  });

  it("has no accessibility violations (axe)", async () => {
    const fake = new Fake();
    const { container } = mount(fake, { theme: "dark" });
    await screen.findByText("user:usr_alice");
    await screen.findByRole("form", { name: "Give a role" });
    expect(container.querySelector(".tutela")?.getAttribute("data-theme")).toBe("dark");
    expect(await violations(container)).toEqual([]);
  });

  it("never writes to browser storage", async () => {
    const setItem = vi.spyOn(Storage.prototype, "setItem");
    const fake = new Fake();
    mount(fake);
    await screen.findByText("user:usr_alice");
    expect(setItem).not.toHaveBeenCalled();
  });
});
