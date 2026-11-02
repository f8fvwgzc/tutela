import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { VERSION } from "../src/index.js";

function Version(): React.JSX.Element {
  return <p>tutela {VERSION}</p>;
}

describe("the workspace", () => {
  it("renders a component in jsdom with the client package linked", () => {
    render(<Version />);
    expect(screen.getByText(`tutela ${VERSION}`)).toBeTruthy();
  });
});
