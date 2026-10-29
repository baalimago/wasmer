// Runs the demo in headless Chromium and checks what the guest fetched.
import { chromium } from "playwright";

import { startServer } from "./server.mjs";

const server = await startServer();
const browser = await chromium.launch();
try {
  const page = await browser.newPage();
  page.on("pageerror", (error) => console.error("page error:", error.message));
  await page.goto("http://localhost:5001/");
  await page.waitForSelector("body[data-ready]");
  const { status, stdout } = await page.evaluate(() => window.runGuest());
  console.log(stdout);
  if (status !== 0 || !stdout.includes("Hello from the host")) {
    console.error(`unexpected outcome: exit status ${status}`);
    process.exitCode = 1;
  } else {
    console.log("ok: the guest fetched hello.txt through WISP");
  }
} finally {
  await browser.close();
  server.close();
}
