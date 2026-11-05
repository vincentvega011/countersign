// Runs the browser verifier in Node over files, for the cross-implementation test.
// Usage: node test/verify-runner.mjs <jobs.json>; each job is {path, pinned: {merchant, platform} | null}
// where pinned values are paths to key files. Prints one JSON array of result lists.
import { readFileSync } from "node:fs";
import { loads } from "../evidence/json.js";
import { verifyText } from "../evidence/verify.js";

const jobs = JSON.parse(readFileSync(process.argv[2], "utf8"));
const out = [];
for (const job of jobs) {
  let pinned = null;
  if (job.pinned) {
    pinned = Object.create(null);
    for (const [name, path] of Object.entries(job.pinned))
      pinned[name] = loads(new Uint8Array(readFileSync(path)));
  }
  out.push(await verifyText(new Uint8Array(readFileSync(job.path)), pinned));
}
process.stdout.write(JSON.stringify(out));
