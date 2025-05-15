/* eslint-disable @typescript-eslint/no-require-imports */
const fs = require("fs"); // TODO: @detunized remove this!

const concurrently = require("concurrently");
const rimraf = require("rimraf");

const args = process.argv.splice(2);

rimraf.sync("build");

// TODO: @detunized remove this!
fs.mkdirSync("build/Release", { recursive: true });
fs.copyFileSync(
  "../../node_modules/sqlite3/build/Release/node_sqlite3.node",
  "./build/Release/node_sqlite3.node",
);

concurrently(
  [
    {
      name: "Main",
      command: "npm run build:main:watch",
      prefixColor: "yellow",
    },
    {
      name: "Prel",
      command: "npm run build:preload:watch",
      prefixColor: "magenta",
    },
    {
      name: "Rend",
      command: "npm run build:renderer:watch",
      prefixColor: "cyan",
    },
    {
      name: "Elec",
      command: `npx wait-on ./build/main.js && npx electron --no-sandbox --inspect=5858 ${args.join(
        " ",
      )} ./build --watch`,
      prefixColor: "green",
    },
  ],
  {
    prefix: "name",
    outputStream: process.stdout,
    killOthers: ["success", "failure"],
  },
);
