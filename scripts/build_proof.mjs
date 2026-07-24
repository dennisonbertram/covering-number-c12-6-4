#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath, pathToFileURL } from "node:url";

import katex from "katex";
import { marked } from "marked";
import { chromium } from "playwright-core";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const repository = path.resolve(scriptDirectory, "..");
const sourcePath = path.join(repository, "proof", "proof.md");
const outputPath = path.join(repository, "proof", "proof.pdf");
const temporaryDirectory = path.join(repository, "tmp", "pdfs", "proof-render");
const htmlPath = path.join(temporaryDirectory, "proof.html");

function renderMath(source) {
  const pieces = source.split(/(```[\s\S]*?```)/g);
  return pieces
    .map((piece, index) => {
      if (index % 2 === 1) {
        return piece;
      }
      const withDisplays = piece.replace(
        /\\\[\s*([\s\S]*?)\s*\\\]/g,
        (_whole, expression) =>
          `<div class="display-math">${katex.renderToString(expression, {
            displayMode: true,
            output: "htmlAndMathml",
            throwOnError: true,
            strict: "error",
          })}</div>`,
      );
      return withDisplays.replace(
        /\\\(([\s\S]*?)\\\)/g,
        (_whole, expression) =>
          `<span class="inline-math">${katex.renderToString(expression, {
            displayMode: false,
            output: "htmlAndMathml",
            throwOnError: true,
            strict: "error",
          })}</span>`,
      );
    })
    .join("");
}

function resolveChrome() {
  const candidates = [
    process.env.C1264_CHROME,
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
  ].filter(Boolean);
  const executable = candidates.find((candidate) => fs.existsSync(candidate));
  if (!executable) {
    throw new Error(
      "Chrome/Chromium not found; set C1264_CHROME to an executable path",
    );
  }
  return executable;
}

const markdown = fs.readFileSync(sourcePath, "utf8");
const renderedMarkdown = renderMath(markdown);
if (/\\[\[(]|\\[\])]/.test(renderedMarkdown)) {
  throw new Error("unrendered TeX delimiter remains outside a code block");
}

marked.setOptions({ gfm: true, breaks: false });
const article = marked.parse(renderedMarkdown);
const katexStylesheet = pathToFileURL(
  path.join(repository, "node_modules", "katex", "dist", "katex.min.css"),
).href;

const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>A computer-assisted determination of C(12,6,4)</title>
  <link rel="stylesheet" href="${katexStylesheet}">
  <style>
    @page { size: Letter; }
    :root {
      color: #161616;
      font-family: "STIX Two Text", "Times New Roman", Georgia, serif;
      font-size: 10.65pt;
      line-height: 1.43;
    }
    * { box-sizing: border-box; }
    body { margin: 0; background: white; }
    main { max-width: 6.62in; margin: 0 auto; }
    h1, h2, h3 {
      color: #10263b;
      font-family: "Helvetica Neue", Arial, sans-serif;
      break-after: avoid-page;
      page-break-after: avoid;
    }
    h1 {
      margin: 0 0 0.17in;
      font-size: 22pt;
      line-height: 1.14;
      letter-spacing: -0.025em;
    }
    h2 {
      margin: 0.28in 0 0.09in;
      border-bottom: 0.5pt solid #b9c5cf;
      padding-bottom: 0.035in;
      font-size: 15pt;
      line-height: 1.2;
    }
    h3 {
      margin: 0.19in 0 0.055in;
      font-size: 12pt;
      line-height: 1.24;
    }
    p { margin: 0.07in 0 0.105in; orphans: 3; widows: 3; }
    ul, ol { margin: 0.07in 0 0.12in 0.25in; padding-left: 0.16in; }
    li { margin: 0.028in 0; }
    a { color: #174f78; text-decoration: none; }
    code {
      border-radius: 2px;
      background: #eef2f5;
      color: #17232d;
      font-family: "SFMono-Regular", Menlo, Consolas, monospace;
      font-size: 8.3pt;
      overflow-wrap: anywhere;
      padding: 0.02in 0.035in;
    }
    pre {
      border: 0.5pt solid #cbd4dc;
      border-radius: 3px;
      background: #f6f8fa;
      break-inside: avoid-page;
      page-break-inside: avoid;
      margin: 0.1in 0 0.14in;
      overflow: hidden;
      padding: 0.095in 0.12in;
      white-space: pre-wrap;
    }
    pre code {
      background: transparent;
      font-size: 7.55pt;
      line-height: 1.34;
      padding: 0;
    }
    blockquote {
      border-left: 2pt solid #8399aa;
      color: #394b59;
      margin: 0.11in 0;
      padding: 0.02in 0 0.02in 0.14in;
    }
    table {
      border-collapse: collapse;
      font-family: "Helvetica Neue", Arial, sans-serif;
      font-size: 7.35pt;
      line-height: 1.25;
      margin: 0.12in 0 0.17in;
      table-layout: fixed;
      width: 100%;
    }
    th, td {
      border: 0.45pt solid #bdc8d0;
      overflow-wrap: anywhere;
      padding: 0.045in 0.055in;
      text-align: left;
      vertical-align: top;
    }
    thead { display: table-header-group; }
    tr { break-inside: avoid-page; page-break-inside: avoid; }
    th { background: #eaf0f4; color: #10263b; font-weight: 650; }
    .display-math {
      break-inside: avoid-page;
      page-break-inside: avoid;
      margin: 0.1in 0 0.13in;
      overflow: hidden;
      text-align: center;
    }
    .katex-display { margin: 0; }
    .katex { font-size: 1.02em; }
    strong { color: #152c3f; }
    hr { border: 0; border-top: 0.5pt solid #b9c5cf; margin: 0.2in 0; }
  </style>
</head>
<body><main>${article}</main></body>
</html>`;

fs.mkdirSync(temporaryDirectory, { recursive: true });
fs.writeFileSync(htmlPath, html);

const browser = await chromium.launch({
  executablePath: resolveChrome(),
  headless: true,
});
try {
  const page = await browser.newPage();
  await page.goto(pathToFileURL(htmlPath).href, { waitUntil: "load" });
  await page.evaluate(() => document.fonts.ready);
  const overflows = await page.evaluate(() =>
    [
      ...document.querySelectorAll(
        "main, h1, h2, h3, p, li, pre, table, .display-math",
      ),
    ]
      .filter(
        (element) =>
          element.clientWidth > 1 &&
          element.scrollWidth > element.clientWidth + 2,
      )
      .map((element) => ({
        tag: element.tagName,
        text: (element.textContent || "").slice(0, 120),
        clientWidth: element.clientWidth,
        scrollWidth: element.scrollWidth,
      }))
      .slice(0, 20),
  );
  if (overflows.length > 0) {
    throw new Error(`horizontal overflow detected: ${JSON.stringify(overflows)}`);
  }
  await page.pdf({
    path: outputPath,
    format: "Letter",
    printBackground: true,
    displayHeaderFooter: true,
    headerTemplate:
      '<div style="font:8px Arial;color:#687783;width:100%;padding:0 0.68in;">C(12,6,4)</div>',
    footerTemplate:
      '<div style="font:8px Arial;color:#687783;width:100%;padding:0 0.68in;text-align:right;"><span class="pageNumber"></span> / <span class="totalPages"></span></div>',
    margin: {
      top: "0.63in",
      right: "0.69in",
      bottom: "0.62in",
      left: "0.69in",
    },
  });
} finally {
  await browser.close();
}

const stats = fs.statSync(outputPath);
process.stdout.write(
  `${path.relative(repository, outputPath)} ${stats.size} bytes\n`,
);
