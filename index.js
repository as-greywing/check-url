const Papa = require("papaparse");
const fs = require("fs");
const axios = require("axios");
const extractUrls = require("extract-urls");

// const sampleFile = fs.readFileSync("./sample.csv", "utf-8");
const raw = fs.readFileSync("./raw.csv", "utf-8");

const THREATS = [
  "MALWARE",
  "SOCIAL_ENGINEERING",
  "UNWANTED_SOFTWARE",
  "SOCIAL_ENGINEERING_EXTENDED_COVERAGE",
];

function checkGoogleUrl(url) {
  return new Promise(async (res) => {
    const encodedUrl = encodeURIComponent(url);
    try {
      const { data } = await axios(
        `https://webrisk.googleapis.com/v1/uris:search?threatTypes=${THREATS.join(
          "&threatTypes="
        )}&uri=${encodedUrl}&key=${process.env.GOOGLE_API_KEY}`
      );
      if (Object.keys(data).length) {
        console.log("Resp", data);
      }
      if ("threat" in data) {
        res(data.threat.threatTypes);
      } else {
        res(null);
      }
    } catch (error) {
      console.error(error.message);
      res(null);
    }
  });
}

function checkIpQualityUrl(url) {
  return new Promise(async (res) => {
    const encodedUrl = encodeURIComponent(url);
    try {
      const { data } = await axios(
        `https://ipqualityscore.com/api/json/url/${process.env.IP_QUALITY_API_KEY}/${encodedUrl}`
      );
      if (data.unsafe) {
        res(String(data.risk_score));
      } else {
        res(null);
      }
    } catch (error) {
      console.error(error.message);
      res(null);
    }
  });
}

// Check processed
async function checkPrev() {
  const prevProcessedFile = fs.readFileSync("./processed.csv", "utf-8");
  const data = await getCSVData(prevProcessedFile);
  return data.reduce((final, o) => {
    if (o.ipQuality && o.threat) {
      final.push(o);
      return final;
    }
    return final;
  }, []);
}

async function checkNew(filename, prev) {
  const file = fs.readFileSync(filename, "utf-8");
  const data = await getCSVData(file);
  return new Promise(async (res) => {
    const prevUrls = prev.map((o) => o.url);

    const processedUrl = prev;

    for await (const result of data) {
      const { url } = result;
      if (prevUrls.includes(url)) {
        return;
      }
      console.log("Checking", url);
      const check = await checkGoogleUrl(url);
      const checkIpQuality = await checkIpQualityUrl(url);
      processedUrl.push({
        url,
        threat: check || "NONE",
        ipQuality: checkIpQuality || "NONE",
      });
    }
    res(processedUrl);
  });
}

function writeToLocal(processed, filename) {
  const saveCsv = Papa.unparse(processed, {
    quotes: false, //or array of booleans
    quoteChar: '"',
    escapeChar: '"',
    delimiter: ",",
    header: true,
    newline: "\r\n",
    skipEmptyLines: false,
    columns: null,
  });
  fs.writeFileSync(filename, saveCsv, "utf-8");
}

const urlCache = {};

async function getCSVData(file) {
  return new Promise((res) => {
    Papa.parse(file, {
      header: true,
      delimiter: ",",
      complete: async (parsed) => {
        res(parsed.data);
      },
    });
  });
}

async function checkRaw() {
  return new Promise((res) => {
    const allUrls = [];
    Papa.parse(raw, {
      header: true,
      delimiter: ",",
      complete: async (parsed) => {
        parsed.data.forEach((o) => {
          const urls = extractUrls(o.description);
          if (urls) {
            urls.forEach((url) => {
              if (!urlCache[url]) {
                allUrls.push({ url });
                urlCache[url] = true;
              }
            });
          }
        });
        res(allUrls);
      },
    });
  });
}

async function extractRawUrls() {
  const rawUrls = await checkRaw();
  writeToLocal(rawUrls, "urls.csv");
}

async function run() {
  const prevChecked = await checkPrev();
  const processed = await checkNew("urls.csv", prevChecked);
  writeToLocal(processed, "processed.csv");
}

run();
