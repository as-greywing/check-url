const Papa = require("papaparse");
const fs = require("fs");
const axios = require("axios");

const file = fs.readFileSync("./sample.csv", "utf-8");
const prevProcessedFile = fs.readFileSync("./processed.csv", "utf-8");

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
  return new Promise((res) =>
    Papa.parse(prevProcessedFile, {
      header: true,
      delimiter: ",",
      complete: async (parsed) => {
        res(
          parsed.data.reduce((final, o) => {
            if (o.ipQuality && o.threat) {
              final.push(o);
              return final;
            }
            return final;
          }, [])
        );
      },
    })
  );
}

async function checkNew(prev) {
  return new Promise((res) => {
    const prevUrls = prev.map((o) => o.url);
    Papa.parse(file, {
      header: true,
      delimiter: ",",
      complete: async (parsed) => {
        const processedUrl = prev;

        for await (const result of parsed.data) {
          const { url } = result;
          if (prevUrls.includes(url)) {
            return;
          }
          const check = await checkGoogleUrl(url);
          const checkIpQuality = await checkIpQualityUrl(url);
          processedUrl.push({
            url,
            threat: check || "NONE",
            ipQuality: checkIpQuality || "NONE",
          });
        }
        res(processedUrl);
      },
    });
  });
}

function writeToLocal(processed) {
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
  fs.writeFileSync("processed.csv", saveCsv, "utf-8");
}

async function run() {
  const prevChecked = await checkPrev();
  const processed = await checkNew(prevChecked);
  writeToLocal(processed);
}

run();
