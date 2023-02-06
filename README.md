# INFO
This will run through a csv of URLs to check if it is safe by using
1. [Google Web Risk API](https://cloud.google.com/web-risk/docs/lookup-api)
2. [IP Quality Score - Malicious URL Scanner API](https://www.ipqualityscore.com/documentation/malicious-url-scanner-api/overview)

Run using `env-cmd node index.js`

1. script will check `urls.csv` then write results to `processed.csv`
