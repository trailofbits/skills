# csv-splitter

Splits a CSV file into chunks of N data rows. Every chunk repeats the header, and every
data row of the input appears in exactly one chunk — the split is lossless.

## Usage

```sh
scripts/split.sh input.csv 500 out/
```

Run the tests with `tests/run_split.sh`.
