# Worked examples

## Plain text extraction

```sh
pdftotext report.pdf report.txt
```

## Preserving layout for tables

```sh
pdftotext -layout invoice.pdf invoice.txt
```

## Decrypting first

```sh
qpdf --decrypt locked.pdf unlocked.pdf && pdftotext unlocked.pdf out.txt
```
