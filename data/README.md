# The 41-block upper-bound witness

`cover_41.txt` is a public \((12,6,4)\) covering from the
[La Jolla Covering Repository](https://ljcr.dmgordon.org/cover.html), whose
archived dataset is available as
[Zenodo record 19735294](https://doi.org/10.5281/zenodo.19735294).
Points are numbered 1 through 12.

Verify it using only the Python standard library:

```sh
python3 scripts/verify_cover_41.py
```

The verifier pins the file SHA-256, requires 41 distinct six-element blocks,
enumerates all \(\binom{12}{4}=495\) quadruples, and checks these multiplicity
histograms:

```text
t=1  20:6,21:6
t=2  9:45,10:21
t=3  3:60,4:160
t=4  1:405,2:75,4:15
```

In particular, every quadruple has positive multiplicity, proving the upper
bound \(C(12,6,4)\leq 41\).
